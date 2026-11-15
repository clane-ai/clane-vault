# Clane Vault — personal agents, agent writes and agent reveal (design)

Status: draft for the owner's review, not scheduled. Builds on `docs/design/2026-10-17-agent-access.md` (shipped in 1.8.0; called "the shipped design" below). Nothing here changes how organisation agents work today.

The request, in the owner's words: every user, not just admins, should be able to give an agent access to their own passwords; agents should be able to write secrets into the Personal vault and read values from it.

## 1. Summary of decisions

| # | Decision |
|---|---|
| 1 | A **personal agent** is owned by one user. It is not an organisation member: no `Membership`, no `MembershipKey`, in no picker, in no team folder or group. It is still a `User` row with `kind = agent` plus an `Agent` row, so tokens, OAuth grants, the gateway envelope and the event log are reused. |
| 2 | A personal agent reaches **only items in its owner's Personal space, one item at a time**. No whole-vault grant, no folder grant, no team-folder items, no items other people shared with the owner. |
| 3 | Three per-item modes, all off by default: **Agent can use** (today's behaviour), **Agent can reveal** (new; the model sees the value), and **Agent can update** (new; the agent may overwrite the item). |
| 4 | Agent-written secrets arrive as **deposits** in a "From agents" inbox, signed by the gateway. They become normal records only when the owner clicks **Keep** in an unlocked browser. The existing guard that refuses a sealed key on the user's own record stays exactly as it is. |
| 5 | Reveal ships as **approval per reveal** first: the agent holds no key for the item; the owner's unlocked browser seals only the approved fields to a one-time key the gateway signed. **Standing reveal** (no approval) is a later, separately switched phase. |
| 6 | The gateway never returns a value unless the operator set `GATEWAY_REVEAL`. Default `off`. |
| 7 | Organisation agents stay Use-only with today's two tools. Write and reveal are for personal agents only in this design. |
| 8 | Hosted: personal agents do not count against the organisation's agent bundle (Team 3, Business 10). They have a per-person allowance (§3.3). |
| 9 | An organisation can switch personal agents off for its members, cap how many each may have, and forbid write or reveal (§3.4). This is the first server-enforced organisation policy that reaches the Personal space, and the docs must say so. |

Build order: **A** personal agents with Use (§3) → **B** writes (§4) → **C** reveal with approval (§5) → **D** standing reveal (§5.6). Each phase is shippable alone.

## 2. How the Personal space is keyed today (what the design has to fit)

- A personal record has one `RecordAccess` row: `holderType user`, `holderId` = the owner, `permission owner`, and `wrappedRecordKey` = a `v1.` envelope under the owner's **user key**. The user key is symmetric and exists only in the owner's unlocked client. There are no folder keys: private folders only carry a name encrypted under the user key.
- The owner also has an account X25519 pair (`User.publicKey`, private key wrapped under the user key). Anyone who knows the public key can seal to it.
- `apps/web/src/features/vault/decrypt.ts` refuses a record the user owns whose key is a sealed box (`s1.`): "a sealed box there would be one the server planted". This guard is why an agent cannot simply write an owner row sealed to the user's public key, and this design does not relax it.
- Personal records have events with `orgId` null. No organisation's event log shows them, and private records follow no organisation's policy today (`docs/policies.md`).
- `/agent/sync` is organisation-scoped (`syncFor(..., orgOnly: true)`). A personal agent needs its own sync body.

Consequence: the gateway can never be given "the Personal vault". It can only be given individual record keys, each sealed to the agent's public key by the owner's browser. That is a good property and the design keeps it.

## 3. Personal agents (phase A)

### 3.1 The principal

```prisma
model Agent {
  // existing fields unchanged, except:
  orgId        String?  @db.Uuid   // null for a personal agent
  /// Set for a personal agent: the one user who owns it. Exactly one of orgId and ownerUserId is set (CHECK constraint).
  ownerUserId  String?  @db.Uuid
  owner        User?    @relation("personalAgents", fields: [ownerUserId], references: [id], onDelete: Cascade)
  @@index([ownerUserId])
}
```

The agent's `User` row is as today (`kind agent`, `agent+<id>@agents.invalid`, empty auth columns). No `Membership` and no `MembershipKey` rows are created, so `activeMember` never returns it and nothing in an organisation can be shared with it. `capForAgent` still applies.

Why not an organisation member: the Personal space belongs to the user and is the same in every organisation they are in. A member agent would appear in the organisation's pickers, could be given team folders by other people, would be revoked by `offboard` when the user leaves one of several organisations, and would put the user's private activity in that organisation's log.

Why still a `User` row: `AgentToken`, `AgentGrant`, OAuth codes, `Event.actorId`, `requireAgent` and the gateway's caches are all keyed on the agent's user id. Reusing them costs one nullable column and one new one.

### 3.2 Who can create one, and enrolment

Any signed-in person with a full session (not a session confined to one organisation, `privateLock.ts`), under **Settings → My agents**. Routes mirror `/admin/agents` under `/me/agents` with `requireAuth` only: `GET`, `POST`, `PATCH /:id`, `POST /:id/verify`, `DELETE /:id`, tokens and grants.

Enrolment is the shipped flow with the owner bound in:

1. `POST /me/agents { name, expiresAt? }`. The API checks the allowance and policy (§3.3, §3.4) and calls the gateway: `POST /internal/agents { agentId, ownerUserId, ownerPublicKey }`.
2. The gateway generates the X25519 pair and signs **`personal-agent-key:<ownerUserId>:<ownerPublicKey>:<agentId>:<publicKey>`** with its identity key (`g1.` attestation, new message; the constructor sits beside `agentKeyMessage` in `packages/crypto/src/agents.ts`).
3. It wraps the private key as a **`k2.`** envelope: the same DEK-under-KEK construction, with AAD `agent-private-key:personal:<ownerUserId>:<ownerPublicKey>:<agentId>:<publicKey>` and KMS encryption context `{ agentId, ownerUserId }`.
4. **The owner's browser verifies.** The same `AgentVerifyDialog`: it checks the attestation against the gateway identity, and additionally that the `ownerPublicKey` in the signed message is the public key it derives from its own unlocked private key (`publicKeyFromPrivateKey`). Then it shows the agent and gateway fingerprints, and the user confirms.

**The owner's key is pinned inside the envelope, not on first use.** The gateway is stateless, so it cannot remember a pin. Instead the owner's public key is part of the AAD of the agent's wrapped private key. On every call the gateway takes the owner key the API reports, rebuilds the AAD and opens the envelope. If the API (or anyone with database access) substitutes another owner key, the open fails and the agent stops (`refused: owner_key_changed`). The owner's browser checked the binding at step 4, so there is no trust-on-first-use window for the owner key at all.

**The gateway pin.** Today the gateway identity is pinned per signed-in user and organisation, and members never re-pin a changed identity; only admins do. A personal agent has no organisation and its owner is the only authority, so:

- the pin for personal agents lives in a slot `personal` for that user;
- the dialog compares the identity with **every** gateway pin this browser holds for the user (any organisation or `personal`). There is one gateway per server, so a difference from any of them shows *Changed*, not *New*;
- the owner may re-pin a changed identity for the `personal` slot themselves, after the dialog shows the old and new fingerprints and the link to the published one. Their agents then show *Needs re-enrolment*, as organisation agents do.

**This weakens the bar, and here is the cost.** Admins are told to compare the fingerprint with the published one and mostly will. Ordinary users mostly will not, so for personal agents the gateway pin is trust-on-first-use in practice. A malicious API server could present its own "gateway" to a first-time user and receive every record key that user then grants. It could not do this to a user whose browser already holds a pin from an organisation. Mitigations: the dialog shows the published-fingerprint link and a one-line reason; the hosted fingerprint is published in the public repository, which the server does not control. Phase 5 of the shipped design (enclave attestation checked by the browser) removes the problem.

### 3.3 Limits

Self-hosted (`BILLING_MODE=off`): no plan limit; the organisation policy's `maxPerMember` is the only cap.

Hosted, proposed:

| | Personal | Team | Business |
|---|---|---|---|
| Organisation agents (unchanged, admin-created) | 0 | 3 | 10 |
| Personal agents, per person | 1 | 2 | 5 |

- Personal agents **do not count** against the organisation bundle. That bundle is a shared resource the admins plan; a member must not be able to use it up, and an admin must not have to spend it on someone's private vault.
- A person in several organisations gets the highest allowance among their active memberships (or the Personal plan's if they have none), then the strictest policy cap applies.
- `Entitlements` gains `personalAgentLimit: number | null`. Refusal: `402 { error: "agent_limit", used, allowed }`, as today. Over the allowance after a downgrade or after leaving an organisation: existing agents keep working, new ones are blocked (the shipped rule).
- Per-agent limits: at most 200 granted items per agent; rate limits as today plus those in §4.5 and §5.5.

### 3.4 Organisation policy

New block in `policySchema` (`lib/policies.ts`); on hosted Team the defaults apply read-only, on Business admins edit it:

```ts
personalAgents: z.object({
  allowed: z.boolean().default(true),
  maxPerMember: z.number().int().min(1).max(20).default(2),
  write: z.boolean().default(true),
  reveal: z.enum(["off", "approval", "standing"]).default("approval"),
}).prefault({})
```

- The policy of **every organisation the user is an active member of** applies, strictest wins: `allowed` is the AND, `maxPerMember` the minimum, `write` the AND, `reveal` the lowest of off < approval < standing. A user with no organisation has no policy; their plan and the server setting decide.
- Enforced by the API, not the client: `POST /me/agents` answers `403 { error: "personal_agents_disabled", orgId }`; `requireAgent` refuses a personal agent with the same code while any of its owner's organisations has `allowed: false`. The gateway treats it like expiry (cache dropped). Agents are **suspended, not deleted**: they work again if the policy changes or the user leaves that organisation. Nothing the user stored is touched.
- `write: false` makes the API refuse `/agent/deposits` and agent updates; `reveal` caps what the API will relay (§5).
- The server operator has a harder switch that no policy can raise: the gateway's `GATEWAY_REVEAL=off|approval|standing` (default `off`), and an API setting `PERSONAL_AGENTS=on|off` (default `on` when agent access is configured).

What this policy cannot do: an organisation cannot read, list or revoke an individual's personal agent or see what it was given. It can only turn the capability off for its members.

`docs/policies.md` currently says private records follow no organisation's policy. That sentence gets an explicit exception for `personalAgents`, with the reason: a company may not want accounts it manages to send any secret to a gateway.

### 3.5 Granting an item

In the record's share sheet, in the Personal space only, a section **Agents** lists the user's verified personal agents with a mode per agent: *None*, *Can use*, *Can reveal* (phase C). The shipped restricted-credential warning is shown every time.

*Can use*: the browser runs `verifyAgentKey` (attestation against the pinned gateway, as today), seals the record key to the agent's public key with AAD **`personal-agent-record:<ownerUserId>:<agentId>:<recordId>`**, and calls `POST /records/:id/agent-grants { agentId, wrappedRecordKey }`. The API stores a `RecordAccess` row (`holderType user`, `holderId` = the agent, `permission use`, `orgId null`, `sealedTo` = the agent key) after checking that the caller holds the record's owner row, the record is in no team folder, and the agent is the caller's own, verified and live.

A multi-select action in the list grants several items at once. There is deliberately **no folder-level or whole-vault grant**: private folders have no key to share, and a standing grant would send every future secret to the gateway without the user deciding.

The item still needs an *Agent use* policy (hosts, how the secret is sent) inside its encrypted body, exactly as in the shipped design. No policy, no use.

The agent's sync: `GET /agent/sync` for a personal agent returns `{ owner: { userId, publicKey }, wrappedPrivateKey (k2.), kekId, records: [...rows the agent holds], reveal: [...stubs, §5], deposits: [...its own, §4], policy: { write, reveal }, expiresAt }`. No folders. Handles are `personal/<title-slug>`.

### 3.6 Connecting a client

The OAuth consent page gains personal agents: `GET /oauth/authorize/info` also lists the caller's own personal agents; `POST /oauth/authorize` accepts one without `orgAdmin` when `agent.ownerUserId` is the caller and the session is a full one. Members who own no personal agent still never see a consent page. API tokens (`cvat_`) are created under **My agents → Connect**, same sheet.

### 3.7 Revocation, leaving an organisation, deletion

- **Revoke** (`DELETE /me/agents/:id`), one transaction: delete the agent's `RecordAccess` rows and reveal stubs, discard its unkept deposits, end tokens and grants, null the wrapped key, disable the agent's `User`; then best-effort cache drop at the gateway. The response lists the items the gateway could open **and the items whose fields were revealed**; the UI says to rotate them. Kept deposits stay: they are the user's records.
- **Removing one item**: `DELETE /records/:id/agent-grants/:agentId`. Record keys are not rotated (the open follow-up in `docs/sharing.md`), so the UI suggests changing the credential.
- **The owner leaves or is removed from an organisation.** Nothing happens to the agent: it never belonged to the organisation. The allowance and policy are recomputed from the memberships that remain; a suspension by that organisation's policy ends.
- **The owner's account is disabled** (instance admin) or locked: `requireAgent` refuses with `403 owner_inactive`; the gateway drops its cache. Re-enabling restores it.
- **The owner's account is deleted.** The deletion transaction revokes every personal agent first (same steps as Revoke), then the existing cascade removes the user's records. The agents' `User` rows are deleted too: with the owner gone there is no log left that names them.
- **The owner's account key changes** (account reset or recovery that makes a new key pair). The `k2.` envelope no longer opens with the new owner key, so the agent stops: *Needs re-enrolment*. The user revokes and creates it again. A master password change does not change the key pair and affects nothing.

### 3.8 Events: what the owner sees, what admins see

**The owner** sees everything about their own agents under **My agents → Activity** (`GET /me/agents/:id/activity`): `agent.use`, `agent.refused`, `agent.reflected`, and the new `agent.deposit`, `agent.update`, `agent.reveal_request`, `agent.reveal`, `agent.reveal_denied`, `agent.reveal_expired`, with record, host, method, field names and connected-app name. These rows have `orgId` null and `actorId` = the agent. Never values, paths, query strings or bodies, as today.

**Admins** see, in their organisation's event log, lifecycle only, for members of their organisation: `personal_agent.create`, `personal_agent.verify`, `personal_agent.revoke`, `personal_agent.connect` (a token or OAuth grant was created), `personal_agent.suspended` (policy). Each row has `actorId` = the member and `meta: { agentId }`. It has **no agent name, no record id, no title, no host, no count of items, no mode**. Admin → Agents gains one line, "Personal agents: 7 across 4 members", with a per-member count. That is all.

The cost of this privacy: an admin cannot tell whether a member's personal agent holds one test key or two hundred passwords, and cannot audit reveals. An organisation that needs that control turns personal agents off and uses organisation agents. A row is written to each organisation the member belongs to, so a person in two organisations discloses "has a personal agent" to both.

## 4. Agent writes (phase B)

Use case: the agent creates an API key or an account and saves it so the user has it and the agent can use it later.

### 4.1 Why a deposit and not a record

The gateway holds the agent's key, never the user's. To give the user a readable item it has to seal the record key to the user's **public** key. But anyone can seal to a public key, which is exactly why the browser refuses a sealed owner key today. If the design accepted agent-written owner rows, a malicious server could plant a login for `paypa1.com` in someone's vault and the extension would offer it.

So an agent-written item is a **deposit**: a separate row, signed by the gateway, shown apart from the vault, and turned into a real record only by the owner's unlocked browser re-wrapping the key under the user key.

```prisma
model AgentDeposit {
  id              String   @id @db.Uuid          // becomes Record.id on Keep (the body's AAD binds it)
  ownerUserId     String   @db.Uuid
  agentId         String   @db.Uuid
  type            String                          // coarse: "login" | "item", as Record.type
  encBody         String                          // aeadEncrypt(recordKey, body, "record-body:<id>")
  revision        Int      @default(1)
  ownerSealedKey  String                          // s1. to the owner's account public key
  agentSealedKey  String                          // s1. to the agent's public key
  signature       String                          // d1.<gatewayKeyId>.<sig>
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt
  @@index([ownerUserId])
}
```

### 4.2 Write flow

1. The gateway validates the body with `normalizeRecordBody` (the same type, field and size rules as the editor; 49 KB), generates the id and a random record key, and encrypts the body.
2. It seals the key twice: to the owner (`ownerPublicKey` from the `k2.` binding, AAD **`agent-deposit-owner:<ownerUserId>:<id>`**) and to the agent itself (AAD `personal-agent-record:<ownerUserId>:<agentId>:<id>`).
3. It signs with the gateway identity key: **`agent-deposit:<ownerUserId>:<ownerPublicKey>:<agentId>:<id>:<revision>:<sha256(encBody)>`** → `d1.<keyId>.<sig>`.
4. `POST /agent/deposits`. The API checks policy and quotas and stores the row. Event `agent.deposit` (owner-visible only).
5. The plaintext, the record key and both seals' ephemeral keys are zeroed; the value is held in the log scrubber while in memory, as injected secrets are.

### 4.3 What the owner sees

Personal space → **From agents** (a badge with the count). For each deposit the browser:

1. verifies the signature against the **pinned** gateway identity and that it names the browser's own public key; a deposit that fails is shown as *Not signed by the gateway — delete it* and never opened;
2. opens the key with the account private key and shows the item read-only with: the agent's name, the connected app, the time, and any *Agent use* policy marked "set by the agent".

Actions: **Keep** (optionally into a folder, with a checkbox *<agent> can keep using this item*, on by default) or **Delete**.

**Keep** = `POST /me/agent-deposits/:id/keep { wrappedRecordKey, folderId, agentWrappedRecordKey? }`: the browser wraps the record key under the user key (`v1.`, the normal owner wrap). The API creates the `Record` (same id, same `encBody`, `createdByAgentId` set), the owner row, optionally the agent's `RecordAccess` row, and deletes the deposit, in one transaction. From then on it is an ordinary record in every client. Its detail view keeps "Created by agent <name> on <date>".

Until kept, a deposit is not in `/sync`, not in the extension, never autofilled, not in password health, not exported and not in offline copies. Older clients simply do not see it. Unkept deposits are deleted after 90 days with a warning in the inbox from day 60.

### 4.4 Integrity rules

- **Telling agent-written from own.** Before Keep: a different place in the UI and a verified gateway signature. After Keep: `Record.createdByAgentId` (server-asserted, shown as provenance only; by then the user has reviewed the content).
- **An agent can change only its own unkept deposits.** `update_secret` on a deposit re-encrypts under the same record key, bumps `revision` and re-signs. The API checks `agentId` on the row.
- **An agent cannot touch a record** — kept or never agent-written — unless the owner turned on **Agent can update** for that item and agent. Keep turns the agent's write off; a person's edit never turns it on. The flag is `RecordAccess.agentWrite Boolean @default(false)` on the agent's row, set only by `PATCH /records/:id/agent-grants/:agentId { write }` from the owner.
- **Updates to a record are signed and reversible.** `PUT /agent/records/:id` requires the current `revision`, carries a gateway signature over `agent-update:<ownerUserId>:<agentId>:<id>:<revision>:<sha256(encBody)>`, and the API first copies the old `encBody` into `RecordAgentOverwrite` (last 5 per record, kept 30 days). The owner's browser shows "Changed by agent <name>" with **Restore previous** until they open the item. The record key is unchanged, so old bodies still decrypt.
- **The agent can never change who can do what.** The gateway copies `agentPolicy` and `agentReveal` through an update byte for byte; the update tool has no field for them. The policy can be set by the agent only when it first saves a deposit, and the owner reviews it at Keep.
- **No delete.** There is no delete tool. Agents cannot trash, purge, move or share anything.

**Where this weakens the bar.** (a) For an item with *Agent can update*, the `agentWrite` flag is server state. A malicious API together with a hijacked agent could overwrite any item the agent holds a key for. The signature and the kept previous version make that visible and reversible, not impossible. (b) The gateway now sees a secret at the moment of writing even if the agent is never granted use. (c) With `save_secret`, the model itself supplied the value, so it has seen it; see capture below for the way around that.

### 4.5 Quotas and rate limits

20 writes (save + update) per agent per hour (`GATEWAY_WRITE_PER_HOUR`); 100 unkept deposits per owner (`refused: inbox_full`); body size as for any record; no attachments. Deposits and kept records count as the owner's records; there is no record count limit today, so no plan change.

### 4.6 Capture: saving a secret the model never sees

Most secrets an agent "creates" come back in an API response (create a token, create a service account key). `http_request` gains an optional `capture`:

```json
{ "item": "personal/github-admin", "method": "POST", "url": "https://api.github.com/…",
  "capture": { "from": "/token", "title": "GitHub deploy token", "type": "apiKey",
               "agent_use": { "hosts": ["api.github.com"], "inject": { "kind": "bearer" } } } }
```

`from` is a JSON Pointer into the response body. The gateway extracts the value, writes a deposit with it, and scrubs it from the response it returns (the existing scrubber, with the captured value added to the held set). The model gets the handle of the new item and never the value. This keeps the shipped guarantee for created credentials, and the docs should tell people to prefer it over `save_secret`. It ships in phase B after plain `save_secret`.

## 5. Agent reads values (phases C and D)

### 5.1 What changes, plainly

Today no tool returns a credential, and `docs/agents.md` and `SECURITY.md` say so. With reveal, a value the owner marked revealable **leaves the vault's control for good**: it is in the model's context, in the model provider's logs and retention, in the conversation history, and available to every other tool and connector in that session. The scrubber cannot help. Approval limits *when* a value is released, not *what happens to it next*.

Threats that are new or worse:

| Threat | What limits it | What remains |
|---|---|---|
| Prompt injection makes the agent ask for a value and send it elsewhere (a web fetch, an email tool, a commit) | Off by default; per item; field scope; approval per reveal shows the item and the connected app; rate limit | If the user approves, or the item is on standing reveal, the value is gone. An injected agent can also write a persuasive reason. Nothing in the vault can stop the model from repeating a value it holds |
| The model provider keeps it | None | Retention is the provider's. Treat every revealed value as disclosed to the provider |
| Approval fatigue | One request at a time per agent, short expiry, no "always allow" in phase C | Users who click Approve without reading |
| A malicious API relays a reveal to itself | The request key is signed by the gateway; the browser verifies against the pinned identity before sealing | A malicious API plus a gateway the user pinned on first use without checking (§3.2) |
| TLS-terminating proxies in front of the gateway (hosted: Cloudflare and the reverse proxy) | None | They see revealed values in transit. Today they see only scrubbed responses |
| Gateway operator | As today | As today for standing reveal (it holds the key). **Better than Use** for approval mode: the gateway never holds the record key, only the fields of each approved request |

Recommendation printed in the UI and docs: prefer *Can use*. Reveal only what cannot be injected into an HTTP call and is low in value or easy to rotate: an account id, a username, a Wi-Fi password, a restricted token for a tool the gateway cannot proxy. Never a master, owner or recovery credential.

### 5.2 Field scope

A revealable item names its fields with the references the usage policy already uses: `username`, `password`, `url`, `notes`, `data.<key>`, `field:<custom field id>`, plus `totp`. `totp` returns the **current 6-digit code**, never `totpSecret`; the seed is not revealable in any mode. The default selection when the user turns reveal on is `username` only; `password` has to be ticked.

### 5.3 Approval per reveal (phase C): no standing key

Turning on *Can reveal* for an item and agent does **not** give the agent the record key. The browser seals a small stub to the agent's public key — `{ title, type, fields: [...] }`, AAD `personal-agent-stub:<ownerUserId>:<agentId>:<recordId>` — stored as `AgentRevealGrant { recordId, agentId, sealedStub }`. The stub lets `list_secrets` show the item and what may be asked for. (If the item is also *Can use*, the agent has the key for that reason; the reveal path below is still the only way a value reaches the model.)

A reveal:

1. `get_secret { item, fields, reason }`. The gateway checks the stub allows those fields, generates a one-time X25519 pair and signs **`agent-reveal-request:<requestId>:<ownerUserId>:<agentId>:<recordId>:<sorted fields>:<requestPublicKey>:<expiresAt>`** with its identity key. `POST /agent/reveals` → `AgentRevealRequest` (expires in 5 minutes; one open request per agent).
2. **Reaching the owner.** Approval can only happen in a signed-in, **unlocked** Clane Vault client, because approving means decrypting. So:
   - the web app (open tab or installed PWA) and the browser extension poll `GET /me/agent-reveals` every 5 seconds while unlocked and show a blocking sheet; the extension also sets a badge and a system notification;
   - optionally (user setting, default on) the API emails "An agent is asking for a secret. Open Clane Vault to answer." The email contains **no approve link**, no item title and no reason; it only brings the user to the app. A mailbox is not an approval channel;
   - web push to a closed PWA is a follow-up, not phase C.
3. The sheet shows: the agent, the connected app (OAuth client name or token label), the item title, the fields asked for, the time, and the agent's reason labelled *"Written by the agent. It may not be true."* Buttons: **Allow once**, **Deny**. The browser first verifies the request signature against the pinned gateway identity; if that fails there is no Allow button.
4. On Allow the browser decrypts the record, takes only the approved fields, and seals that JSON to `requestPublicKey` with AAD `agent-reveal:<requestId>:<recordId>:<agentId>` → `POST /me/agent-reveals/:id/approve { sealed }`.
5. The gateway (long-polling the API, up to 50 seconds per tool call) opens it, returns `{ fields: { … } }`, zeroes its copies. If the user has not answered, the tool returns `{ status: "pending", request_id }` and the agent calls `get_secret { request_id }` again.

Events: `agent.reveal_request`, then `agent.reveal` (field names only), `agent.reveal_denied` or `agent.reveal_expired`. All owner-visible only.

If nobody has an unlocked client, the request expires. That is the intended behaviour: no human, no value.

### 5.4 Tool shape

Personal-agent sessions list five static tools; organisation-agent sessions keep exactly today's two. The server instructions for personal agents become: *"`http_request` uses a credential without showing it; prefer it. `get_secret` shows you a value only where the owner allowed it, and they may be asked to approve."*

| Tool | Input | Output |
|---|---|---|
| `list_secrets` | — | as today, plus per item `modes: ["use"?, "reveal"?]`, `reveal: { fields, approval: true \| false }`, `deposit: true` for the agent's own unkept deposits, `can_update` |
| `http_request` | as today, plus optional `capture` (§4.6) | as today; with capture, `saved: { item }` |
| `save_secret` | `{ title, type, fields: { username?, password?, url?, notes?, data? }, custom_fields?, agent_use?: { hosts, inject, secret? } }` | `{ item }` (a deposit) |
| `update_secret` | `{ item, set: { …fields }, revision? }` | `{ item, revision }`, or `refused: not_writable \| conflict` |
| `get_secret` | `{ item, fields, reason }` or `{ request_id }` | `{ fields }`, `{ status: "pending", request_id }`, or `refused: reveal_off \| field \| denied \| expired \| busy` |

New refusal reasons: `reveal_off` (operator, policy or item), `field`, `denied`, `expired`, `not_writable`, `conflict`, `inbox_full`, `owner_key_changed`.

### 5.5 Limits

`GATEWAY_REVEAL_PER_HOUR` (default 10 per agent); one open approval request per agent; three denials in ten minutes pause that agent's reveals for an hour and show the owner a notice. Revealed values are never logged and are held in the log scrubber while in memory.

### 5.6 Standing reveal (phase D)

For unattended agents the user can turn approval off for one item: the browser then also seals the record key to the agent (as for Use) and writes inside the encrypted body

```ts
agentReveal?: { v: 1; agents: string[]; fields: string[] }   // validated in packages/crypto/src/records.ts
```

so the API can neither add an agent nor widen the fields; the gateway returns only the listed fields to the listed agents. The editor requires typing the item's title to confirm and shows the §5.1 warning. A client from before this feature drops the field on save, which fails closed, as with `agentPolicy`.

This is the mode that fully gives up "the model never sees plaintext" with no human in the loop. It needs `GATEWAY_REVEAL=standing` on the gateway and `reveal: "standing"` in every applicable organisation policy. Recommendation: build it last, and decide separately whether the hosted service enables it (open question 3).

## 6. Zero-knowledge accounting after this design

Additions to the table in `SECURITY.md` and the shipped design §8.1:

| Data | Server (API, database) | Gateway | Model / agent client |
|---|---|---|---|
| Personal items never granted to an agent | ciphertext only | nothing | nothing |
| Personal items with *Can use* | ciphertext only | plaintext at use time; could decrypt any time while the agent is live | names, hosts, policy; scrubbed responses |
| Items with *Can reveal*, approval mode | ciphertext only | **only the approved fields, per approved request**; never the record key | the approved fields, in full |
| Items with standing reveal | ciphertext only | as *Can use* | the listed fields, in full, whenever it asks |
| Deposits and agent updates | ciphertext only | plaintext at write time | whatever it wrote (nothing, with capture) |

Sentences for the UI: *"Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards."* and, on *Can use* in the Personal space, the shipped sentence about the gateway operator.

Every place this design lowers the shipped bar, in one list:

1. Reveal: the model sees values (§5.1). Cost: the central guarantee, for the items the owner opts in.
2. Non-admin users pin the gateway: trust-on-first-use in practice (§3.2).
3. Agent update of records depends on a server-side flag (§4.4).
4. Admins lose sight of what personal agents hold (§3.8).
5. The gateway sees written secrets, and more code paths in the gateway handle plaintext (write, capture, reveal), which enlarges what an audit must cover.
6. `list_secrets` for personal agents is no longer "nothing here can ever return a secret"; a client that auto-approves all tools of a connector now auto-approves `get_secret` calls. The human approval inside Clane Vault is the control, not the MCP client's.

Unchanged: SSRF rules, redirects, scrubbing of `http_request`, attestation, the runtime guard, tokens, rate limits, and everything about organisation agents.

## 7. API and code surface (for estimating)

- **Schema**: `Agent.orgId` nullable, `Agent.ownerUserId`; `RecordAccess.agentWrite`; `Record.createdByAgentId`; new `AgentDeposit`, `RecordAgentOverwrite`, `AgentRevealGrant`, `AgentRevealRequest`. One migration per phase.
- **API**: `/me/agents*`; `/records/:id/agent-grants*`; `/agent/sync` personal body; `/agent/deposits`, `/agent/records/:id`, `/agent/reveals`; `/me/agent-deposits*`, `/me/agent-reveals*`; `requireAgent` learns `ownerUserId`, policy suspension and `owner_inactive`; OAuth consent for owners; `policySchema.personalAgents`; `Entitlements.personalAgentLimit`; account deletion revokes agents.
- **Crypto package**: message and AAD constructors for the personal attestation, `k2.` envelope AAD, deposit and update signatures, reveal request signature, stub and reveal seals; `agentReveal` in `RecordBody` (phase D).
- **Gateway**: `/internal/agents` accepts the owner binding; identity gains `signDeposit`, `signUpdate`, `signRevealRequest`; three tools and `capture`; `GATEWAY_REVEAL`, `GATEWAY_WRITE_PER_HOUR`, `GATEWAY_REVEAL_PER_HOUR`; personal handles.
- **Web and extension**: Settings → My agents (reusing the admin Agents components); Agents section in the personal share sheet; From agents inbox; reveal approval sheet (web and extension); policy form; the admin count line.
- **Docs**: `docs/agents.md`, `SECURITY.md`, `docs/policies.md`, `docs/plans.md`, `docs/sharing.md`.
- **KMS key policy**: the allowed encryption-context keys gain `ownerUserId` (operators must update their key policy before enabling personal agents; the release notes must say so).

## 8. Acceptance tests (the ones that carry the security claims)

- A personal agent has no `Membership`; it is absent from `GET /users`, every picker and `/group-access/pending`; `POST /folders/:id/members` for it answers `400 user_not_active`.
- `POST /records/:id/agent-grants` is refused for a record in a team folder, a record the caller does not own, and another user's agent.
- Swapping `User.publicKey` of the owner in the database makes the gateway refuse every call for that owner's agents (`owner_key_changed`), with no deposit written.
- An attestation whose owner key is not the browser's own fails verification in the dialog.
- A record the user owns with an `s1.` owner key is still refused by `decrypt.ts` (the guard is untouched).
- A deposit with a bad or missing signature, or one signed by a non-pinned identity, is never opened; an unkept deposit is absent from `/sync` and from the extension.
- `update_secret` on a kept record without `agentWrite` → `not_writable`; with it, the previous body is restorable and the result carries the same `agentPolicy` bytes.
- With `GATEWAY_REVEAL=off`, `get_secret` returns `reveal_off` and no request reaches the API.
- A reveal request whose `requestPublicKey` was changed by the API shows no Allow button; the sealed reply contains only approved fields; `totpSecret` never appears in any reply.
- The "no plaintext in logs" test of the shipped design runs over save, capture, update and reveal paths with known values.
- Policy `allowed: false` in one of two organisations suspends the agent; leaving that organisation restores it. Admin event log rows contain no record id, title or host.
- Organisation-agent sessions list exactly two tools.

## 9. Open questions for the owner

1. **Should a personal agent also reach team-folder items its owner can open?** Recommendation: **no**. Those items belong to the folder owner and the organisation; a member could otherwise send organisation secrets to the gateway without an admin knowing, and §3.8 hides it from the log. Members who need that ask an admin for an organisation agent.
2. **Personal-agent allowances on hosted plans** (proposed: Personal 1, Team 2 per person, Business 5 per person, outside the organisation bundle). Recommendation: as proposed. The Personal plan has 0 agents today, so giving it 1 is a pricing decision; if in doubt start it at 0 and Team/Business as proposed.
3. **Does the hosted service ever enable standing reveal?** Recommendation: **no at launch**: run `GATEWAY_REVEAL=approval` on vault.clane.ai, ship standing reveal for self-hosters only, and revisit after the enclave and the external audit.
4. **Policy default for existing organisations: personal agents on or off?** Recommendation: **on** (`allowed: true`, `reveal: "approval"`), because the request was "every user" and no organisation data is reachable; say so prominently in the release notes so admins who disagree can switch it off before members find it. Note that hosted Team organisations cannot edit policies today, so they could not switch it off: either make this one policy editable on Team or default it to off there.
5. **Is email acceptable as a reveal notification?** Recommendation: **yes, as a notification only** (no item, no reason, no approve link), on by default, with web push as the follow-up. Without it, a reveal requested while the user has no tab open just expires.
