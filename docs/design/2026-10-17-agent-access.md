# Clane Vault — agent access through a hosted gateway (build spec)

Status: draft for review, not yet scheduled. Target: `clane-ai/clane-vault`. Research: `reports/Agent access to vault secrets.md`. Phases 1 and 2 are specified to build; 3–5 are outlined. Where the report and the code disagree, this spec follows the code (§13).

## 1. Goal and non-goals

Let cloud AI agents (Claude.ai and ChatGPT connectors, the Claude and OpenAI APIs, Claude Code) **use** credentials held in a team vault through one remote MCP server, `https://vault.clane.ai/mcp`, without the model ever seeing a value and without the user installing anything.

- **One interface.** A remote MCP server over HTTPS (Streamable HTTP) with two tools, `list_secrets` and `http_request`. There is no get-value verb, no local install, no exec mode. The gateway makes the outbound call itself, with the credential injected, and returns a scrubbed response. Self-hosters run the same gateway container next to their own API.
- **Agents are organisation members** with their own X25519 key, so every existing sealing path (folder keys, groups, direct shares, pinning) applies unchanged.
- **A deliberate, disclosed exception to zero-knowledge.** The gateway holds agent keys (wrapped by a KMS or HSM key) and decrypts agent-scoped records at use time. Only folders, groups and records shared to an agent are affected; everything else stays zero-knowledge. §8 states this plainly, and the UI says it where a human shares to an agent.
- **Small gateway, maximum security.** A separate minimal service, envelope-encrypted keys, decrypt per call, no plaintext in logs or dumps, strict SSRF and redirect rules, response scrubbing, OAuth 2.1, per-agent limits (§5). The design moves into an enclave later without product changes (§6).
- **Self-hosted gets everything, with no limits.** Hosted plans gate counts and approvals only (§9).

Non-goals for phases 1–2: per-request approval, ssh-agent and database proxies, browser autofill, hash-chained logs, the enclave itself, an agent that writes to the vault.

## 2. What already exists and is reused

| Existing piece | Reused as |
|---|---|
| `MembershipKey` (one X25519 pair per person and org; `sealedTo` on every wrap) | The agent's identity in the org. Its public key is the agent's `MembershipKey.publicKey`; `wrappedPrivateKey` is `""` (the API never holds it in any form; the gateway holds it KMS-wrapped). |
| `FolderMember.wrappedFolderKey` (folder key sealed to each member, AAD `org-folder-key:<org>:<folder>`) | The scope envelope key: a team folder *is* a scope, granted with one seal. |
| `RecordAccess` folder rows, `openRecordKey`, `decryptRecordBody` | How the gateway reaches record keys and bodies. |
| `Permission.use` | The only permission an agent can hold; capped server-side (§4.3). |
| Groups and the pending-access approval queue (`docs/groups.md`) | How an admin scopes an agent to folders they don't own: add it to a group; the key holder approves, fingerprint shown. |
| TOFU pinning (`pinStatus`, `pinKey`, `assertPinned`, `KeyChangedError`, `fingerprintOf` in `apps/web/src/lib/orgKeys.ts`) | Pins the agent key *and* the gateway identity key in the admin's browser. |
| `offboard(tx, orgId, userId, "remove")` (`lib/orgs.ts`), `Session`, `Event` log, `/admin/events`, CSV export | Revocation, sessions, audit. |
| `lib/plans.ts`, `requireEntitlement`, 402 `plan_required`; `lib/serverSecretCheck.ts` pattern | Plan gating; gateway identity pinning on the API side. |

## 3. Architecture

```
Claude.ai / ChatGPT / Claude API / OpenAI API / Claude Code
        │  MCP over HTTPS (Streamable HTTP), OAuth 2.1 or static bearer
        ▼
 apps/gateway  (own container; KMS-wrapped agent keys; decrypt per call; outbound allowlist; scrub)
   │ ES256 agent token + X-Gateway-Token              │ outbound HTTPS to allowed hosts only
   ▼                                                  ▼
 apps/api  /agent/* (ciphertext, events), OAuth AS   api.stripe.com, api.github.com, …
   ▲
   │ seals folder keys to the agent key; pins agent and gateway fingerprints
 admin browser
```

| Phase | Scope | Proves |
|---|---|---|
| 1. Agent member (§4) | Member kind, enrolment in the gateway, gateway-attested key and fingerprint pin, Use-only scopes via folders/groups/shares, expiry, revocation with rotation prompt, events | Agents fit the sealed-box model; the API never holds an agent private key |
| 2. Gateway and MCP (§5) | `apps/gateway` with OAuth 2.1 and static tokens, KMS envelope keys, usage policy inside the encrypted body, SSRF and redirect rules, scrubbing, rate limits, client configs (§7) | Use without seeing, for HTTP API keys, from any cloud agent |
| 3. Approvals (§6) | Approval-required items with no standing key, relayed to approvers' browsers, ephemeral per-request keys, per-method and per-path policy | A control a hijacked agent cannot click through |
| 4. More credential types (§6) | ssh-agent protocol, database protocol proxy, autofill for agent browsers | Coverage beyond HTTP |
| 5. Hardening (§6) | Gateway in a Nitro or SEV-SNP enclave with attestation verified by the admin's browser, external audit, hash-chained log | Restores zero-knowledge for agent-scoped data against the operator |

## 4. Phase 1: agent members

### 4.1 Data model (Postgres migration)

```prisma
enum UserKind { person agent }

model User {
  /// agent: a machine member (docs/agents.md). No password, 2FA or email delivery: authHash, kdfSalt, wrappedUserKey and
  /// wrappedPrivateKey are "" and kdfParams {}. publicKey is the agent's one key (also its MembershipKey).
  kind   UserKind @default(person)
  agent  Agent?
  @@index([kind])
}

/// One row per agent member (1:1 with its User). The private key exists only inside the gateway's KMS envelope.
model Agent {
  userId        String       @id @db.Uuid
  user          User         @relation(fields: [userId], references: [id], onDelete: Cascade)
  orgId         String       @db.Uuid
  org           Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)
  createdById   String       @db.Uuid
  publicKey     String       @unique
  /// "k1.<kekId>.<wrappedDek>.<v1. envelope>": the X25519 private key under a per-agent DEK, the DEK under the gateway's
  /// KMS/HSM key (§5.3). Opaque to the API; useless without the KEK. Null after revocation.
  wrappedPrivateKey String?
  kekId         String
  /// Gateway identity signature over "agent-key:<orgId>:<userId>:<publicKey>" ("g1.<gatewayKeyId>.<sig>"), or from
  /// Phase 5 an enclave attestation document ("g2.…"). The admin's browser verifies it before pinning the key.
  attestation   String
  /// The admin compared the fingerprints and accepted the gateway's attestation.
  verifiedById  String?      @db.Uuid
  verifiedAt    DateTime?
  /// Access ends here (null: no expiry). Enforced by the API refusing ciphertext, not by cryptography.
  expiresAt     DateTime?    @db.Timestamptz
  revokedAt     DateTime?
  revokedById   String?      @db.Uuid
  lastUsedAt    DateTime?
  lastSyncLoggedAt DateTime?
  createdAt     DateTime     @default(now())
  tokens        AgentToken[]
  grants        AgentGrant[]
  @@index([orgId])
}

/// Static bearer token for API/SDK clients (§5.6): the token itself is shown once; only its hash is kept.
model AgentToken {
  id        String   @id @default(uuid()) @db.Uuid
  agentId   String   @db.Uuid
  agent     Agent    @relation(fields: [agentId], references: [userId], onDelete: Cascade)
  label     String
  tokenHash String   @unique
  createdById String @db.Uuid
  expiresAt DateTime? @db.Timestamptz
  lastUsedAt DateTime?
  revokedAt DateTime?
  createdAt DateTime @default(now())
}

/// OAuth 2.1 (§5.6): a dynamically registered MCP client, an authorization code in flight, and a granted refresh token.
model AgentOAuthClient { id String @id @default(uuid()) @db.Uuid; name String; redirectUris String[]; createdAt DateTime @default(now()) }
model AgentOAuthCode  { codeHash String @id; clientId String @db.Uuid; agentId String @db.Uuid; grantedById String @db.Uuid; codeChallenge String; redirectUri String; expiresAt DateTime; usedAt DateTime? }
model AgentGrant {
  id          String   @id @default(uuid()) @db.Uuid
  agentId     String   @db.Uuid
  agent       Agent    @relation(fields: [agentId], references: [userId], onDelete: Cascade)
  clientId    String   @db.Uuid
  grantedById String   @db.Uuid
  refreshHash String   @unique
  rotatedAt   DateTime?
  expiresAt   DateTime
  revokedAt   DateTime?
  createdAt   DateTime @default(now())
  @@index([agentId])
}

/// The gateway's identity public key as first seen by this API (lib/serverSecretCheck.ts pattern). A change stops the
/// API with a clear message unless GATEWAY_ACCEPT_NEW_IDENTITY=true.
model GatewayIdentity { id String @id @default("gateway"); keyId String; publicKey String; firstSeenAt DateTime @default(now()) }
```

The agent's `User.email` is `agent+<userId>@agents.invalid` (reserved TLD, satisfies the unique constraint). `Membership`: `role member`, `status invited` until verified, then `active`. One `MembershipKey` row: the agent's `publicKey`, `wrappedPrivateKey ""`, `userKeyGen 1`, `state current`. `FolderMember`, `RecordAccess`, `GroupMember`, `Session` and `Event` rows reference the agent's `User.id` as a person's.

### 4.2 Enrolment: the key is born in the gateway

1. **Admin creates the agent.** `POST /admin/agents` (`orgAdmin`) `{ name, expiresAt? }`. Hosted: `402 { error: "agent_limit", used, allowed }` when live agents (not revoked) would exceed `agentLimit` (§9), counted under a `FOR UPDATE` on the org row as `assertSeat` does. Name rules as org names.
2. **API asks the gateway for a key.** `POST <GATEWAY_INTERNAL_URL>/internal/agents` with header `X-Gateway-Token: <GATEWAY_API_TOKEN>` and body `{ agentId, orgId }`. The gateway generates an X25519 pair (`generateKeyPair()` from `@clane-vault/crypto`), wraps the private key (§5.3), signs `agent-key:<orgId>:<agentId>:<publicKey>` with its Ed25519 identity key, zeroes the plaintext key, and returns `{ publicKey, wrappedPrivateKey, kekId, attestation }`. Gateway down or refusing: `503 { error: "gateway_unavailable" }`, nothing created.
3. **API stores it** in one transaction: `User` (kind agent), `Membership` (invited), `MembershipKey`, `Agent`. Response `201 { id, name, publicKey, fingerprint, attestation, gateway: { keyId, fingerprint } }`. Event `agent.create` (`targetUserId` = agent, `meta.gatewayKeyId`).
4. **Admin's browser verifies and pins.** The Agents page fetches `GET /org/agents/gateway` → `{ url, identityKeyId, identityPublicKey }`, checks the attestation signature over the agent key with that identity key (Ed25519 verify via WebCrypto), compares it with the gateway pin and shows the gateway fingerprint with *Pinned* / *New* / *Changed — compare it with the published fingerprint*. The published fingerprint is in `docs/agents.md` and the hosted status page; self-hosters print it with `clane-gateway identity`. On **Verify** the browser sends `POST /admin/agents/:id/verify { publicKey }`; the API checks it equals `MembershipKey.publicKey` (`409 stale_key`), sets `verifiedAt` and `Membership.status active`. The browser then pins both the gateway identity and the agent key (`pinKey(me, orgId, agentUserId, publicKey)`). *Amended:* the gateway identity is pinned in **one fixed slot per signed-in user and organisation** (`gatewayPinStatus`), not one slot per `identityKeyId`, so a new key id shows as *Changed* rather than as a fresh pin (§10). Members who are not admins pin it trust-on-first-use from `GET /org/agents/gateway` on their first share to an agent; a changed identity is never re-pinned by a member, only by an admin here. A gateway identity change invalidates every existing attestation: such agents show *Needs re-enrolment* and are revoked and created again. Event `agent.verify`. A failed signature shows *The gateway did not sign this key* and offers revoke with `reason: "attestation_failed"`.

**What the gateway identity pin protects.** A compromised or malicious API server, or anyone with write access to its database, cannot substitute an agent key it controls: the browser requires a signature from the gateway's identity key, and `assertPinned` refuses every later seal to a changed key. A replaced gateway shows as *Changed* on every admin's browser. **What it does not protect.** A compromised gateway signs whatever key it generated, and it holds the keys anyway: the gateway is the trust boundary (§8). On the hosted service Clane operates both, so until Phase 5 this protects against an API-only breach and a stolen database, not against the operator. The TOFU limits of `docs/sharing.md` apply to the gateway pin as to any other: first use trusts, and pins are per browser.

Until verified the agent is not an `activeMember`, so no picker lists it and no folder key can be sealed to it.

### 4.3 Scope: Use-only access through folders, groups and shares

Granted exactly as to a person, with `use`:

- **Direct folder membership.** The folder owner adds the agent in the people sheet (`POST /folders/:id/members`, `permission: "use"`); the client runs `assertPinned`, `sealFolderKeyTo` (→ `sealOrgFolderKey`) and `pinKey`, as `addMembers` in `useVault.ts` does.
- **Groups.** An admin adds the agent to a group; key holders see it in `GET /group-access/pending` marked *Agent* and approve or decline.
- **Single records.** `POST /records/:id/shares` with `use`.

**Restricted-credential warning.** Every place a human shares to an agent (people sheet, PeoplePicker, group approval, record share sheet) shows, above the confirm button: *"Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent."* It is shown each time, not dismissable.

Server-side cap: `capForAgent(db, userId, permission)` in `lib/access.ts` returns `use` for agent users, applied in `POST /folders/:id/members`, `PATCH /folders/:id/members/:userId`, `POST /folders/:id/group-access`, `recomputeMember` (after `maxPermission`), `POST /records/:id/shares`, `PATCH /records/:id/shares/:userId`. Explicit requests for more get `400 { error: "agent_use_only" }`; group grants are capped silently. Agents are refused as folder successors (`folderSuccessor` skips `use`), by `org.transfer`, `admin.role_change` and group creation. `seatEmails` in `lib/seats.ts` adds `AND u.kind = 'person'`. `GET /users` and `/sync` members gain `kind`; pickers lock agents to *Use* and show a bot icon.

### 4.4 Agent sessions and the API's `/agent` routes

Agent access tokens are ES256 JWTs with scope `agent` (`signAgentAccess` in `lib/tokens.ts`; private key from `AGENT_TOKEN_PRIVATE_KEY`; public key published at `GET /.well-known/jwks.json`). Claims: `sub` agent user id, `org`, `aud` the gateway URL, `jti`, `grant` (an `AgentGrant.id` or `AgentToken.id`), `exp` 15 min. `requireAuth` keeps verifying HS256 scope `access`, so an agent token reaches no human route; `POST /auth/login` also refuses `kind = agent`. `app.requireAgent` verifies the ES256 token **and** `X-Gateway-Token`, loads `Agent`, `Membership` and the grant, and refuses with `401 unauthorized` (bad token, revoked grant or token), `403 agent_expired`, `403 agent_unverified`.

| Method | Path | Body → response | Errors |
|---|---|---|---|
| GET | `/agent/sync` | → `{ serverTime, orgId, wrappedPrivateKey, kekId, folders, records, expiresAt, entitlements: { approvals } }` | `agent_expired`, `agent_unverified` |
| POST | `/agent/events` | §5.5 | |
| GET | `/org/agents/gateway` | `requireAuth` + `orgRequired` → `{ url, identityKeyId, identityPublicKey }` | |
| GET | `/admin/agents`, POST `/admin/agents`, PATCH `/admin/agents/:id`, POST `/admin/agents/:id/verify`, DELETE `/admin/agents/:id` | §4.2, §4.5 | `agent_limit`, `gateway_unavailable`, `stale_key` |
| POST | `/admin/agents/:id/tokens` `{ label, expiresAt? }` → `201 { id, token }`; DELETE `/admin/agents/:id/tokens/:tokenId`; DELETE `/admin/agents/:id/grants/:grantId` | §5.6 | |
| GET | `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`; POST `/oauth/register`, `/oauth/token`, `/oauth/revoke`; GET `/oauth/authorize` (web page) | §5.6 | |

`GET /agent/sync` is the existing `/sync?space=org` body for the agent's user and org, with the route body moved into `lib/sync.ts` (`syncFor(prisma, cfg, { userId, orgId, orgOnly: true })`) so both routes share it. The API logs `agent.sync` (`meta.records`) at most hourly per agent (`lastSyncLoggedAt`).

### 4.5 Expiry, revocation, rotation prompt

- **Expiry.** `Agent.expiresAt`, editable with `PATCH /admin/agents/:id { name?, expiresAt? }`. After it, `requireAgent` refuses everything; the first refusal logs `agent.expired` once. The gateway treats `agent_expired` like revocation: cache dropped at once.
- **Revocation.** `DELETE /admin/agents/:id`, one transaction: list the live team folders and records it could open; `offboard(tx, orgId, userId, "remove")`; revoke every `AgentToken` and `AgentGrant`; null `wrappedPrivateKey`; `User.status disabled`, `Agent.revokedAt`. Then best-effort `DELETE /internal/agents/:id` on the gateway to drop its cache. The `User` row stays so the log keeps the name. Response `{ rotate: { folders: [{ id }], records: n } }`. Event `agent.revoke` (`meta: { reason?, folders, records }`).
- **Rotation prompt.** "The gateway could open these folders for this agent. Rotate the credentials in them." Folder-key rotation on removal is still the open follow-up in `docs/sharing.md`; the docs say the prompt is the substitute.

### 4.6 Events

| Action | Actor | Fields |
|---|---|---|
| `agent.create`, `agent.verify`, `agent.update`, `agent.revoke`, `agent.token_create`, `agent.token_revoke`, `agent.grant_revoke` | admin | `targetUserId` (agent); `meta.reason`, `meta.gatewayKeyId`, `meta.tokenId` |
| `agent.grant` | admin (the OAuth consent) | `meta.clientName` |
| `agent.sync`, `agent.expired` | agent (API-side) | `meta.records`; hourly / once |
| `agent.use`, `agent.refused`, `agent.reflected` | agent (reported by the gateway) | `recordId`, `meta.host`, `meta.method`, `meta.reason` |
| existing `folder.member_add`, `folder.group_access_*`, `record.share`, `group.member_add` | key holder or admin | unchanged; `targetUserId` is the agent |

### 4.7 Web app

- **Admin → Agents** (`features/admin/AgentsPage.tsx`): list with name, status (*Awaiting verification*, *Active*, *Expired*, *Revoked*), agent fingerprint, gateway fingerprint and pin state, expiry, last use, folders and groups. **New agent** → name, expiry → the verify dialog straight away (§4.2 step 4). **Connect** → the connector URL and per-client snippets (§7), **Create API token** (shown once), the list of OAuth grants (client name, granted by, when) with *Revoke*. **Revoke** → confirmation, then the rotation list. Hosted: `PlanLock` at `agentLimit`.
- **OAuth consent page** (`/oauth/authorize`, signed-in owner or admin): "<client> wants to use vault credentials as agent …" with an agent picker limited to the admin's orgs, then **Allow**. Members never see it.
- **People pickers and approval queue**: bot icon, *Use* locked, the restricted-credential warning.
- No sign-in, settings, recovery, People-page rows or health reports for agents (`kind = person` filters).

## 5. Phase 2: the gateway, MCP and usage policy

### 5.1 Usage policy inside the encrypted record body

A new optional top-level field of `RecordBody` (v2), validated in `validate()` in `packages/crypto/src/records.ts` and therefore inside the AES-GCM payload the API cannot read or alter:

```ts
interface AgentPolicy {
  v: 1;
  /** Exact host names, optionally ":port"; "*.example.com" matches one leftmost label. No IP literals, max 32. */
  hosts: string[];
  inject:
    | { kind: "bearer" }                                  // Authorization: Bearer <secret>
    | { kind: "basic" }                                   // Authorization: Basic base64(username:secret)
    | { kind: "header"; name: string; prefix?: string }   // <name>: <prefix><secret>
    | { kind: "query"; name: string };                    // ?<name>=<secret>; labelled weaker (URLs get logged)
  /** "password", "data.<key>" or "field:<custom field id>". Default by type: apiKey → data.secret, login/server/database → password. */
  secret?: string;
  /** Phase 3; the gateway enforces them whenever present. */
  methods?: ("GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE")[];
  paths?: string[];          // prefix match on the URL path, max 32
  approval?: boolean;
}
// RecordBody gains: agentPolicy?: AgentPolicy
```

Rules: unknown keys refused; `hosts` non-empty, lower-cased, each `^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+(:\d{1,5})?$`; `paths` start with `/`; `secret` must name a field the type has. Edit holders write it in the record editor (**Agent use** section). A record without `agentPolicy` is listed to the agent but never injected: use with no policy is no use.

### 5.2 The service: `apps/gateway`

A separate workspace package and container (`ghcr.io/clane-ai/clane-gateway`), never the API process. Dependencies: `@modelcontextprotocol/sdk` (Streamable HTTP server transport over `node:http`), `jose` (token verification, DCR metadata), `undici` (outbound client with a pinned-address `connect`), `@clane-vault/crypto`; `@aws-sdk/client-kms` as an optional dependency loaded only when configured; *amended:* Google Cloud KMS through its REST API with metadata-server credentials instead of `@google-cloud/kms` (§13). No database: the gateway's only state is its identity key; everything else is read from the API per call and cached briefly.

Configuration (env): `API_URL`, `GATEWAY_API_TOKEN` (32+ bytes, shared with the API), `PUBLIC_URL` (e.g. `https://vault.clane.ai/mcp`), `GATEWAY_KEK` (`aws-kms:<key arn>` | `gcp-kms:<resource name>` | `file:<path to 32 random bytes>`), `GATEWAY_IDENTITY_KEY_FILE` (Ed25519 private key wrapped under the KEK; generated at first start), `GATEWAY_CACHE_TTL_SECONDS` (default 60, `0` = none), `GATEWAY_AGENT_RATE_PER_MINUTE` (default 60), `GATEWAY_MAX_RESPONSE_BYTES` (default 4 MiB), `GATEWAY_UPSTREAM_TIMEOUT_MS` (default 30 000), `GATEWAY_ALLOW_PRIVATE_CIDRS` (self-hosted only; default none). The API gets `GATEWAY_INTERNAL_URL`, `GATEWAY_PUBLIC_URL`, `GATEWAY_API_TOKEN`, `AGENT_TOKEN_PRIVATE_KEY`.

Routes: `POST /mcp` (and the GET/DELETE the transport needs), `GET /.well-known/oauth-protected-resource` (points at the API's authorization server), `POST /internal/agents`, `DELETE /internal/agents/:id`, `GET /internal/health` (returns the identity key; the API pins it in `GatewayIdentity` at start). `/internal/*` requires `X-Gateway-Token`; in compose it is on an internal network only.

### 5.3 Keys at rest: envelope encryption

Per agent: a random 32-byte DEK; the X25519 private key AES-GCM under the DEK with AAD `agent-private-key:<orgId>:<agentId>:<publicKey>` (`aeadEncrypt`); the DEK wrapped by the KEK (KMS `Encrypt` with encryption context `{ agentId, orgId }`, or AES-GCM under the file key with the same AAD). Stored as `k1.<kekId>.<wrappedDek>.<v1. envelope>` in `Agent.wrappedPrivateKey`, in the API database. A database dump yields nothing without the KEK; KMS use is itself logged (CloudTrail, Cloud Audit Logs), which is the operator-side audit trail of every decrypt.

Per call: fetch `/agent/sync` (cached for the TTL), unwrap the DEK through the KEK, open the private key, open folder keys (`openOrgFolderKey`) and record keys (`openRecordKey`), decrypt only the record the call names (`decryptRecordBody`), read the policy and the secret field, run the request, then `fill(0)` every key and secret buffer. The DEK and opened private key are cached for `GATEWAY_CACHE_TTL_SECONDS` keyed by agent (0 means a KMS call per request). Record bodies are never cached.

Process rules: no value is ever passed to a logger, an error message, a stack trace or a response other than the injected header. A single error serialiser replaces any occurrence of secrets currently held in memory with `[redacted]` before anything is logged; `uncaughtException` logs the error class only and exits. Core dumps off (`ulimits: core: 0` in the compose file; *amended:* no Helm chart and no `prlimit` in the distroless image, §13), read-only root filesystem, no shell in the image, `--heapsnapshot-signal` and inspector disabled. The docs state that JavaScript cannot guarantee zeroing (the GC may copy buffers); the enclave is the real answer.

### 5.4 Outbound calls: allowlist, SSRF and redirects, scrubbing

- **Allowlist** from the record's `agentPolicy.hosts` (and Phase 3 `methods`/`paths`). The request URL must be `https:` (`http:` only for hosts in `GATEWAY_ALLOW_PRIVATE_CIDRS` ranges, self-hosted). Mismatch → the tool returns `{ error: "refused", reason: "host" }` with no connection, event `agent.refused`.
- **SSRF.** Resolve the host (A and AAAA); refuse if any address is loopback, link-local (`169.254.0.0/16`, `fe80::/10`), private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), CGNAT (`100.64/10`), multicast, unspecified, or a cloud metadata address (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`); connect to exactly the resolved address with SNI and `Host` set to the policy host (`undici` `Agent` with a custom `connect.lookup`), so a DNS rebind between check and connect cannot land elsewhere. `GATEWAY_ALLOW_PRIVATE_CIDRS` lists the only exceptions.
- **Redirects.** `redirect: "manual"`; follow at most 3 hops, only when the new host passes the same allowlist and SSRF checks; otherwise return the 3xx without the `Location` credential. *Amended:* the credential is re-injected only on a same-origin hop; a hop to a different origin goes without it, even to another allowed host (as browser `fetch` drops `Authorization` cross-origin). A `Location` that contains the secret is never followed (§13).
- **Strip then inject.** Drop any `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key` and the policy's header or query name the agent supplied; set the real one per `inject`. Body passed through unchanged (max 1 MiB).
- **Limits.** `GATEWAY_UPSTREAM_TIMEOUT_MS` total; responses read up to `GATEWAY_MAX_RESPONSE_BYTES`, then closed and marked `truncated: true`; one in-flight call per MCP session.
- **Scrub.** Response headers and body are scanned for the exact secret bytes and their base64, base64url, URL-encoded and hex forms (and the `username:secret` basic string); matches become `[clane:redacted]`, event `agent.reflected`. Bodies are decompressed before scanning. A hostile host that re-encodes a value otherwise gets past; the docs say so.

### 5.5 MCP server and use events

Streamable HTTP at `POST /mcp`. Each session is bound to the token's agent. Tools:

| Tool | Input | Output |
|---|---|---|
| `list_secrets` | — | `[{ handle, title, type, hosts, inject, approval, methods?, paths? }]`; handle = `<folder>/<title>` slug, unique per agent |
| `http_request` | `{ item, method, url, headers?, body? }` | `{ status, headers, body, truncated? }` after §5.4, or `{ error, reason }` |
| `request_access` (Phase 3) | `{ item, reason }` | approval id |

No `get_secret`, nothing that returns a field marked secret; the server instructions say so. Tool definitions are static.

Use events: after each call the gateway posts `POST /agent/events` `{ events: [{ at, recordId, action: "use" | "refused" | "reflected", host, method, reason?, truncated? }] }` (batched, max 200) → `Event` rows `agent.<action>` with `actorId` = agent, `orgId`, `recordId` (dropped unless the agent can open it), `meta`. No values, paths or query strings. The gateway's own stdout log carries the same fields and nothing more.

### 5.6 MCP authentication: OAuth 2.1 and static tokens

- **Protected resource**: `GET https://vault.clane.ai/mcp/.well-known/oauth-protected-resource` → `{ resource, authorization_servers: ["<API_URL>"], bearer_methods_supported: ["header"] }`. Unauthenticated `/mcp` calls get `401` with `WWW-Authenticate: Bearer resource_metadata="…"`.
- **Authorization server (the API)**: metadata at `/.well-known/oauth-authorization-server` (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `jwks_uri`, `code_challenge_methods_supported: ["S256"]`, `grant_types_supported: ["authorization_code", "refresh_token"]`). Dynamic client registration at `POST /oauth/register` (name, redirect URIs; `https` or loopback only). `GET /oauth/authorize` is the consent page of §4.7; it issues a code bound to the chosen agent, the client and the admin, with PKCE S256 required. `POST /oauth/token` exchanges the code for an ES256 access token (§4.4; 15 min, `aud` = gateway URL, `grant` = the new `AgentGrant.id`) and a rotating refresh token (30 days, hashed in `AgentGrant`). Refresh reuse after rotation revokes the grant (as `/auth/refresh` does). `POST /oauth/revoke` and the Agents page end a grant; the gateway sees the revoke at its next API call because `requireAgent` checks the grant on every request.
- **Static bearer tokens** for the Claude and OpenAI APIs and CI: `POST /admin/agents/:id/tokens` returns `cvat_<id>_<secret>` once; the gateway exchanges it at `POST /oauth/token` with `grant_type=client_credentials`-style body `{ grant_type: "urn:clane:agent-token", token }` for a 15-minute ES256 token, cached until expiry. Revocable per token; optional expiry.
- **Rate limits** per agent in the gateway (`GATEWAY_AGENT_RATE_PER_MINUTE` for `http_request`, 20/min for `list_secrets`; `429` with `Retry-After`) and per client address, plus the API's existing per-address limit on `/oauth/*`.

### 5.7 Self-hosted deployment

`deploy/client/docker-compose.yml` gains a `gateway` service (image, `GATEWAY_KEK=file:/run/secrets/gateway-kek`, `ulimits: core: 0`, `read_only: true`, internal network to the API, published only as `/mcp` through the existing reverse proxy). `docs/agents.md` covers KMS setup on AWS and GCP, the file-key fallback and its weaker standing (the key sits on the same host), backup of the KEK (lose it and every agent must be re-enrolled; nothing else is affected), the identity fingerprint and how to publish it to admins.

## 6. Phases 3–5 (outline)

**3. Approvals.** `agentPolicy.approval: true` items are not reachable through folder keys: the owner's client re-wraps the record key under a per-record approval key sealed to each approver's membership key (new `RecordAccess` holder type `approver`) and removes the folder-row wrap. On `request_access` the gateway generates an ephemeral X25519 pair for the request and posts `POST /agent/approvals { recordId, host, method, path, reason, requestPublicKey }`; approvers' browsers poll `GET /approvals/pending`, see item, destination and reason, and on approve seal the record key to `requestPublicKey` with a TTL. The API relays opaque blobs and logs `approval.request|grant|deny|expire`. `methods` and `paths` are enforced from this phase and shown in the editor. Hosted: Business (`agentApprovals`, `agentPathPolicy`).

**4. More credential types.** An ssh-agent-protocol endpoint (sign only) for `sshKey` records; a PostgreSQL/MySQL protocol proxy that performs the auth handshake itself; autofill into agent-driven browsers through the extension, behind the same approval flow.

**5. Enclave and audit.** The gateway container runs unchanged inside a Nitro enclave (or SEV-SNP confidential VM). The KEK's key policy requires attestation (`kms:RecipientAttestation:ImageSha384` on the enclave PCRs), so only that measured code can unwrap agent keys, not the host, not an operator with KMS rights. The identity key is generated inside the enclave and its public half bound into the attestation document; `Agent.attestation` becomes `g2.<document>` and the browser verifies the Nitro certificate chain and the PCRs published with each release instead of a pinned Ed25519 key. Nothing else changes: same routes, same data, same seals. This restores zero-knowledge for agent-scoped data against the operator, and is the gate for removing the evaluation label on this feature, together with an external audit and hash-chained `agent.*` events.

## 7. How Claude and OpenAI connect

Hosted URL `https://vault.clane.ai/mcp`; self-hosted `https://<your host>/mcp`. OAuth flows end on the consent page, where an owner or admin picks the agent. API clients use a static token from the Agents page.

**Claude.ai (web and desktop)** — *Customize → Connectors → + Add → Add custom connector* → name and URL `https://vault.clane.ai/mcp` → *Continue* → OAuth client *Register automatically* → *Add* → *Connect* → sign in to Clane Vault, pick the agent, *Allow*. Uses dynamic client registration and PKCE; no client id to copy. (Team and Enterprise: an owner adds it under *Organization settings → Connectors*.)

**ChatGPT** — *ChatGPT Plugins* (`chatgpt.com/plugins`) → *+* → *Add custom MCP server* → name, description, MCP server URL `https://vault.clane.ai/mcp`, authentication OAuth → *I understand and want to continue* → *Create as a plugin* → consent page as above. Account and workspace policies decide whether custom MCP servers are allowed.

**Claude Code** — `claude mcp add --transport http clane-vault https://vault.clane.ai/mcp` then `/mcp` to sign in (OAuth), or non-interactive with a static token: `claude mcp add --transport http clane-vault https://vault.clane.ai/mcp --header "Authorization: Bearer cvat_…"`.

**Claude API (Messages API MCP connector)** — both halves are required, with the beta header:

```json
{
  "model": "claude-opus-5-5",
  "max_tokens": 16000,
  "mcp_servers": [{ "type": "url", "url": "https://vault.clane.ai/mcp", "name": "clane-vault", "authorization_token": "cvat_…" }],
  "tools": [{ "type": "mcp_toolset", "mcp_server_name": "clane-vault" }],
  "messages": [{ "role": "user", "content": "Create a Stripe test customer for ACME." }]
}
```
Header `anthropic-beta: mcp-client-2025-11-20`. Managed Agents declare the same `mcp_servers` entry on the agent and keep the token in a vault credential.

**OpenAI Responses API (remote MCP tool)**:

```json
{
  "model": "<model>",
  "tools": [{ "type": "mcp", "server_label": "clane_vault", "server_url": "https://vault.clane.ai/mcp",
              "authorization": "cvat_…", "require_approval": "never" }],
  "input": "Create a Stripe test customer for ACME."
}
```
(Verified 2026-10-18 against OpenAI's MCP and connectors guide: `authorization` is the bare token, not stored by OpenAI, so sent with every request. The client steps above were re-checked the same day; sources are cited in `docs/agents.md`.)

The docs and the Connect sheet show one model prompt, as a separate *Tell the model* block rather than inside each snippet: *"Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential."*

## 8. Zero-knowledge accounting and threat model

### 8.1 Who can read what

| Data | Server (API, database) | Gateway (hosted: Clane; self-hosted: you) | Model / agent client |
|---|---|---|---|
| Records never shared to an agent | ciphertext only (unchanged) | nothing (no key reaches it) | nothing |
| Records in folders, groups or shares an agent holds | ciphertext only | **plaintext at use time**, and *could* decrypt at any time while the agent is live (it holds the wrapped key and the KEK) | names, hosts, policy; responses with the secret scrubbed |
| Agent private key | KMS-wrapped envelope only | plaintext in memory per call; wrapped at rest | never |
| Who used what, where, when | metadata events | metadata log | its own calls |

The docs and the sharing UI say in one sentence: *Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted.*

### 8.2 Threats

| Threat | Mitigation | Residual risk |
|---|---|---|
| Prompt injection makes the agent exfiltrate a value | No tool returns a value; the gateway strips agent-supplied auth and injects only for policy hosts; scrubbed responses | A hijacked agent can make legitimate-looking calls to an allowed host with bad intent (delete the repo, email the customer list). Phase 3 per-path policy and approvals narrow it; nothing removes it |
| Malicious or compromised API server substitutes an agent key | Keys are generated and signed in the gateway; the browser verifies the signature against the pinned gateway identity before sealing; `assertPinned` on every later seal | A compromised gateway; hosted, Clane runs both until the enclave (Phase 5). First-use TOFU on the gateway identity per browser, mitigated by the published fingerprint |
| API server or database breach | Agent keys are KMS envelopes; records are ciphertext; tokens are hashed | None beyond what exists today for people (metadata, the trust limits in `docs/sharing.md`) |
| Gateway host breach (with its KMS permissions) | Decrypt per call, short cache, no plaintext on disk, no shell, read-only FS, no core dumps; KMS audit log shows every unwrap; only agent-scoped items are reachable; revoking an agent nulls its wrapped key | **Agent-scoped plaintext is readable**: this is the accepted exception. Rotate the credentials of every agent-scoped folder after a gateway incident. Enclave removes it |
| Insider at the operator | Separation of duties: KMS key policy limited to the gateway's role, not to engineers; deploy pipeline with reviewed images; CloudTrail/Audit Logs on the KEK; no interactive access to the gateway host; agent-scoped data only | An insider who controls both the deploy pipeline and the KMS policy can read agent-scoped items until Phase 5 |
| Legal compulsion of the operator | For non-agent data Clane cannot comply technically. For agent-scoped data it could, by deploying a modified gateway; the transparency section of the docs commits to disclosing requests where the law allows | Users with legal exposure should not share such items to agents on the hosted service, or should self-host (the KEK and gateway are then theirs) |
| Logs, crash dumps, error messages | Secret-aware error serialiser; metadata-only events; core dumps disabled; inspector and heap snapshots disabled; no request/response bodies logged | A kernel-level or hypervisor dump of the host; JavaScript cannot guarantee zeroing |
| SSRF through the gateway (metadata endpoints, internal services, DNS rebinding) | Public-address check after resolution, pinned connect address, no private ranges, metadata hosts blocked, manual redirects re-checked, `https` only | Operators who widen `GATEWAY_ALLOW_PRIVATE_CIDRS` |
| Reflection and encoding leaks | Scrub exact bytes and base64, base64url, URL and hex forms in headers and body, decompressed; `agent.reflected` logged | A hostile allowed host that re-encodes the value. Values that reach a model fall under the model provider's retention; rotation is mandatory after a suspected leak |
| Stolen MCP token (OAuth or static) | Short ES256 access tokens bound to one agent and the gateway audience; rotating refresh tokens with reuse detection; revocable per grant and per token; per-agent rate limits | The holder can *use* the agent's credentials against allowed hosts until revoked, exactly as the agent could |
| Compromised gateway under-reports use | `agent.sync`, `agent.verify`, `agent.revoke`, OAuth grants and KMS audit entries are outside the gateway | `agent.use` events are self-reported by the gateway |
| Revocation and expiry lag | API refuses on the next call; grants checked on every request; gateway cache TTL ≤ 60 s by default and dropped on refusal; rotation prompt | Nothing |
| Query-string injection logged by intermediaries | `inject.kind: "query"` labelled weaker | Operators who choose it |

## 9. Plans and entitlements

Self-hosted (`BILLING_MODE=off`): everything, no limits. Hosted: **agents are not seats**.

| | Personal | Team | Business | Self-hosted |
|---|---|---|---|---|
| Agent members (live) | 0 | 3 | 10 | unlimited |
| Use-only scopes, destination binding, MCP, OAuth, static tokens | — | ✓ | ✓ | ✓ |
| Approval-required items; per-method and per-path policy in the editor (Phase 3) | — | — | ✓ | ✓ |
| Agent events in the log | — | 30 days | 365 days + CSV | ✓ |
| Above the bundle | — | add-on, priced later (nearer €1 than €20 per agent) | same | — |

`lib/plans.ts`: `Feature` gains `"agentApprovals" | "agentPathPolicy"` (in `FEATURES`, so `all()` covers them); `Entitlements` gains `agentLimit: number | null` (`UNLIMITED` null, `TEAM` 3, `BUSINESS` 10, personal 0). `POST /admin/agents` replies `402 { error: "agent_limit", used, allowed }`; `GET /org/plan` adds `agents: { used, allowed }`; Phase 3 routes use `requireEntitlement("agentApprovals")`. `agentPathPolicy` gates editor fields only: the policy is ciphertext, and the gateway always enforces whatever it contains, so a downgrade never loosens a restriction. A downgrade past the bundle blocks new agents only.

## 10. Tests (acceptance)

- `BILLING_MODE=off`: the full existing e2e suite passes unchanged; agents unlimited; `agent_limit` never returned.
- `POST /admin/agents` with the gateway down returns `503 gateway_unavailable` and creates nothing; with it up, the `Agent` row holds a `k1.` envelope, a `g1.` attestation, and the `MembershipKey` has `wrappedPrivateKey ""`.
- The attestation verifies with the gateway identity key; a tampered `publicKey` fails verification in the browser test; `verify` with a different key returns `409 stale_key` and leaves the membership invited.
- Before verification the agent is absent from `GET /users`, `GET /group-access/pending` and the pickers; `POST /folders/:id/members` for it returns `400 user_not_active`.
- Any permission other than `use` for an agent returns `400 agent_use_only`; an agent in an `edit` group gets an effective `use` row; agents never change `seats.used`.
- An agent token is refused by every `requireAuth` route; a person's token by every `/agent/*` route; `/agent/*` without `X-Gateway-Token` returns `401`; `POST /auth/login` refuses an agent user.
- OAuth: DCR, authorize with PKCE S256 (plain refused), code single use, token `aud` = gateway URL and `sub` = the chosen agent, refresh rotation, refresh reuse revokes the grant, `/oauth/revoke` and the Agents page end access on the next gateway call. A static token works, is shown once, and stops after revoke or expiry.
- After `expiresAt`, `GET /agent/sync` returns `403 agent_expired`, logged once; revoke removes rows, grants and tokens, nulls `wrappedPrivateKey`, lists the folders it could open, and the gateway returns `401` to the next MCP call.
- Gateway unit tests: the wrapped key cannot be opened with the wrong KEK or wrong AAD; a `file:` and a mocked `aws-kms:` backend both round-trip; with `GATEWAY_CACHE_TTL_SECONDS=0` every call hits the KEK once; after the TTL the DEK is gone from memory (inspectable test hook).
- SSRF: hosts resolving to `127.0.0.1`, `10.0.0.5`, `169.254.169.254`, `fd00::1`, `metadata.google.internal` are refused with no socket opened (stubbed resolver); a host that resolves publicly at check time and privately at connect time still connects to the checked address.
- Redirects: a 302 to a non-allowed host is returned without following and without the credential; a 302 to another allowed host is followed without the credential (amended, §5.4); a 4th hop stops.
- Scrubbing: a response echoing the secret raw, base64, base64url, URL-encoded, hex and as `user:secret` basic comes back with `[clane:redacted]` in headers and body and one `reflected` event; gzip bodies are scrubbed; a body over the cap is truncated and marked.
- Strip-then-inject: agent-supplied `Authorization`, `Cookie` and the policy's header are replaced; `list_secrets` output contains no field marked secret; a record with no `agentPolicy` is listed and refused on `http_request` (`reason: "no_policy"`).
- No plaintext in logs: a test runs every error path (bad KEK, upstream timeout, scrub hit, uncaught exception) with a known secret and asserts it never appears in stdout, stderr or the error response.
- Rate limit: the 61st `http_request` in a minute returns `429` with `Retry-After`.
- Hosted: the 4th live agent on Team returns `402 agent_limit`; revoking one frees the slot; approval routes return `402 plan_required` on Team.
- Web: Agents page flows (create → verify dialog with both fingerprints → *Matches* pins both; changed gateway key shows *Changed*; connect sheet shows snippets; token shown once; revoke → rotation list); the restricted-credential warning appears on every share to an agent.

## 11. Open decisions

1. **Agent as a `User` row versus a separate identity table.** Recommend the `User` row with `kind = agent`: every access path, lock and offboarding routine is reused; cost is sentinel values in five columns and a `kind` filter in seats, login and the People page.
2. **Scope envelope key versus folder keys.** Recommend folder keys: a folder already is a one-seal scope, and groups give admins a way to scope folders they do not own with a key holder's approval.
3. **Where wrapped agent keys live.** Recommend the API database (this spec): the gateway stays stateless, and the envelope is useless without the KEK. Alternative: a gateway-owned store, which adds a database to the "small" service.
4. **Consent for OAuth.** Recommend owners and admins only, choosing an agent of an org they administer. Letting members connect their own agent would turn agents into personal credentials, which seats and audit are not designed for.
5. **Cache TTL default.** Recommend 60 s: one KMS call per agent per minute under load; `0` for the most sensitive deployments.
6. **Private-range exceptions.** Recommend shipping `GATEWAY_ALLOW_PRIVATE_CIDRS` for self-hosters with internal APIs, off by default and never set on the hosted gateway.
7. **Bundle sizes.** Recommend Team 3, Business 10, add-on price with the Stripe work.
8. **Query-string injection.** Recommend shipping it with the weaker label.
9. **Token signing algorithm.** Recommend ES256 with a JWKS endpoint over a shared HS256 secret, so the gateway cannot mint human tokens.
10. **Should the hosted gateway run in the enclave from launch** (Phase 5 pulled forward)? Recommend no for the first release: ship with the disclosure, keep the data model enclave-ready (`g2.` attestations), and make the enclave the headline of the audit release.

## 12. Assumptions

- `@clane-vault/crypto` runs under Node 22 as is (WebCrypto X25519 and `crypto.subtle` only); `@modelcontextprotocol/sdk` ships a Streamable HTTP server transport usable on `node:http` without a framework; `undici`'s `connect.lookup` option allows pinning the resolved address with SNI set to the host name.
- `validate()` strictness on unknown keys extends naturally to `agentPolicy`; `keyFingerprint` output is what the web app shows (`fingerprintOf`).
- `docs/design/2026-10-08-per-org-keypairs.md` was not re-read; behaviour was taken from `lib/membershipKeys.ts`, `routes/membershipKeys.ts` and `apps/web/src/lib/orgKeys.ts`.
- The OpenAI remote MCP tool shape and the ChatGPT connector steps were verified against their public docs on 2026-10-18 (§7); the Claude.ai and ChatGPT steps were corrected then.

## 13. Deviations from the report

- **No local broker, egress proxy or exec mode.** The report's `clane-agent` daemon is replaced by a hosted gateway reachable only as a remote MCP server, by the user's decision. The consequence, agent-scoped plaintext at the gateway, is disclosed rather than hidden (§8.1).
- **No separate scope envelope key.** The code already has that shape per folder, so a scope is a folder and admins reach folders they do not own through groups plus key-holder approval.
- **Agents are `User` rows**, not a new principal, because `accessFor`, `/sync`, groups, `offboard` and the event log are keyed on `User.id`.
- **Enrolment fingerprint.** The report has the admin compare a fingerprint printed on the agent's host. There is no host, so the gateway signs the key with a pinned identity key and the admin's browser verifies it; the admin compares the *gateway's* fingerprint with a published one instead (§4.2).
- **Use-only is enforced server-side for agents**, while it stays a soft limit for people.
- **Per-path policy cannot be plan-gated on the server** because it is ciphertext; the spec gates the editor only.
- **Revocation prompts credential rotation** rather than rotating folder keys, because folder-key rotation on removal is still an open follow-up.

### Deviations from this spec found in implementation

- **Gateway identity pin: one fixed slot** per signed-in user and organisation, not one per `identityKeyId` (§4.2). The §10 *Changed* requirement needs it. Members pin trust-on-first-use; only admins re-pin a changed identity, and a change invalidates every agent attestation (re-enrol).
- **No credential on a cross-origin redirect**, even to another allowed host (§5.4, §10). Matches browser `fetch`; a redirect-across-hosts API loses auth through an agent.
- **Google Cloud KMS through REST** with metadata-server credentials instead of `@google-cloud/kms`; `@aws-sdk/client-kms` is an optional dependency bundled into the image (§5.2). Infeasible to keep the GCP SDK in a small bundled distroless image.
- **The file KEK's AAD** is `kek:<sorted k=v context>` (the KMS encryption context as a string), not the agent-private-key AAD; the private key itself still uses `agent-private-key:<orgId>:<agentId>:<publicKey>` under the DEK (§5.3).
- **No `prlimit` and no Helm chart** (§5.3, §5.7): the distroless image has no `prlimit`, so core dumps are off through `ulimits: core: 0` in the compose file only. Kubernetes users set the equivalent themselves.
- **Runtime guard is an allowlist**: the gateway refuses any `NODE_OPTIONS`, any Node flag outside a short allowlist, and starting without `--disable-sigusr1` (the image runs `node --disable-sigusr1 dist/server.js`; the dev script builds then runs the same way). Node's option parsing makes a denylist of inspector flags unwinnable.
- **Encoded `/`, `\` and `.` in request paths are always refused** (`%2f`, `%5c`, `%2e`, double-encoded too), which makes APIs that use encoded slashes in paths (GitLab project paths) unusable through an agent. Path policy matches whole segments; an empty `methods` or `paths` list denies everything; Unicode policy hosts are refused (punycode only).
- **MCP transport** answers with JSON responses (no SSE streaming), so an API refusal inside a tool call can return HTTP 401.
- **Error codes added**: `409 agent_revoked`, `400 invalid_redirect_uri`, `403 forbidden` (gateway session of another agent), `429 rate_limited`, `503 api_unavailable` (gateway cannot reach the API).
