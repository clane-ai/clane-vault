# Personal agents, agent writes and agent reveal (Phases A–D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every signed-in person can enrol their own agent, grant it single items from their Personal space (Use), let it save and update secrets through a reviewed inbox, and let it read named fields after an in-app approval (or, where the operator and every policy allow it, without one).

**Architecture:** A personal agent is the shipped agent principal (`User` kind `agent` + `Agent` row) with `ownerUserId` in place of `orgId`, and no `Membership`. The owner's public key is bound into the gateway's attestation and into the AAD of the agent's wrapped key (`k2.`), so a swapped owner key stops the agent. Access is one `RecordAccess` row per item, sealed by the owner's browser after it verified the attestation. Writes arrive as gateway-signed `AgentDeposit` rows that only the owner's unlocked browser turns into records; the `s1.`-on-own-record guard in `decrypt.ts` is untouched. Approved reveal never gives the gateway a record key: the browser seals only the approved fields to a one-time key the gateway signed. Standing reveal is a field in the encrypted body, gated by `GATEWAY_REVEAL=standing` and every applicable organisation policy.

**Tech Stack:** As the shipped plan (`docs/superpowers/plans/2026-10-17-agent-access.md`): Fastify 5, Prisma 6 / Postgres, zod, jose, vitest against real Postgres; `apps/gateway` (`node:http`, `@modelcontextprotocol/sdk`, undici, `@clane-vault/crypto`); web: React, TanStack Query, msw; extension (MV3); Playwright. No new dependency anywhere.

**Spec:** `docs/design/2026-11-15-personal-agents.md`. It builds on `docs/design/2026-10-17-agent-access.md` ("the shipped design"). Executors read both.

**Phases.** A = Tasks 1–9 (personal agents, Use). B = Tasks 10–15 (writes). C = Tasks 16–21 (approved reveal). D = Tasks 22–23 (standing reveal). Each phase ends in an acceptance task (e2e + docs) and ships on its own; do not start a phase before the previous one's acceptance task passes.

## Resolved decisions (spec §9, the owner said "build it")

1. **Personal agents reach Personal items only.** No team-folder item, no item shared with the owner by someone else. `POST /records/:id/agent-grants` refuses both.
2. **Allowances per person:** Personal 1, Team 2, Business 5, outside the organisation bundle (`agentLimit` 0 / 3 / 10 is unchanged).
3. **Standing reveal is built, and off unless the gateway operator sets `GATEWAY_REVEAL=standing`.** `GATEWAY_REVEAL` defaults to `off`. This repository says nothing about what any hosted service sets.
4. **Personal agents are allowed by default** (`personalAgents.allowed: true`, `reveal: "approval"`).
5. **Email is a notification only.** It has no approve link, no item title and no reason. Approval happens in the web app.

## Spec defects found while planning, and the rulings

| # | Defect | Ruling |
|---|---|---|
| R1 | §3.4 says Team reads the policy defaults read-only; §9.4 notes Team admins then cannot switch personal agents off. | The `personalAgents` block is editable on **every** plan, through its own route (`PUT /admin/settings/policies/personal-agents`, no `policyEdit` gate), and `readPolicies` honours the stored block even without `policyEdit`. |
| R2 | §3.4 `maxPerMember` defaults to 2, which would silently cap Business's allowance of 5 (decision 2). | `maxPerMember` is `nullable`, default `null` = no organisation cap. A hard ceiling of 20 per person applies everywhere (the schema's maximum), self-hosted included. |
| R3 | §3.7 "the owner's account is deleted": the API has no account deletion route. The only code that deletes `User` rows is `deleteSandbox` (`lib/demo.ts`). | `revokePersonalAgentsOf(tx, ownerUserId)` exists and `deleteSandbox` calls it. `Agent.owner` is `onDelete: Cascade`. |
| R4 | Agent access tokens carry a required `org` claim (`lib/tokens.ts`, gateway `auth.ts`). The spec is silent. | A personal agent's token carries `owner` (the owner's user id) and no `org`. Both verifiers require exactly one of the two. |
| R5 | §5.3 "long-polling the API, up to 50 seconds". The gateway's API calls time out at 15 s and the API holds no connections. | The gateway polls `GET /agent/reveals/:id` every 2 s for at most 50 s. Same behaviour for the agent. |
| R6 | §5.3 has the extension show the approval sheet. The gateway pin lives in the web app's `localStorage`; the extension has none and could not verify a request's signature. An MV3 background also cannot poll every 5 s. | The extension only **notifies** (badge, system notification, a popup row that opens the web app). *Allow* exists in the web app only. The extension polls on a 30-second alarm, and every 5 s while its popup is open. |
| R7 | §4.4/§5.3 give no tag for the update and reveal-request signatures, and don't say which revision an update signs. | `u1.<keyId>.<sig>` and `q1.<keyId>.<sig>`. A deposit or update signature covers the revision the row has **after** the write. |
| R8 | §4.3 doesn't say whether an unkept deposit can be used with `http_request`. Its usage policy is "reviewed at Keep". | Not until kept: `reason: "not_kept"`. Also new: `reason: "invalid"` for a body the editor's rules refuse. |
| R9 | §3.5 stores grants as `RecordAccess` user rows with `orgId null`. The Personal `/sync` would list them under `sharedWith`, and the shipped `/records/:id/shares/:userId` routes match them. | `/sync` returns them as `agentGrants` instead, never in `sharedWith`. The shares routes cannot raise one (`400 agent_use_only`, already shipped; pinned by a test). |

## Global Constraints

- Everything here is off when agent access is off (`GATEWAY_INTERNAL_URL` unset), and additionally when `PERSONAL_AGENTS=off` on the API (default `on`). Off means `/me/agents*`, `/records/:id/agent-*`, `/me/agent-*` answer 404 and the web app shows no *My agents* section. With both unset the existing unit and e2e suites pass unchanged.
- **Kept from the shipped design, not to be weakened:** the SSRF guard and redirect rules, scrubbing of every `http_request` response, attestation verification by every browser that seals to an agent, trust-on-first-use pinning with no silent re-pin, the gateway's runtime guard (`assertSafeRuntime`), generation-based OAuth refresh, strip-then-inject. Organisation agents keep exactly two tools and today's behaviour.
- A personal agent's rows: `User` as for any agent (`kind agent`, `agentEmail(id)`, empty auth columns); `Agent` with `orgId null`, `ownerUserId` set, `createdById` = the owner. **No `Membership` and no `MembershipKey`.** A database CHECK enforces exactly one of `orgId`, `ownerUserId`.
- Messages and AADs, exact (base64url keys, UTF-8, constructors in `packages/crypto/src/agents.ts`):
  - attestation `g1.`: `personal-agent-key:<ownerUserId>:<ownerPublicKey>:<agentId>:<publicKey>`
  - wrapped key `k2.<kekId>.<wrappedDek>.<v1. envelope>`, AAD `agent-private-key:personal:<ownerUserId>:<ownerPublicKey>:<agentId>:<publicKey>`, KEK context `{ agentId, ownerUserId }`
  - record key sealed to the agent: AAD `personal-agent-record:<ownerUserId>:<agentId>:<recordId>`
  - deposit key sealed to the owner: AAD `agent-deposit-owner:<ownerUserId>:<id>`
  - deposit signature `d1.`: `agent-deposit:<ownerUserId>:<ownerPublicKey>:<agentId>:<id>:<revision>:<sha256(encBody)>`
  - update signature `u1.`: `agent-update:<ownerUserId>:<agentId>:<id>:<revision>:<sha256(encBody)>`
  - reveal request signature `q1.`: `agent-reveal-request:<requestId>:<ownerUserId>:<agentId>:<recordId>:<sorted fields joined by ",">:<requestPublicKey>:<expiresAt ISO>`
  - reveal stub sealed to the agent: AAD `personal-agent-stub:<ownerUserId>:<agentId>:<recordId>`
  - reveal reply sealed to the request key: AAD `agent-reveal:<requestId>:<recordId>:<agentId>`
  - `sha256(encBody)` is base64url of SHA-256 over the UTF-8 of the `encBody` string.
- Limits: 200 granted items per agent; 100 unkept deposits per owner; unkept deposits deleted after 90 days (inbox warns from day 60); last 5 overwrites per record, kept 30 days; reveal request lifetime 5 minutes; one open reveal request per agent; three denials in ten minutes pause that agent's reveals for one hour; at most one reveal email per owner per 10 minutes; hard ceiling 20 personal agents per person.
- Gateway env added (defaults): `GATEWAY_REVEAL` `off` (`off|approval|standing`), `GATEWAY_WRITE_PER_HOUR` 20, `GATEWAY_REVEAL_PER_HOUR` 10. API env added: `PERSONAL_AGENTS` `on` (`on|off`).
- Error bodies stay `{ error: "<snake>", ...extra }`. New codes:
  - `403 { error: "personal_agents_disabled", orgId? }`, `403 owner_inactive`, `403 reveal_disabled`, `403 totp_step_up_required` (a session confined to one organisation, `privateLock.ts`)
  - `402 { error: "agent_limit", used, allowed }` (shipped shape), `409 agent_item_limit`, `409 team_record`, `409 already_shared`
  - Every business refusal on `/agent/deposits`, `/agent/records/:id` and `/agent/reveals*` is **`409 { error: <reason> }`**, never 401/403: the gateway treats 401/403 as "agent ended" and drops its caches. Reasons: `not_writable`, `conflict`, `inbox_full`, `reveal_off`, `busy`, `denied`, `expired`.
- Tool refusal reasons added: `owner_key_changed`, `not_kept`, `invalid`, `not_writable`, `conflict`, `inbox_full`, `reveal_off`, `field`, `denied`, `expired`.
- Events. Owner-visible rows have `orgId` null: `agent.use|refused|reflected` (shipped), `agent.item_grant`, `agent.item_revoke`, `agent.item_write`, `agent.item_reveal_on`, `agent.item_reveal_off`, `agent.deposit`, `agent.deposit_keep`, `agent.deposit_delete`, `agent.update`, `agent.reveal_request`, `agent.reveal`, `agent.reveal_denied`, `agent.reveal_expired`. Admin-visible rows, one per organisation the owner is an active member of: `personal_agent.create|verify|revoke|connect|suspended` with exactly `{ orgId, actorId: <the member>, action, meta: { agentId } }` — no `targetUserId`, record, title, host, count, mode, ip or user agent.
- No value is ever logged, put in an error message, or sent to the API in clear. Values the gateway handles in write, capture and reveal paths are in `HeldSecrets` for as long as they are in memory. `totpSecret` is not revealable in any mode; `totp` returns the current 6-digit code.
- UI copy, exact:
  - On *Can reveal*: *"Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards."*
  - On a reveal request's reason: *"Written by the agent. It may not be true."*
  - On a deposit that fails verification: *"Not signed by the gateway — delete it"*
  - The shipped restricted-credential warning (`AgentWarning`) above every grant, every time.
  - Personal-agent server instructions (from Phase C): *"`http_request` uses a credential without showing it; prefer it. `get_secret` shows you a value only where the owner allowed it, and they may be asked to approve."*
- Public repository: no billing provider code, no deploy secrets, no hosted-service host names or settings beyond what `docs/agents.md` already contains.
- Migrations, one per phase: `20261115000000_personal_agents`, `20261116000000_agent_writes`, `20261117000000_agent_reveal`. Phase D has none.
- Commit after each task; messages start `Personal agents:`.

## Review Focus

1. **Nobody has an unlocked client while a reveal is pending** (laptop closed, vault auto-locked mid-request). Expected: the request expires at 5 minutes, `get_secret` returns `{ error: "refused", reason: "expired" }`, the sealed reply (if one arrived late) is never delivered, and the session is not left `busy`. *Tests in Tasks 17 and 18.*
2. **A granted personal item is moved into a team folder, trashed or purged.** Expected: the agent's `RecordAccess` row, its `agentWrite` flag and its `AgentRevealGrant` go in the same transaction as the move (trash: the item just stops being listed), and the agent's next call gets `not_found`. *Tests in Tasks 4 and 16.*
3. **A captured credential cannot be saved** (inbox full, write limit reached, API down) after the upstream already created it. Expected: inbox space and the write limit are checked **before** the outbound call (`inbox_full` or 429, nothing sent). If the save still fails afterwards, the response is scrubbed of the value all the same and carries `capture: { refused: <reason> }`, so the model can tell the person to delete the orphaned credential. *Tests in Task 13.*
4. **The agent rewrites a deposit while its owner is reading it**, or updates a record the owner is editing. Expected: `keep` with a stale `revision` answers `409 conflict` and the inbox reloads; an agent update with a stale revision answers `conflict` and writes no overwrite row; a person's later save hides *Changed by agent*. *Tests in Tasks 10, 11 and 14.*
5. **The shipped share routes are used on a grant row** (`PATCH`/`DELETE /records/:id/shares/<agentId>` from the Personal space, where `orgId` is null and so matches). Expected: `PATCH` to anything above `use` answers `400 agent_use_only`; the row never appears in `sharedWith`; `agentWrite` cannot be set through it. *Tests in Task 4.*

---

## Phase A — personal agents with Use

### Task 1: Crypto — personal attestation, `k2.` AAD, per-item seal

**Files:**
- Modify: `packages/crypto/src/agents.ts`
- Test: `packages/crypto/test/agents.test.ts`

**Interfaces:**
- Produces:
  ```ts
  export interface PersonalIds { ownerUserId: string; ownerPublicKey: string; agentId: string; publicKey: string }
  export const personalAgentKeyMessage: (i: PersonalIds) => string;         // "personal-agent-key:<owner>:<ownerPub>:<agent>:<pub>"
  export const personalAgentPrivateKeyAad: (i: PersonalIds) => string;      // "agent-private-key:personal:<owner>:<ownerPub>:<agent>:<pub>"
  export const personalAgentRecordAad: (ownerUserId: string, agentId: string, recordId: string) => string;
  export type GatewaySigTag = "g1" | "d1" | "u1" | "q1";
  /** "<tag>.<keyId>.<sig>": Ed25519 over the UTF-8 of `message`. */
  export function signGatewayMessage(identityPrivatePkcs8: Uint8Array, keyId: string, tag: GatewaySigTag, message: string): Promise<string>;
  /** False on a wrong tag, key id, signature or any malformed input; never throws. */
  export function verifyGatewayMessage(sig: string, tag: GatewaySigTag, message: string, identity: { keyId: string; publicKey: string }): Promise<boolean>;
  export const signPersonalAgentKey: (pkcs8: Uint8Array, keyId: string, i: PersonalIds) => Promise<string>;                 // g1
  export const verifyPersonalAgentAttestation: (att: string, i: PersonalIds, identity: { keyId: string; publicKey: string }) => Promise<boolean>;
  export function sealPersonalAgentRecordKey(recordKey: Uint8Array, ids: { ownerUserId: string; agentId: string; recordId: string }, agentPublicKey: Uint8Array): Promise<string>; // s1.
  export function openPersonalAgentRecordKey(sealed: string, ids: { ownerUserId: string; agentId: string; recordId: string }, keys: SealKeys): Promise<Uint8Array>;
  ```
- `signAgentKey` and `verifyAgentAttestation` keep their signatures and are rewritten on `signGatewayMessage` / `verifyGatewayMessage`.

- [ ] **Step 1: Write the failing tests** in `agents.test.ts`:
  ```ts
  const i = { ownerUserId: "u", ownerPublicKey: "opk", agentId: "a", publicKey: "pub" };
  expect(personalAgentKeyMessage(i)).toBe("personal-agent-key:u:opk:a:pub");
  expect(personalAgentPrivateKeyAad(i)).toBe("agent-private-key:personal:u:opk:a:pub");
  expect(personalAgentRecordAad("u", "a", "r")).toBe("personal-agent-record:u:a:r");
  const att = await signPersonalAgentKey(id.privateKey, keyId, i);
  expect(att.startsWith(`g1.${keyId}.`)).toBe(true);
  expect(await verifyPersonalAgentAttestation(att, i, identity)).toBe(true);
  expect(await verifyPersonalAgentAttestation(att, { ...i, ownerPublicKey: "other" }, identity)).toBe(false); // spec §8: another owner key
  expect(await verifyAgentAttestation(att, { orgId: "u", agentId: "a", publicKey: "pub" }, identity)).toBe(false); // not an org attestation
  expect(await verifyGatewayMessage(att, "d1", personalAgentKeyMessage(i), identity)).toBe(false); // the tag is checked
  const kp = await generateKeyPair(); const rk = randomBytes(32);
  const s = await sealPersonalAgentRecordKey(rk, { ownerUserId: "u", agentId: "a", recordId: "r" }, kp.publicKey);
  expect(await openPersonalAgentRecordKey(s, { ownerUserId: "u", agentId: "a", recordId: "r" }, kp)).toEqual(rk);
  await expect(openPersonalAgentRecordKey(s, { ownerUserId: "u", agentId: "a", recordId: "r2" }, kp)).rejects.toThrow();
  ```
  The existing org attestation tests stay and pass.
- [ ] **Step 2: Run** `npx vitest run test/agents.test.ts` in `packages/crypto`. Expected: FAIL, `personalAgentKeyMessage` is not exported.
- [ ] **Step 3: Implement.** The seal pair is `sealTo` / `openSealed` (`seal.ts`) with the AAD above.
- [ ] **Step 4: Run** `npx vitest run` and `npx tsc --noEmit -p tsconfig.json` in `packages/crypto`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: owner-bound attestation, k2 AAD and per-item seal (crypto)"`

### Task 2: API — schema, `PERSONAL_AGENTS`, allowance, organisation policy

**Files:**
- Modify: `apps/api/prisma/schema.prisma` (`Agent`, `User`); Create: `apps/api/prisma/migrations/20261115000000_personal_agents/migration.sql`
- Modify: `apps/api/src/config.ts` (`AgentConfig.personalAgents: boolean`, env `PERSONAL_AGENTS`), `apps/api/.env.example`
- Modify: `apps/api/src/lib/plans.ts`, `apps/api/src/lib/policies.ts`, `apps/api/src/routes/policies.ts`
- Create: `apps/api/src/lib/personalAgents.ts`
- Modify: every reader of `Agent.orgId` that assumed non-null: `routes/agents.ts` (already filters by `orgId`, no change in behaviour), `routes/oauth.ts` (`revokeGrant`, the three `signAgentAccess` callers), `plugins/agent.ts`. In this task they only compile (`orgId ?? undefined` for events); behaviour comes in Tasks 4–5.
- Test: `apps/api/test/personal-agents-unit.test.ts`, `apps/api/test/policies.test.ts`, `apps/api/test/plans-unit.test.ts`

**Interfaces:**
- Schema: `Agent.orgId String? @db.Uuid`, `org Organization?`, `ownerUserId String? @db.Uuid`, `owner User? @relation("personalAgents", fields: [ownerUserId], references: [id], onDelete: Cascade)`, `@@index([ownerUserId])`; `User.personalAgents Agent[] @relation("personalAgents")`, and the existing `User.agent` relation gets an explicit name. The migration adds `CHECK (("orgId" IS NULL) <> ("ownerUserId" IS NULL))`.
- `Entitlements.personalAgentLimit: number | null`: unlimited `null`, Team `2` (also during the Business trial, like `agentLimit`), Business `5`, `getPersonalEntitlements` `1`.
- `policySchema` gains (R2):
  ```ts
  personalAgents: z.object({
    allowed: z.boolean().default(true),
    maxPerMember: z.number().int().min(1).max(20).nullable().default(null),
    write: z.boolean().default(true),
    reveal: z.enum(["off", "approval", "standing"]).default("approval"),
  }).prefault({})
  ```
  `clientPolicies` includes it. `readPolicies(stored, ent)` without `policyEdit` returns `{ ...DEFAULT_POLICIES, personalAgents: <the stored block, parsed, or its default> }` (R1).
- `PUT /admin/settings/policies/personal-agents` (owner or admin, **no** `requireEntitlement`): body is the block; replaces only that key of the stored JSON; event `org.policies_update` with `meta.changed: ["personalAgents"]`; answers the same view as `GET`. The full `PUT /` accepts the block too.
- In `lib/personalAgents.ts`:
  ```ts
  export const PERSONAL_AGENT_CEILING = 20;
  export type RevealMode = "off" | "approval" | "standing";
  export interface PersonalAgentRules { allowed: boolean; blockedByOrgId: string | null; max: number; write: boolean; reveal: RevealMode }
  /** Pure. allowed = AND, max = min(ceiling, allowance ?? ceiling, every non-null maxPerMember), write = AND, reveal = lowest of off < approval < standing. No policies: allowed, write true, reveal "standing". */
  export function strictest(allowance: number | null, policies: { orgId: string; p: Policies["personalAgents"] }[]): PersonalAgentRules;
  /** Active memberships only. Hosted allowance: the highest personalAgentLimit among them, or the Personal plan's with none; billing off: null. cfg.agents.personalAgents false → allowed false, blockedByOrgId null. */
  export async function personalAgentRules(db: Db, cfg: Config, userId: string): Promise<PersonalAgentRules>;
  /** lockUser, count live (revokedAt null) agents with this owner, throw AgentLimitError(used, rules.max). */
  export async function assertPersonalAgentSlot(tx: Db, cfg: Config, ownerUserId: string): Promise<void>;
  /** One Event per organisation the owner is an active member of: { orgId, actorId: ownerUserId, action: `personal_agent.${what}`, meta: { agentId } } and nothing else. */
  export async function logLifecycle(tx: Db, ownerUserId: string, what: "create" | "verify" | "revoke" | "connect" | "suspended", agentId: string): Promise<void>;
  ```
- When a policy write turns `personalAgents.allowed` from true to false: `logLifecycle(..., "suspended", agentId)` for every live personal agent whose owner is an active member of that organisation, then `app.gateway.dropAgent(agentId)` for each, best effort.

- [ ] **Step 1: Write the failing tests.**
  - `strictest(5, [])` → `{ allowed: true, blockedByOrgId: null, max: 5, write: true, reveal: "standing" }`; `strictest(null, [])` → `max: 20`.
  - `strictest(5, [{ orgId: "a", p: { allowed: true, maxPerMember: null, write: true, reveal: "approval" } }, { orgId: "b", p: { allowed: false, maxPerMember: 1, write: false, reveal: "standing" } }])` → `{ allowed: false, blockedByOrgId: "b", max: 1, write: false, reveal: "approval" }`.
  - `plans-unit`: `personalAgentLimit` is 1 / 2 / 5 / null for personal / Team / Business / billing off, and 2 during the Business trial.
  - `personalAgentRules`, hosted: a user in a Team and a Business organisation → `max: 5`; with the Business one's `maxPerMember: 3` → 3; a user in none → 1. With `PERSONAL_AGENTS=off` → `allowed: false`.
  - `policies.test.ts`: on hosted Team, `PUT /admin/settings/policies/personal-agents { allowed: false, ... }` → 200 and `GET` shows it, while `PUT /admin/settings/policies` still answers `402 plan_required`. A member (not admin) → 403. `{}` stored policies read back the defaults above. The block survives a full `PUT /` on Business and a risk-ignore write.
  - Migration: inserting an `Agent` with both or neither of `orgId` / `ownerUserId` fails; existing rows are untouched (`org-migration.test.ts` style, in `personal-agents-unit.test.ts`).
- [ ] **Step 2: Run** `npx vitest run test/personal-agents-unit.test.ts test/policies.test.ts test/plans-unit.test.ts` in `apps/api`. Expected: FAIL.
- [ ] **Step 3: Implement.** `npx prisma migrate dev --name personal_agents --create-only`, rename the folder to the fixed name, add the CHECK by hand.
- [ ] **Step 4: Run** the three files, then `npx vitest run test/agents-admin.test.ts test/agents-api.test.ts test/agents-revoke.test.ts test/oauth.test.ts` and `npm run typecheck -w @clane-vault/api`. Expected: PASS, nothing shipped changes.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: schema, PERSONAL_AGENTS, per-person allowance and the organisation policy"`

### Task 3: API — `/me/agents`: enrol, list, verify, rename, tokens

**Files:**
- Modify: `apps/api/src/lib/gateway.ts` (`createPersonalAgentKey`; `keyBody` accepts `k2.` for it), `apps/api/src/lib/agents.ts` (move `attestationOk` here from `routes/agents.ts`, generalised)
- Create: `apps/api/src/routes/myAgents.ts`; register in `apps/api/src/app.ts` inside the `if (opts.config.agents)` block when `agents.personalAgents`
- Modify: `apps/api/src/routes/agents.ts` (`GET /admin/agents/personal-count`)
- Modify: `apps/api/test/fakeGateway.ts`, `apps/api/test/agentHelpers.ts`
- Test: `apps/api/test/personal-agents.test.ts`

**Interfaces:**
- Consumes: Task 2 (`personalAgentRules`, `assertPersonalAgentSlot`, `logLifecycle`).
- Produces, `lib/gateway.ts`: `GatewayClient.createPersonalAgentKey(ids: { agentId: string; ownerUserId: string; ownerPublicKey: string }): Promise<AgentKeyResult>` → `POST /internal/agents` with that body; the answer's `wrappedPrivateKey` must match `/^k2\.[^.]+\.[^.]+\.v1\./`.
- Produces, `lib/agents.ts`: `export function gatewaySigned(sig: string, tag: "g1" | "d1" | "u1" | "q1", message: string, identity: GatewayIdentityInfo): boolean` (node `verify`, as `attestationOk` today). Later tasks use it for defence-in-depth checks.
- Produces, `routes/myAgents.ts`. Plugin hooks: `requireAuth`; then `isPrivateLocked(req)` → `403 totp_step_up_required`. No organisation context is read.
  - `POST /me/agents { name: displayName, expiresAt? }`: rules not `allowed` → `403 { error: "personal_agents_disabled", orgId: blockedByOrgId ?? undefined }`; slot check; `ensureIdentity`; `createPersonalAgentKey` with the caller's `User.publicKey`; `gatewaySigned` over the personal message or `GatewayUnavailable`; one transaction creating `User` + `Agent` (`ownerUserId`, `createdById` = caller), re-checking the slot, `logLifecycle("create")`. → `201 { id, name, publicKey, fingerprint, attestation, owner: { userId, publicKey }, gateway: { keyId, publicKey, fingerprint } }`.
  - `GET /me/agents` → `{ agents: MyAgent[], allowance: { used, allowed }, rules: { allowed, blockedByOrgId, write, reveal }, gateway: { url, identityKeyId, identityPublicKey } | null, revealEmail: true }`. `MyAgent` is the shipped agent view without `folders`/`groups`, plus `items: number` (its `RecordAccess` rows) and `owner: { userId, publicKey }` (the owner's current key). `status` adds `"suspended"` (live and verified, rules not `allowed`).
  - `GET /me/agents/gateway` → `{ url, identityKeyId, identityPublicKey }` (as `/org/agents/gateway`, without an organisation).
  - `POST /me/agents/:id/verify { publicKey }`: `409 stale_key` unless it equals `Agent.publicKey`; sets `verifiedById`/`verifiedAt`; `logLifecycle("verify")`.
  - `PATCH /me/agents/:id { name?, expiresAt? }`; `POST /me/agents/:id/tokens { label, expiresAt? }` → `201 { id, token }` + `logLifecycle("connect")`; `DELETE /me/agents/:id/tokens/:tokenId`; `DELETE /me/agents/:id/grants/:grantId` (`revokeGrant`). All as their `/admin/agents` twins, scoped by `ownerUserId = caller`; another person's agent is 404. Events for these have `orgId` undefined.
  - `GET /admin/agents/personal-count` (org admin) → `{ agents: number, members: number, perMember: { userId: string; count: number }[] }`: live personal agents whose owner is an active member of the organisation. No agent id, name or item count.
- `startFakeGateway` signs the personal message and answers a `k2.` envelope when the body has `ownerUserId`. `createTestPersonalAgent(t, { ownerUserId, verified?, expiresAt? })` inserts the two rows with a real X25519 pair and returns `{ id, publicKey, privateKey }`.

- [ ] **Step 1: Write the failing tests** (`personal-agents.test.ts`):
  - A plain member creates an agent: 201; the DB has the `User` (kind agent) and `Agent` (`orgId` null, `ownerUserId` = member); **no `Membership` and no `MembershipKey` row** for it; `fake.created` got `ownerUserId` and the member's public key.
  - Spec §8: the agent is absent from `GET /users`, `GET /admin/people` and `GET /group-access/pending`; `POST /folders/:id/members` with its id → `400 user_not_active`; `POST /records/:id/shares` with its id → `400 user_not_active`.
  - `GET /me/agents` of another user does not list it; `PATCH`/`DELETE` by another user → 404.
  - Hosted Team: a third agent → `402 { error: "agent_limit", used: 2, allowed: 2 }`; the organisation's `agentLimit` count (`liveAgents`) is still 0.
  - Policy `allowed: false` in one of the member's two organisations → `403 { error: "personal_agents_disabled", orgId }` naming it.
  - A session with `totpSkippedForOrg` → `403 totp_step_up_required` on every `/me/agents` route.
  - The fake signing the wrong agent id → 503 `gateway_unavailable` and no rows.
  - Each organisation the member belongs to gets one `personal_agent.create` event whose keys are exactly `orgId`, `actorId`, `action`, `meta.agentId` (`targetUserId`, `recordId`, `ip` null). Token creation adds `personal_agent.connect`.
  - `personal-count` for an organisation with two members holding 1 and 2 agents → `{ agents: 3, members: 2, perMember: [...] }`; a non-admin → 403.
  - With `PERSONAL_AGENTS=off`: `/me/agents` → 404 while `/admin/agents` still works.
- [ ] **Step 2: Run** `npx vitest run test/personal-agents.test.ts`. Expected: FAIL (404).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file and `npx vitest run test/agents-admin.test.ts test/agents-members.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: /me/agents enrolment bound to the owner's key, tokens, lifecycle events for admins"`

### Task 4: API — owner tokens, `requireAgent`, per-item grants, the personal sync

**Files:**
- Modify: `apps/api/src/lib/tokens.ts`, `apps/api/src/plugins/agent.ts`, `apps/api/src/routes/oauth.ts` (the three `signAgentAccess` callers pass `ownerUserId`)
- Create: `apps/api/src/routes/agentGrants.ts`; register beside `myAgentRoutes`
- Modify: `apps/api/src/routes/agentApi.ts` (`/agent/sync`, `/agent/events`), `apps/api/src/lib/sync.ts` (`agentGrants`, `sharedWith`)
- Modify: `apps/api/src/lib/personalAgents.ts` (`personalAgentSync`)
- Test: `apps/api/test/personal-agents-access.test.ts`

**Interfaces:**
- Consumes: Tasks 2–3.
- Produces, `lib/tokens.ts` (R4):
  ```ts
  export async function signAgentAccess(cfg: Config, p: { agentId: string; orgId: string | null; ownerUserId?: string | null; grant: string }): Promise<{ token: string; expiresIn: 900 }>;
  export async function verifyAgentAccess(cfg: Config, token: string): Promise<{ sub: string; org: string | null; owner: string | null; grant: string; jti: string }>; // exactly one of org, owner
  ```
- Produces, `plugins/agent.ts`: `req.agent: { userId: string; orgId: string | null; ownerUserId: string | null; grantId: string; via: "token" | "grant" }`. Steps 1–5 as shipped, with the `Agent` looked up by `orgId` **or** `ownerUserId` matching the token. For an organisation agent step 6 is unchanged. For a personal agent, in this order: `verifiedAt` null → `403 agent_unverified`; owner `User.status` not `active` → `403 owner_inactive`; `personalAgentRules(owner)` not `allowed` → `403 { error: "personal_agents_disabled", orgId? }`. `agent.expired` is logged with `orgId` undefined.
- Produces, `routes/agentGrants.ts` (`requireAuth`, then `isPrivateLocked` → `403 totp_step_up_required`):
  - `POST /records/:id/agent-grants { agentId: uuid, wrappedRecordKey: <s1. sealed box> }` → `201 { ok: true }`. Checks, in order: the caller holds the record's `owner` `RecordAccess` row and is `Record.ownerId`, else 404; `recordOrgOf(record) !== null` → `409 team_record`; trashed → `409 in_trash`; the agent has `ownerUserId` = caller, `verifiedAt`, `revokedAt` null and is unexpired, else `400 user_not_active`; the agent already holds 200 rows → `409 agent_item_limit`; a row exists → `409 already_shared`. Stores `RecordAccess { holderType: "user", holderId: agentId, permission: "use", orgId: null, sealedTo: <Agent.publicKey>, wrappedRecordKey }`. Event `agent.item_grant` (`actorId` caller, `recordId`, `targetUserId` agent).
  - `DELETE /records/:id/agent-grants/:agentId` → 204, event `agent.item_revoke`; 404 when there is no such row of the caller's.
- Produces, `personalAgentSync(db, cfg, agentUserId)`, the body of `GET /agent/sync` when `req.agent.ownerUserId` is set:
  ```ts
  { owner: { userId: string; publicKey: string },          // the owner's CURRENT User.publicKey
    agentId: string, publicKey: string, wrappedPrivateKey: string | null, kekId: string, expiresAt: string | null,
    records: { id: string; encBody: string; revision: number; wrappedRecordKey: string; write: boolean; deletedAt: string | null }[],
    reveal: [], deposits: [],                               // filled in Tasks 16 and 10
    policy: { write: boolean; reveal: RevealMode } }        // from personalAgentRules
  ```
  Only records with the agent's own row whose `recordOrgOf` is null and whose `ownerId` is the owner. No folders, no members. `agent.sync` is logged hourly with `orgId` undefined.
- `/agent/events` for a personal agent stores rows with `orgId` null; `accessFor(prisma, agentId, recordId, null)` decides whether `recordId` is kept. Its `reason` values may now include `owner_key_changed`.
- `/sync` (Personal space): an owned record gains `agentGrants: { agentId: string; use: true; write: boolean }[]`; `sharedWith` excludes rows whose holder is an agent with `ownerUserId` set (R9).
- `PUT /records/:id/folder` into a team folder already deletes non-owner user rows with `orgId` null (`foreign`): the grant goes with it. No code change; a test pins it.

- [ ] **Step 1: Write the failing tests:**
  - Token: a personal agent's exchanged access token decodes to `owner === ownerId` and no `org` claim; an organisation agent's is unchanged. A hand-signed token with both claims, or neither → 401.
  - Grants (spec §8): 201 for the owner's private record with a real `sealPersonalAgentRecordKey` box. Refused: a record in a team folder (`409 team_record`), a record shared *to* the caller (404), another user's agent (`400 user_not_active`), an unverified agent (`400`), a trashed record (`409 in_trash`), a second grant (`409 already_shared`), the 201st item (`409 agent_item_limit`, rows inserted directly).
  - Sync: `GET /agent/sync` lists exactly the granted record with the stored `wrappedRecordKey`, `owner.publicKey` equal to the owner's `User.publicKey`, a `k2.` `wrappedPrivateKey`, no `folders` key. Updating `User.publicKey` in the DB changes `owner.publicKey` in the next sync (the gateway refuses on it in Task 6).
  - `requireAgent`: owner disabled → `403 owner_inactive`, re-enabled → 200. Two organisations, one sets `allowed: false` → `403 personal_agents_disabled` with that `orgId`; removing the membership (`offboard(..., "remove")`) → 200 again; the agent's rows were never deleted (spec §8).
  - The agent's token on `GET /sync`, `GET /me/agents`, `GET /users` → 401.
  - `/agent/events` stores `orgId` null; no organisation's `GET /admin/events` returns the row.
  - Person sync: the record carries `agentGrants: [{ agentId, use: true, write: false }]` and its `sharedWith` is empty.
  - Review Focus 2: `PUT /records/:id/folder` into a team folder → the grant row is gone and the agent's sync no longer lists the record. Trash → listed with `deletedAt`. Purge → gone.
  - Review Focus 5: `PATCH /records/:id/shares/<agentId> { permission: "edit" }` without `X-Org-Id` → `400 agent_use_only`.
- [ ] **Step 2: Run** `npx vitest run test/personal-agents-access.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file and `npx vitest run test/agents-api.test.ts test/sharing.test.ts test/records.test.ts test/oauth.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: owner-scoped tokens, per-item grants and the personal agent sync"`

### Task 5: API — revocation, activity, OAuth consent by the owner

**Files:**
- Modify: `apps/api/src/lib/personalAgents.ts`, `apps/api/src/routes/myAgents.ts`, `apps/api/src/routes/oauth.ts`, `apps/api/src/lib/demo.ts`
- Test: `apps/api/test/personal-agents-revoke.test.ts`, `apps/api/test/oauth.test.ts`

**Interfaces:**
- Produces, `lib/personalAgents.ts`:
  ```ts
  export interface PersonalRotation { records: { id: string }[]; revealed: { id: string; fields: string[] }[] }   // `revealed` stays [] until Task 17
  /** In the caller's transaction: lockUser(agent); claim revokedAt (null when already revoked); delete its RecordAccess rows; revoke tokens and grants; wrappedPrivateKey null; User disabled; logLifecycle("revoke"). */
  export async function revokePersonalAgent(tx: Db, agentUserId: string, byUserId: string): Promise<PersonalRotation | null>;
  /** Every live personal agent of the owner, then deletes those agents' User rows (R3). */
  export async function revokePersonalAgentsOf(tx: Db, ownerUserId: string): Promise<string[]>;
  ```
- `DELETE /me/agents/:id` → `{ rotate: PersonalRotation }`, `409 agent_revoked` on a second call; then `gateway.dropAgent`, best effort.
- `GET /me/agents/:id/activity?before=<event id>&limit=<1–100, default 50>` → `{ events: { id: string; at: string; action: string; recordId: string | null; meta: unknown }[], nextBefore: string | null }`: rows with `orgId` null and (`actorId` = the agent or `targetUserId` = the agent), newest first.
- `deleteSandbox` calls `revokePersonalAgentsOf` for each user id before deleting records.
- OAuth:
  - `GET /oauth/authorize/info`: `agents` also lists the caller's own grantable personal agents as `{ id, name, orgId: null, orgName: null, personal: true }`, unless the session is private-locked or rules are not `allowed`.
  - `POST /oauth/authorize`: `preHandler` becomes `requireAuth` only. The agent is loaded first: with `ownerUserId` it must be the caller's, the session must not be private-locked (`403 totp_step_up_required`) and rules must be `allowed`; otherwise `app.orgAdmin(req, reply)` runs as before. Unknown agent → `400 invalid_request` as today.
  - The code exchange logs `agent.grant` with `orgId` undefined plus `logLifecycle("connect")`, and signs with `ownerUserId`.

- [ ] **Step 1: Write the failing tests:**
  - Revoke with two granted records, a token and a grant: `rotate.records` has both ids; the agent's `RecordAccess` rows are gone; token and grant have `revokedAt`; `wrappedPrivateKey` null; `User.status` `disabled`; `fake.dropped` has the id; the old access token → 401; a `personal_agent.revoke` row per organisation. Gateway down → still 200.
  - After a revoke at the allowance, the next create succeeds.
  - Activity lists `agent.item_grant` and a posted `agent.use`, and nothing of another user's agent (404).
  - `deleteSandbox` for a demo user with a personal agent leaves no `Agent` and no agent `User` row.
  - OAuth: a member who is not an admin and owns a verified personal agent gets it in `info` and can authorise it without `X-Org-Id`; the code exchanges into a token with the `owner` claim. Authorising someone else's personal agent → `400 invalid_request`. A member without one still gets `agents: []`. The organisation-agent consent tests are unchanged.
- [ ] **Step 2: Run** `npx vitest run test/personal-agents-revoke.test.ts test/oauth.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** both files and `npx vitest run test/demo.test.ts test/agents-revoke.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: revocation with the items to rotate, owner activity, OAuth consent by the owner"`

### Task 6: Gateway — owner-bound enrolment, `k2.` envelope, personal items

**Files:**
- Modify: `apps/gateway/src/envelope.ts`, `apps/gateway/src/identity.ts`, `apps/gateway/src/app.ts` (`/internal/agents`), `apps/gateway/src/apiClient.ts`, `apps/gateway/src/auth.ts`, `apps/gateway/src/keys.ts`, `apps/gateway/src/items.ts`, `apps/gateway/src/mcp.ts`
- Modify: `apps/gateway/test/fakeApi.ts`
- Test: `apps/gateway/test/envelope.test.ts`, `internal.test.ts`, `identity.test.ts`, `keys.test.ts`, `items.test.ts`, `mcp.test.ts`

**Interfaces:**
- Consumes: Task 1; the sync body of Task 4.
- Produces, `envelope.ts`:
  ```ts
  export async function sealWithKek(kek: Kek, ctx: KekContext, aad: string, plaintext: Uint8Array, tag?: "k1" | "k2"): Promise<string>;   // default "k1"
  export async function openWithKek(kek: Kek, ctx: KekContext, aad: string, envelope: string, tag?: "k1" | "k2"): Promise<Uint8Array>;      // another tag → EnvelopeError("bad_envelope")
  export const wrapPersonalAgentKey: (kek: Kek, ids: PersonalIds, privateKey: Uint8Array) => Promise<string>;   // k2, ctx { agentId, ownerUserId }
  export const unwrapPersonalAgentKey: (kek: Kek, ids: PersonalIds, envelope: string) => Promise<Uint8Array>;
  ```
- Produces, `identity.ts`: `Identity` gains `signPersonal(ids: PersonalIds): Promise<string>` and `signMessage(tag: GatewaySigTag, message: string): Promise<string>` (Tasks 12 and 18 sign deposits, updates and reveal requests with it; the spec's `signDeposit`, `signUpdate` and `signRevealRequest` are this one method plus the message constructors in `@clane-vault/crypto`).
- `POST /internal/agents` accepts exactly one of `{ agentId, orgId }` (unchanged answer) and `{ agentId, ownerUserId, ownerPublicKey }` (strict; `ownerPublicKey` a 32-byte base64url key) → `{ publicKey, wrappedPrivateKey: "k2.…", kekId, attestation }`.
- `apiClient.ts`: `OrgAgentSync` (today's `AgentSync`), `PersonalAgentSync` (Task 4's body), `type AgentSync = OrgAgentSync | PersonalAgentSync`, `export const isPersonal = (s: AgentSync): s is PersonalAgentSync => "owner" in s`.
- `auth.ts`: `AgentPrincipal { agentId: string; orgId: string | null; ownerUserId: string | null; accessToken: string; exp: number }`; a token with both or neither of `org` / `owner` is null.
- `keys.ts`: `export class OwnerKeyChanged extends Error`. `AgentKeyCache.open` for a personal sync unwraps with `{ ownerUserId: sync.owner.userId, ownerPublicKey: sync.owner.publicKey, agentId, publicKey: sync.publicKey }`; a `CryptoError` there becomes `OwnerKeyChanged`. A cache hit also requires the entry's owner public key to equal `sync.owner.publicKey`; otherwise the entry is dropped and re-opened (and so refused). The cached value stays `MembershipKeys`, with `orgId: ""` for a personal agent; it is never used as an AAD there.
- `items.ts`: for a personal sync the record key opens with `openPersonalAgentRecordKey(r.wrappedRecordKey, { ownerUserId: sync.owner.userId, agentId: sync.agentId, recordId: r.id }, keys)` and the handle prefix is `personal`. `ItemSummary` is unchanged in this task.
- `mcp.ts`: `OwnerKeyChanged` → `list_secrets` and `http_request` answer `{ error: "refused", reason: "owner_key_changed" }` (one `refused` event with that reason for `http_request`), with no outbound call. Tools and instructions are unchanged.
- `startFakeApi` gains `personal`: a second principal `{ agentId, ownerId, ownerKeys, token(), addRecord(body), setOwnerPublicKey(b64) }` whose sync is a `PersonalAgentSync` with real seals.

- [ ] **Step 1: Write the failing tests:**
  - `envelope`: `wrapPersonalAgentKey` → starts `k2.`; `unwrapPersonalAgentKey` with the same ids round-trips; with another `ownerPublicKey` → rejects; `openWithKek` of a `k2.` envelope without the tag argument → `bad_envelope`; the recording KEK saw context `{ agentId, ownerUserId }` and no `orgId`.
  - `internal`: the personal body → 200, `verifyPersonalAgentAttestation(attestation, ids, identity)` true and `verifyAgentAttestation` false; a body with both `orgId` and `ownerUserId` → 400; the organisation body still answers a `k1.` envelope.
  - `keys`: after a hit, a sync with a different `owner.publicKey` throws `OwnerKeyChanged` and `has(agentId)` is false.
  - `items`: two personal records titled "GitHub" → handles `personal/github`, `personal/github-2`; a record sealed for another agent id is skipped and logged `item_skipped`.
  - `mcp`: with the personal principal, `list_secrets` lists `personal/echo` and `http_request` reaches the echo upstream with the injected header and returns the scrubbed body. After `setOwnerPublicKey(<another key>)` and a cache drop, both tools → `owner_key_changed`, the upstream saw no request, and the API got one `refused` event (spec §8). `tools/list` in an organisation session and in a personal session each name exactly `http_request`, `list_secrets`.
  - `auth`: a JWT with `owner` and no `org` verifies; with both → null.
- [ ] **Step 2: Run** `npx vitest run` in `apps/gateway`. Expected: the new cases FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and `npm run typecheck -w @clane-vault/gateway`. Expected: PASS, `noPlaintext.test.ts` included.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: gateway enrolment bound to the owner's key (k2), personal handles, owner_key_changed"`

### Task 7: Web — the `personal` pin slot, verify dialog, Settings → My agents

**Files:**
- Modify: `apps/web/src/lib/orgKeys.ts`, `apps/web/src/lib/paths.ts` (`SETTINGS_SECTIONS` gains `"agents"`), `apps/web/src/features/settings/SettingsPage.tsx`
- Modify: `apps/web/src/features/admin/AgentVerifyDialog.tsx`, `apps/web/src/features/admin/AgentConnectSheet.tsx`, `apps/web/src/features/admin/agents.ts`
- Create: `apps/web/src/features/settings/myAgents.ts`, `apps/web/src/features/settings/MyAgentsSection.tsx`
- Test: `apps/web/src/lib/orgKeys.personal.test.ts`, `apps/web/src/features/settings/MyAgents.test.tsx`

**Interfaces:**
- Consumes: Task 3's routes; Task 1.
- Produces, `lib/orgKeys.ts`:
  ```ts
  export const PERSONAL_SLOT = "personal";   // pinnedGateway / pinGateway / gatewayPinStatus take it where they take an org id
  /** Every gateway identity this browser pinned for the user, in any organisation or the personal slot. */
  export function allGatewayPins(me: string): GatewayIdentity[];
  /** "changed" when ANY pin differs from `identity` (previous = that pin); else "same" when at least one pin exists; else "new". */
  export function personalGatewayPinStatus(me: string, identity: GatewayIdentity): { status: "new" | "same" | "changed"; previous?: GatewayIdentity };
  /** Throws AgentAttestationError: "unpinned", "gateway_changed", "invalid", or the new reason "owner" when owner.publicKey is not the key derived from myPrivateKey (publicKeyFromPrivateKey). */
  export async function verifyPersonalAgentKey(me: string, agent: { id: string; publicKey: string; attestation: string }, owner: { userId: string; publicKey: string }, myPrivateKey: Uint8Array): Promise<void>;
  ```
  `ensureGatewayPinned` takes an optional path (default `/org/agents/gateway`; the personal slot passes `/me/agents/gateway`) and refuses with `gateway_changed` when `personalGatewayPinStatus` is `changed`. `AgentAttestationError` text for `owner`: *"This agent's key is bound to a different account key than yours, so nothing was shared. Revoke the agent and create it again."*
- `AgentVerifyDialog` gains `personal?: { ownerUserId: string; ownerPublicKey: string }`. With it: the attestation is checked with `verifyPersonalAgentAttestation`, the owner key against the unlocked private key, the pin with `personalGatewayPinStatus`. *Changed* shows both fingerprints and a link to `docs/agents.md` (*The published fingerprint*), and the owner may confirm (`pinGateway(me, PERSONAL_SLOT, identity, { repin: true })`). One line under the gateway fingerprint: *"Compare this with the fingerprint your server's operator published. A wrong gateway could read everything you give this agent."*
- `agents.ts`: `useCreateToken`, `useRevokeToken`, `useRevokeGrant` accept `{ personal?: boolean }` and then call `api` on `/me/agents/...`; `AgentConnectSheet` gains `personal?: boolean` and passes it. `AgentStatus` gains `"suspended"` (label *Suspended by an organisation's policy*).
- `myAgents.ts`: `useMyAgents()`, `useCreateMyAgent()`, `useVerifyMyAgent()` (server verify, then pin the gateway in `PERSONAL_SLOT` and `pinKey(me, PERSONAL_SLOT, agentId, publicKey)`), `useUpdateMyAgent()`, `useRevokeMyAgent()`, `useMyAgentActivity(id)`. `export type MyAgent` mirrors Task 3's view.
- `MyAgentsSection`: the list with status chips, *n of m agents*, **New agent**, verify, **Connect**, **Activity**, **Revoke** (the dialog lists `rotate.records` by title: *"The gateway could open these items. Change the credentials in them."*). `rules.allowed` false → a notice naming the organisation and no **New agent**. A 404 from `/me/agents` hides the section from the settings menu.

- [ ] **Step 1: Write the failing tests:**
  - `orgKeys.personal`: no pins → `new`; an organisation pin equal to the identity → `same`; an organisation pin that differs → `changed` with `previous` (spec §3.2, "Changed, not New"); `pinGateway(me, PERSONAL_SLOT, other)` without `repin` throws `gateway_changed`.
  - `verifyPersonalAgentKey` with a real attestation passes; with `owner.publicKey` of another key pair → `AgentAttestationError("owner")` (spec §8); with an attestation signed for another agent id → `invalid`.
  - `MyAgents` (msw): creating opens the verify dialog with two fingerprints; an attestation for another owner key shows *The gateway did not sign this key* and no confirm button; confirming calls `POST /me/agents/:id/verify` and stores the personal pin; at the allowance the button is disabled with *2 of 2 agents*; `personal_agents_disabled` shows the organisation's name; revoke shows the rotation list.
- [ ] **Step 2: Run** `npx vitest run src/lib/orgKeys.personal.test.ts src/features/settings/MyAgents.test.tsx` in `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and `npm run typecheck -w @clane-vault/web`. Expected: PASS (`AgentsPage.test.tsx` unchanged).
- [ ] **Step 5: Commit** `git commit -m "Personal agents: personal gateway pin, owner-checked verify dialog, Settings → My agents"`

### Task 8: Web — granting items, consent page, policy form, the admin count

**Files:**
- Create: `apps/web/src/features/vault/RecordAgentsSection.tsx`, `apps/web/src/features/vault/GrantToAgentDialog.tsx`
- Modify: `apps/web/src/features/vault/ShareSheet.tsx`, `RecordList.tsx`, `useVault.ts`, `types.ts`, `decrypt.ts` (pass `agentGrants` through, nothing else)
- Modify: `apps/web/src/features/auth/OAuthAuthorize.tsx`, `apps/web/src/features/policies/OrgPoliciesSection.tsx`, `apps/web/src/lib/policies.ts`, `apps/web/src/features/admin/AgentsPage.tsx`
- Test: `apps/web/src/features/vault/RecordAgents.test.tsx`, `apps/web/src/features/vault/decrypt.personal.test.ts`, `apps/web/src/features/policies/Policies.test.tsx`

**Interfaces:**
- Consumes: Tasks 4, 5, 7.
- `types.ts`: `SyncRecord.agentGrants?: { agentId: string; use: boolean; write: boolean; reveal?: string[] }[]`, carried onto `VaultRecord`.
- `useVault.ts`: `grantAgent(record: VaultRecord, agent: MyAgent): Promise<void>` = `verifyPersonalAgentKey` → `sealPersonalAgentRecordKey(record.recordKey, { ownerUserId: me, agentId, recordId }, agentKey)` → `POST /records/:id/agent-grants`; `revokeAgentGrant(recordId, agentId)`. A failed verification seals nothing and shows the `AgentAttestationError` text.
- `RecordAgentsSection` renders in `ShareSheet` only for a record the user owns in the Personal space (`!teamFolder`, not `sharedBy`): one row per verified, live personal agent with a select *None* / *Can use*; `<AgentWarning />` above it every time. Under a record without `body.agentPolicy`: *"This item has no Agent use settings yet, so the agent can't use it."* No agents → a link to `/settings/agents`.
- `RecordList` multi-select gains **Give to agent…** → `GrantToAgentDialog` (pick one agent, the warning, confirm): grants one by one and reports *n given, n skipped* (already given, or not yours).
- `OAuthAuthorize`: personal agents listed under *Your agents*; allowing one posts with `api` (no `X-Org-Id`). The `forbidden` message becomes *"Only owners and admins can connect an organisation's agents."*
- `OrgPoliciesSection`: a **Personal agents** block (*Members may use personal agents*; *At most n per member*, empty = no limit; *Agents may save and update items*; *Reading values: Off / With approval / Without approval*), saved through `PUT /admin/settings/policies/personal-agents`, editable on every plan. Under it: *"This is the one policy that reaches members' Personal space. It can switch personal agents off; it cannot show you what they hold."*
- `AgentsPage`: one line from `/admin/agents/personal-count`: *"Personal agents: 7 across 4 members"*, expandable to a per-member count.

- [ ] **Step 1: Write the failing tests:**
  - `RecordAgents`: the section is absent for a team-folder record and for a record shared with me; choosing *Can use* posts a body whose `wrappedRecordKey` opens with the agent's private key and the AAD `personal-agent-record:<me>:<agent>:<record>`; with a tampered attestation nothing is posted and the error text shows; the warning is in the DOM before the select; *None* calls `DELETE`.
  - `decrypt.personal`: a record I own whose `wrappedRecordKey` starts `s1.` still comes back `error: "cannot_open"` (spec §8, the guard is untouched); `agentGrants` survives `decryptSync`.
  - `Policies`: on a Team plan the Personal agents block is enabled while the other fields show the plan lock; saving calls the new route.
- [ ] **Step 2: Run** the three files in `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and `npm run typecheck -w @clane-vault/web`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: grant items from the Personal space, owner consent, policy form, admin count"`

### Task 9: Phase A acceptance — e2e and docs

**Files:**
- Create: `e2e/agents/personal.spec.ts` (picked up by `e2e/playwright.agents.config.ts`, `testDir: "agents"`; it starts its own echo upstream, on another port than `agents.spec.ts`)
- Modify: `docs/agents.md` (new section *Personal agents*; the KMS policy example), `SECURITY.md`, `docs/policies.md`, `docs/plans.md`, `docs/sharing.md`, `CHANGELOG.md` (a new `## Unreleased` section above 1.8.0), `deploy/client/README.md`, `deploy/client/.env.example`, `apps/api/.env.example`

**Interfaces:**
- Consumes: Tasks 1–8.

- [ ] **Step 1: Write the test** (`test.describe.configure({ mode: "serial" })`), as a member who is **not** an admin:
  1. Settings → My agents → **New agent** "My helper" → the dialog shows two fingerprints → confirm. The row reads *Active*.
  2. In the Personal space create an *API key* item "Echo" (secret `sk_test_PERSONAL_CANARY`, Agent use host `echo.test`, bearer). Share sheet → Agents → "My helper": *Can use*; the restricted-credential warning is visible.
  3. **Connect** → **Create API token**. MCP client: `list_secrets` contains `personal/echo` and not the canary; `http_request` reaches the upstream with `Authorization: Bearer sk_test_PERSONAL_CANARY` and the result has `[clane:redacted]`.
  4. My agents → Activity shows a use of "Echo". As the organisation's admin, Event log shows `personal_agent.create` for the member and **no** row naming "Echo" or `echo.test`; Admin → Agents shows *Personal agents: 1 across 1 members*.
  5. The admin turns *Members may use personal agents* off → the next MCP call is HTTP 401 and the member's row reads *Suspended*; on again → the call works.
  6. Move "Echo" into a team folder → `list_secrets` no longer lists it. **Revoke** → the next MCP call is 401.
- [ ] **Step 2: Run** `npm run test:agents -w e2e`. Expected: both spec files PASS.
- [ ] **Step 3: Write the docs.**
  - `docs/agents.md`, *Personal agents*: who can create one; that it is not a member; Personal items only, one at a time (decision 1); the owner-bound enrolment and what the dialog checks; the `personal` pin and its trust-on-first-use cost, in the spec's §3.2 words; allowances (decision 2) and the policy block; suspension; revocation and what to rotate; what admins see and do not see. The KMS section: the encryption-context keys become `["orgId", "agentId", "ownerUserId", "purpose"]`. Settings and error tables gain `PERSONAL_AGENTS` and the new codes.
  - `SECURITY.md`: the row *Personal items with Can use*, and the list item "non-admin users pin the gateway: trust-on-first-use in practice".
  - `docs/policies.md`: the sentence that private records follow no organisation's policy gets its one exception, `personalAgents`, with the reason from spec §3.4, and that it is editable on every plan (R1).
  - `docs/plans.md`: the *Personal agents, per person* row (1 / 2 / 5; self-hosted up to 20), outside the organisation bundle.
  - `docs/sharing.md`: a grant to a personal agent is not a share; removing one does not rotate the record key.
  - `CHANGELOG.md` *Unreleased*: the feature; migration `20261115000000_personal_agents`; **"Operators using AWS KMS must add `ownerUserId` to the allowed encryption-context keys before anyone enrols a personal agent"**; personal agents are on by default and how to switch them off (`PERSONAL_AGENTS=off`, or the policy).
  - `deploy/client/README.md` (*Agent access (optional)*) and both `.env.example` files: `PERSONAL_AGENTS`.
- [ ] **Step 4: Run** `npm run e2e` from the repo root with no `GATEWAY_*` set, then `npm test` and `npm run typecheck`. Expected: PASS, unchanged.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: Phase A acceptance (e2e) and docs"`

---

## Phase B — agent writes

### Task 10: Crypto and API — deposits

**Files:**
- Modify: `packages/crypto/src/agents.ts`; Test: `packages/crypto/test/agents.test.ts`
- Modify: `apps/api/prisma/schema.prisma`; Create: `apps/api/prisma/migrations/20261116000000_agent_writes/migration.sql` (also carries Task 11's column and table)
- Create: `apps/api/src/routes/agentDeposits.ts` (the gateway's `/agent/deposits*` and the owner's `/me/agent-deposits*`); register with the personal-agent routes
- Modify: `apps/api/src/lib/personalAgents.ts` (`personalAgentSync.deposits`, `connectedApp`, `sweepAgentWrites`; revoke discards unkept deposits), `apps/api/src/lib/sync.ts`, `apps/api/src/app.ts` (the sweep interval)
- Test: `apps/api/test/agent-deposits.test.ts`

**Interfaces:**
- Produces, crypto:
  ```ts
  export async function sha256B64(text: string): Promise<string>;                          // base64url(SHA-256(utf8))
  export const agentDepositOwnerAad: (ownerUserId: string, id: string) => string;
  export const agentDepositMessage: (m: { ownerUserId: string; ownerPublicKey: string; agentId: string; id: string; revision: number; encBodyHash: string }) => string;
  export const agentUpdateMessage: (m: { ownerUserId: string; agentId: string; id: string; revision: number; encBodyHash: string }) => string;
  export function sealDepositKeyToOwner(recordKey: Uint8Array, ids: { ownerUserId: string; id: string }, ownerPublicKey: Uint8Array): Promise<string>;
  export function openDepositKey(sealed: string, ids: { ownerUserId: string; id: string }, keys: SealKeys): Promise<Uint8Array>;
  ```
- Schema: `AgentDeposit` as spec §4.1 (one field per line), plus `connectedApp String`, and relations to the owner `User` and the `Agent` with `onDelete: Cascade`. `Record.createdByAgentId String? @db.Uuid` (no relation: the name is looked up, and the column survives the agent).
- `connectedApp(db, a: FastifyRequest["agent"]): Promise<string>`: the `AgentToken.label`, or the `AgentOAuthClient.name` behind `grantId`.
- Gateway routes (`requireAgent`; an organisation agent → `409 not_writable`):
  - `POST /agent/deposits { id: uuid, type: "login" | "item", encBody, ownerSealedKey, agentSealedKey, signature: /^d1\.[^.]+\.[^.]+$/ }` → `201 { id, revision: 1 }`. `409 not_writable` when `rules.write` is false; `409 inbox_full` at 100 unkept deposits of the owner; `409 conflict` when the id is already a `Record` or a deposit. The signature must pass `gatewaySigned` over `agentDepositMessage` with the owner's current public key and revision 1, else `409 conflict`. Event `agent.deposit` (`actorId` agent, `recordId` = id, `meta { app }`).
  - `PUT /agent/deposits/:id { encBody, revision, signature }` → `{ id, revision: revision + 1 }`; only the agent's own row (else `409 not_writable`); `revision` must be the stored one (`409 conflict`); the signature covers `revision + 1`.
- Owner routes (`requireAuth`, private-lock refused):
  - `GET /me/agent-deposits` → `{ deposits: { id, agentId, agentName, app, type, encBody, revision, ownerSealedKey, signature, createdAt, updatedAt, expiresAt }[] }` (`expiresAt` = `createdAt` + 90 days).
  - `POST /me/agent-deposits/:id/keep { revision, wrappedRecordKey: <v1. envelope>, folderId: uuid | null, agentWrappedRecordKey?: <s1.> }` → `201 { id, revision: 1 }`. `409 conflict` when `revision` is not the stored one (Review Focus 4). `folderId` must be the caller's own private folder (`404 folder_not_found`). One transaction: create the `Record` (same id, `type`, `encBody`, `createdByAgentId`) and the owner row; with `agentWrappedRecordKey` and a live agent, the agent's `use` row (`agentWrite` false, `sealedTo` its key); delete the deposit. Event `agent.deposit_keep`.
  - `DELETE /me/agent-deposits/:id` → 204, event `agent.deposit_delete`.
- `personalAgentSync.deposits`: `{ id, encBody, revision, agentSealedKey }[]`, the agent's own unkept ones.
- `/sync` (Personal space): top-level `agentInbox: number`; a record with `createdByAgentId` carries `createdByAgent: { id, name }`. Deposits are in no `/sync`.
- `sweepAgentWrites(prisma, now = new Date()): Promise<number>`: deletes deposits older than 90 days (and, from Task 11, overwrites older than 30); called in the existing sweep interval when agents are on. `revokePersonalAgent` deletes the agent's unkept deposits; kept records stay.

- [ ] **Step 1: Write the failing tests.**
  - Crypto: `agentDepositMessage({ ownerUserId: "u", ownerPublicKey: "opk", agentId: "a", id: "d", revision: 2, encBodyHash: "h" })` is `"agent-deposit:u:opk:a:d:2:h"`; `agentUpdateMessage` → `"agent-update:u:a:d:2:h"`; `agentDepositOwnerAad("u", "d")` → `"agent-deposit-owner:u:d"`; `sha256B64("")` is `"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"`; the seal pair round-trips and fails on another id.
  - API, with deposits built by a test helper that plays the gateway (a real body, real seals, and a signature by the fake gateway's identity key):
    - `POST` → 201; the row exists; `GET /me/agent-deposits` shows it with the agent's name and the token's label as `app`; `GET /sync` (Personal) has `agentInbox: 1` and **no record with that id**; `GET /sync?space=org` has neither (spec §8).
    - A signature over another `encBody`, or by another identity key → `409 conflict`, nothing stored.
    - Policy `write: false` → `409 not_writable`. The 101st → `409 inbox_full`. An organisation agent's token → `409 not_writable`.
    - `PUT` by the same agent bumps the revision; by the owner's second agent → `409 not_writable`; a stale revision → `409 conflict`.
    - `keep` with `revision: 1` after the agent's update → `409 conflict`; with the current one → 201: a `Record` with that id and `encBody`, `createdByAgentId` set, an owner row holding `wrappedRecordKey`, the deposit gone, `/sync` now lists the record with `createdByAgent`. With `agentWrappedRecordKey` the agent's row exists with `agentWrite` false; without it, none.
    - Another user cannot `GET`, `keep` or `DELETE` it (404).
    - `sweepAgentWrites` at `createdAt` + 91 days deletes it; at + 89 days it does not.
    - Revoking the agent deletes its unkept deposit and leaves a kept record.
- [ ] **Step 2: Run** `npx vitest run test/agents.test.ts` in `packages/crypto` and `npx vitest run test/agent-deposits.test.ts` in `apps/api`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** both, plus `npx vitest run test/records.test.ts test/sharing.test.ts test/personal-agents-revoke.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: gateway-signed deposits and the owner's Keep (API, crypto)"`

### Task 11: API — *Agent can update*: signed, reversible record updates

**Files:**
- Modify: `apps/api/prisma/schema.prisma` and the Task 10 migration (`RecordAccess.agentWrite`, `RecordAgentOverwrite`)
- Modify: `apps/api/src/routes/agentGrants.ts`, `apps/api/src/routes/agentDeposits.ts` (`PUT /agent/records/:id`), `apps/api/src/lib/sync.ts`, `apps/api/src/lib/personalAgents.ts`
- Test: `apps/api/test/agent-updates.test.ts`

**Interfaces:**
- Schema: `RecordAccess.agentWrite Boolean @default(false)`, and
  ```prisma
  model RecordAgentOverwrite {
    id          String    @id @default(uuid()) @db.Uuid
    recordId    String    @db.Uuid
    record      Record    @relation(fields: [recordId], references: [id], onDelete: Cascade)
    agentId     String    @db.Uuid
    prevEncBody String
    newRevision Int
    /// u1.<gatewayKeyId>.<sig> over the body written at newRevision
    signature   String
    ackedAt     DateTime?
    createdAt   DateTime  @default(now())

    @@index([recordId])
  }
  ```
- `PATCH /records/:id/agent-grants/:agentId { write: boolean }` → `{ ok: true }` (owner only; the row must exist, else 404); event `agent.item_write` with `meta { write }`. Nothing else sets `agentWrite`: not `keep`, not a person's edit, not the shares routes.
- `PUT /agent/records/:id { encBody, revision, signature: /^u1\./ }` (`requireAgent`) → `{ id, revision: revision + 1 }`. In order: `rules.write` false, or no row of the agent's with `agentWrite` true, or the record is trashed or no longer the owner's private record → `409 not_writable`; `revision` not the stored one → `409 conflict`; the signature must pass `gatewaySigned` over `agentUpdateMessage` with `revision + 1`, else `409 conflict`. One transaction with a row lock on the record: insert the overwrite (`prevEncBody`, `newRevision`), keep only the newest 5 for the record, update `encBody` and `revision`. `Record.type` is not changed. Event `agent.update` (`recordId`).
- `GET /records/:id/agent-overwrites` (owner) → `{ overwrites: { id, agentId, agentName, prevEncBody, newRevision, signature, createdAt }[] }`, newest first. `POST /records/:id/agent-overwrites/ack` → sets `ackedAt` on all of them. Restoring is the client saving the previous body through the shipped `PUT /records/:id`; there is no restore route.
- `/sync` (Personal): a record gains `agentChange: { agentId, agentName, at, signature }` when its newest overwrite has `ackedAt` null and `newRevision === record.revision` (so any later save by a person hides it). `personalAgentSync.records[].write` is `agentWrite && rules.write`.
- `sweepAgentWrites` also deletes overwrites older than 30 days.

- [ ] **Step 1: Write the failing tests:**
  - A granted record without `agentWrite` → `409 not_writable` (spec §8). After `PATCH { write: true }` → 200, revision 2, and `GET agent-overwrites` returns the previous `encBody`, which still decrypts with the record key.
  - A stale `revision` → `409 conflict` and **no overwrite row** (Review Focus 4). A signature over another body → `409 conflict`.
  - Six updates leave five overwrite rows. `/sync` shows `agentChange`; after the owner's `PUT /records/:id` it is gone; after `ack` it is gone.
  - `keep` (Task 10) with `agentWrappedRecordKey` leaves `agentWrite` false; `PATCH /records/:id/shares/<agentId>` cannot set it.
  - Policy `write: false` → `409 not_writable` and the sync's `write` is false. After a move into a team folder → `409 not_writable`.
  - Another owner's agent, or another user's record → `409 not_writable`.
- [ ] **Step 2: Run** `npx vitest run test/agent-updates.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file and `npx vitest run test/agent-deposits.test.ts test/records.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: Agent can update, signed overwrites with the previous five kept"`

### Task 12: Gateway — `save_secret`, `update_secret`, the write limit

**Files:**
- Modify: `apps/gateway/src/config.ts` (`writePerHour`, `GATEWAY_WRITE_PER_HOUR`), `apps/gateway/src/apiClient.ts`, `apps/gateway/src/items.ts`, `apps/gateway/src/mcp.ts`
- Create: `apps/gateway/src/deposits.ts`
- Modify: `apps/gateway/test/fakeApi.ts`
- Test: `apps/gateway/test/deposits.test.ts`, `mcp.test.ts`, `config.test.ts`, `noPlaintext.test.ts`

**Interfaces:**
- Consumes: Tasks 6, 10, 11.
- `apiClient.ts`:
  ```ts
  export type WriteRefused = { refused: "not_writable" | "conflict" | "inbox_full" };   // a 409 body's error; 401/403 still throw ApiRefused
  deposit(token: string, d: { id: string; type: "login" | "item"; encBody: string; ownerSealedKey: string; agentSealedKey: string; signature: string }): Promise<{ revision: number } | WriteRefused>;
  updateDeposit(token: string, id: string, d: { encBody: string; revision: number; signature: string }): Promise<{ revision: number } | WriteRefused>;
  updateRecord(token: string, id: string, d: { encBody: string; revision: number; signature: string }): Promise<{ revision: number } | WriteRefused>;
  ```
  `PersonalAgentSync.deposits` and `records[].write` as the API sends them.
- `deposits.ts`:
  ```ts
  export interface SaveInput { title: string; type: RecordType;
    fields?: { username?: string; password?: string; url?: string; notes?: string; data?: Record<string, string> };
    custom_fields?: { label: string; kind: FieldKind; value: string }[];
    agent_use?: { hosts: string[]; inject: AgentInject; secret?: string } }
  export type BuiltDeposit = { id: string; type: "login" | "item"; encBody: string; ownerSealedKey: string; agentSealedKey: string; signature: string };
  /** normalizeRecordBody (a throw → "invalid"), a random id and record key, both seals, the d1 signature at revision 1. Zeroes the key; every value of password, data.* and custom fields is in `held` until it returns. */
  export async function buildDeposit(sync: PersonalAgentSync, identity: Identity, input: SaveInput, held: HeldSecrets): Promise<BuiltDeposit>;
  /** Decrypts, applies `set` to username/password/url/notes/data only, leaves agentPolicy and agentReveal exactly as decrypted, re-encrypts under the same key, signs for `revision + 1` (d1 for a deposit, u1 for a record). */
  export async function buildUpdate(sync: PersonalAgentSync, keys: MembershipKeys, identity: Identity, target: { kind: "deposit" | "record"; id: string; revision: number },
    set: NonNullable<SaveInput["fields"]>, held: HeldSecrets): Promise<{ encBody: string; revision: number; signature: string }>;
  ```
- `items.ts`: `ItemSummary` gains `deposit?: true`, `can_update?: true`, `revision: number`. Unkept deposits are listed (same handle namespace, `personal/<slug>`), opened with `agentSealedKey`. `withItem` on a deposit → `{ error: "refused", reason: "not_kept" }` (R8).
- `mcp.ts`, personal sessions only (organisation sessions still register exactly two tools):
  - `save_secret` (`SaveInput` as a zod schema; `title` 1–200 characters) → `{ item: <handle> }` or `{ error: "refused", reason: "invalid" | "not_writable" | "inbox_full" }`. `sync.policy.write` false → `not_writable` without calling the API. The agent's sync cache entry is dropped after a write.
  - `update_secret { item, set, revision? }` → `{ item, revision }` or `refused: not_found | not_writable | conflict | invalid`. A record without `write` → `not_writable` without calling the API. A given `revision` that is not the current one → `conflict`.
  - Both count against `write:<agentId>`: `cfg.writePerHour` per hour, checked before the transport like the shipped limits (HTTP 429 with `Retry-After`).
  - `list_secrets` items gain `deposit` and `can_update` where true.
- No delete, move or share tool exists.

- [ ] **Step 1: Write the failing tests:**
  - `deposits`: from `buildDeposit`'s output the owner opens `ownerSealedKey` with `openDepositKey`, decrypts `encBody` (`decryptRecordBody(id, …)`) and reads the body back; `agentSealedKey` opens with `openPersonalAgentRecordKey`; `verifyGatewayMessage(signature, "d1", agentDepositMessage({ …, revision: 1, encBodyHash: await sha256B64(encBody) }), identity)` is true. A 60 KB note → throws.
  - `buildUpdate` on a record with an `agentPolicy`: `JSON.stringify(after.agentPolicy) === JSON.stringify(before.agentPolicy)` (spec §8), only the `set` fields differ, and the signature verifies as `u1` at `revision + 1`.
  - `mcp`: `save_secret`, then `list_secrets` shows the handle with `deposit: true`; `http_request` on it → `not_kept`. `update_secret` on the deposit bumps its revision at the fake API. On a record with `write: false` → `not_writable` and the fake API saw no `PUT`. With `write: true` → the fake API's stored body decrypts to the new password. The fake API answering `409 inbox_full` → `refused: inbox_full`. The 21st write in an hour → HTTP 429. In an organisation session `tools/list` has two tools and calling `save_secret` is an unknown-tool error.
  - `noPlaintext`: the shipped canary test also runs `save_secret` and `update_secret` with known values; they appear in no log line, no MCP response and no API request body (spec §8).
  - `config`: `GATEWAY_WRITE_PER_HOUR` defaults to 20; `0` is refused.
- [ ] **Step 2: Run** `npx vitest run` in `apps/gateway`. Expected: the new cases FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and the typecheck. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: save_secret and update_secret, signed by the gateway, with an hourly write limit"`

### Task 13: Gateway — `capture`: saving a secret the model never sees

**Files:**
- Modify: `apps/gateway/src/outbound/request.ts`, `apps/gateway/src/mcp.ts`, `apps/gateway/src/deposits.ts`
- Test: `apps/gateway/test/capture.test.ts`, `request.test.ts`, `noPlaintext.test.ts`

**Interfaces:**
- Consumes: Task 12.
- `OutboundCtx` gains `capture?: (body: string, status: number) => string | null`: called once, on the final response only (never on a redirect hop), with the decompressed, capped body **before** scrubbing. A returned string is scrubbed from the headers and body with every variant (`variantsOf`), exactly like the injected secret.
- `deposits.ts`: `export function pointerValue(json: string, pointer: string): string | null` — RFC 6901 (`~0`, `~1`); null unless the JSON parses and the target is a non-empty string of at most `MAX_FIELD_VALUE`.
- `http_request` input gains, in personal sessions only, `capture?: { from: string (≤ 256 characters), title: string, type: RecordType, agent_use?: SaveInput["agent_use"] }`. `type` must have a default secret field (`defaultSecretRef(type) !== null`, else an input error); the value goes there (`data.secret` for `apiKey`, else `password`).
- Behaviour:
  1. Before the outbound call: `sync.policy.write` false → `not_writable`; `sync.deposits.length >= 100` on a fresh (uncached) sync → `inbox_full`; the write limit is taken (429). In all three nothing is sent (Review Focus 3).
  2. The capture callback returns the pointer's value only for a 2xx, untruncated response.
  3. The value is held in `HeldSecrets`, saved with `buildDeposit` and `api.deposit`, and the result gains `saved: { item }`.
  4. No value at the pointer → the normal result plus `capture: { refused: "not_found" }`. The save failing after the call → the result plus `capture: { refused: <reason> }`, still scrubbed of the value.

- [ ] **Step 1: Write the failing tests** (upstream answering `{"id":7,"token":"ghp_CAPTURED_CANARY"}`):
  - The tool result has `saved.item === "personal/github-deploy-token"`; its body contains `[clane:redacted]` and not the canary (raw, base64, URL-encoded); the fake API holds a deposit whose `data.secret` decrypts to the canary; `list_secrets` shows it with `deposit: true`.
  - A full inbox → `inbox_full` and the upstream received **no** request. The write limit used up → 429, no request.
  - The fake API failing the deposit after the call → the result has `capture: { refused: "conflict" }`, no `saved`, and still no canary.
  - `from: "/missing"` → `capture: { refused: "not_found" }`. A truncated or non-2xx response is never captured.
  - `pointerValue('{"a/b":{"c":["x","y"]}}', "/a~1b/c/1")` is `"y"`; a number, an object or an empty string → null.
  - `capture` in an organisation session → an input validation error. `noPlaintext` runs a capture.
- [ ] **Step 2: Run** `npx vitest run test/capture.test.ts test/request.test.ts test/noPlaintext.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `apps/gateway`. Expected: PASS, `scrub.test.ts` and `ssrf.test.ts` unchanged.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: http_request capture saves a created credential without showing it"`

### Task 14: Web — the *From agents* inbox, provenance, *Agent can update*

**Files:**
- Create: `apps/web/src/features/vault/agentInbox.ts`, `apps/web/src/features/vault/AgentInbox.tsx`
- Modify: `apps/web/src/features/vault/Sidebar.tsx`, `VaultScreen.tsx`, `RecordPanel.tsx`, `RecordAgentsSection.tsx`, `useVault.ts`, `types.ts`
- Test: `apps/web/src/features/vault/AgentInbox.test.tsx`, `apps/web/src/features/vault/RecordAgents.test.tsx`

**Interfaces:**
- Consumes: Tasks 10, 11; `verifyGatewayMessage`, `agentDepositMessage`, `agentUpdateMessage`, `sha256B64`, `openDepositKey`.
- `agentInbox.ts`:
  ```ts
  export type OpenedDeposit = { id: string; agentId: string; agentName: string; app: string; createdAt: string; expiresAt: string; revision: number }
    & ({ ok: true; body: RecordBody; recordKey: Uint8Array } | { ok: false });
  /** ok only when the d1 signature verifies against pinnedGateway(me, PERSONAL_SLOT) over a message naming MY public key (derived from the unlocked private key), and the key and body then open. Nothing is decrypted before the signature passes. */
  export async function openDeposit(d: DepositRow, me: string, keys: UnlockedKeys): Promise<OpenedDeposit>;
  export function useAgentInbox();     // GET /me/agent-deposits → OpenedDeposit[]
  export function useKeepDeposit();    // wrapKey(recordKey, userKey, `record-key:${id}`) → POST keep { revision, wrappedRecordKey, folderId, agentWrappedRecordKey? }
  export function useDeleteDeposit();
  ```
- `AgentInbox`: the Personal space's sidebar gets **From agents** with a count badge (`agentInbox` from `/sync`); the entry is absent in organisation spaces. Each deposit is shown read-only with the agent's name, the connected app, the time, and any `agentPolicy` under the label *set by the agent*. A failed one shows *"Not signed by the gateway — delete it"* with **Delete** only. **Keep** offers a folder and the checkbox *"<agent> can keep using this item"* (on by default; it runs `verifyPersonalAgentKey` and seals as a grant). From day 60: *"Deleted in n days unless you keep it."* A `409 conflict` on Keep reloads the inbox with *"The agent changed this item. Check it again."*
- `RecordPanel`: *"Created by agent <name> on <date>"* for `createdByAgent`. For `agentChange`: a banner *"Changed by agent <name>"* — worded *"Changed, but not signed by the gateway"* when the `u1` signature over the current `encBody` fails against the pinned identity — with **Restore previous** (loads `agent-overwrites`, decrypts `prevEncBody` with the record key, saves it through the normal edit path). Opening the record calls `ack`.
- `RecordAgentsSection`: with *Can use* chosen, a checkbox *Agent can update this item* → `PATCH { write }`. Hidden when `rules.write` is false.

- [ ] **Step 1: Write the failing tests** (deposits built in the test with real crypto and a test identity key pinned in `PERSONAL_SLOT`):
  - A good deposit renders its title and username. One signed by another identity, one with the signature removed, and one whose message names another owner key each render the refusal copy, and `openDepositKey` was never called for them (spy) (spec §8).
  - **Keep** posts a `wrappedRecordKey` that unwraps under the user key with AAD `record-key:<id>` to the deposit's record key, and an `agentWrappedRecordKey` that opens with the agent key; unticking the box omits it.
  - `409 conflict` → the inbox refetches and shows the message (Review Focus 4).
  - A record with `agentChange` shows the banner; **Restore previous** issues a `PUT /records/:id` whose body decrypts to the previous body; a bad `u1` signature shows the not-signed wording.
  - Ticking *Agent can update* sends `PATCH … { write: true }`.
- [ ] **Step 2: Run** the two files in `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and the typecheck in `apps/web`, and `npx vitest run` in `apps/extension` (it reuses `decryptSync`; no deposit may appear in its items). Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: From agents inbox with signature check and Keep, provenance, Agent can update"`

### Task 15: Phase B acceptance — e2e and docs

**Files:**
- Modify: `e2e/agents/personal.spec.ts`; `docs/agents.md`, `SECURITY.md`, `CHANGELOG.md` (*Unreleased*), `deploy/client/README.md`, `deploy/client/.env.example`, `deploy/client/docker-compose.yml` (pass `GATEWAY_WRITE_PER_HOUR` to the gateway, like the other `GATEWAY_*` values)

- [ ] **Step 1: Extend the test** (as the member, before the revoke step):
  1. MCP `save_secret { title: "Saved by agent", type: "apiKey", fields: { data: { secret: "sk_test_SAVED_CANARY" } } }` → `{ item }`. The vault list does not show it; **From agents** shows a badge of 1.
  2. Open it: the agent's name and the token label are shown. **Keep** → it is in the vault with *Created by agent My helper*, and the record view shows the canary.
  3. MCP `update_secret` on it → `not_writable`. Tick *Agent can update this item* and call again with a new secret → the record shows *Changed by agent My helper*; **Restore previous** brings `sk_test_SAVED_CANARY` back.
  4. The echo upstream's `POST /token` answers `{"token":"tok_CAPTURED_CANARY"}`: `http_request` with `capture: { from: "/token", title: "Captured", type: "apiKey" }` → the result has `saved.item` and no canary; **From agents** shows "Captured", and its secret is the canary.
- [ ] **Step 2: Run** `npm run test:agents -w e2e`. Expected: PASS.
- [ ] **Step 3: Write the docs.**
  - `docs/agents.md`: *Saving and updating items* (deposits and why they are not records, Keep, 90 days, *Agent can update* and Restore previous, no delete); the tools' inputs and outputs; `capture`, and "prefer it over `save_secret`"; `GATEWAY_WRITE_PER_HOUR`; the new refusal reasons.
  - `SECURITY.md`: the *Deposits and agent updates* row and the costs from spec §4.4 (the `agentWrite` flag is server state; the gateway sees written secrets).
  - `CHANGELOG.md`: the feature and migration `20261116000000_agent_writes`. Deploy README and `.env.example`: the setting.
- [ ] **Step 4: Run** `npm test`, `npm run typecheck`, and `npm run e2e` with agents off. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: Phase B acceptance (e2e) and docs"`

---

## Phase C — reveal with approval

### Task 16: Crypto and API — field scope, reveal stubs

**Files:**
- Modify: `packages/crypto/src/agents.ts`; Test: `packages/crypto/test/agents.test.ts`
- Modify: `apps/api/prisma/schema.prisma`; Create: `apps/api/prisma/migrations/20261117000000_agent_reveal/migration.sql` (also carries Task 17's table and columns)
- Create: `apps/api/src/routes/agentReveals.ts` (this task: the stub routes); register with the personal-agent routes
- Modify: `apps/api/src/lib/personalAgents.ts` (`personalAgentSync.reveal`; revoke deletes stubs), `apps/api/src/lib/sync.ts`, `apps/api/src/routes/records.ts` (the move into a team folder deletes the record's stubs in its transaction)
- Test: `apps/api/test/agent-reveals.test.ts`

**Interfaces:**
- Produces, crypto:
  ```ts
  /** A field reference: "username" | "password" | "url" | "notes" | "totp" | "data.<key>" | "field:<id>". Never "totpSecret". */
  export const REVEAL_REF = /^(username|password|url|notes|totp|data\.[A-Za-z0-9_]{1,40}|field:[A-Za-z0-9_-]{1,64})$/;
  /** 1–20 unique refs, each matching REVEAL_REF and naming something this body has ("totp" needs totpSecret; data.<key> ∈ dataKeysOf(type); field:<id> ∈ body.fields). Returns them sorted. Throws otherwise. */
  export function validateRevealFields(fields: unknown, body: Pick<RecordBody, "type" | "fields" | "totpSecret">): string[];
  /** Only the named fields that have a value. "totp" → totpCode(body.totpSecret, atMs). The seed is never returned under any ref. */
  export async function revealFieldsOf(body: RecordBody, fields: string[], atMs?: number): Promise<Record<string, string>>;
  export interface RevealStub { title: string; type: RecordType; fields: string[] }
  export const personalAgentStubAad: (ownerUserId: string, agentId: string, recordId: string) => string;
  export function sealRevealStub(stub: RevealStub, ids: { ownerUserId: string; agentId: string; recordId: string }, agentPublicKey: Uint8Array): Promise<string>;
  export function openRevealStub(sealed: string, ids: { ownerUserId: string; agentId: string; recordId: string }, keys: SealKeys): Promise<RevealStub>;
  export const agentRevealRequestMessage: (m: { requestId: string; ownerUserId: string; agentId: string; recordId: string; fields: string[]; requestPublicKey: string; expiresAt: string }) => string; // fields sorted, joined by ","
  export const agentRevealAad: (requestId: string, recordId: string, agentId: string) => string;
  export function sealReveal(fields: Record<string, string>, ids: { requestId: string; recordId: string; agentId: string }, requestPublicKey: Uint8Array): Promise<string>;
  export function openReveal(sealed: string, ids: { requestId: string; recordId: string; agentId: string }, keys: SealKeys): Promise<Record<string, string>>;
  ```
- Schema:
  ```prisma
  model AgentRevealGrant {
    id         String   @id @default(uuid()) @db.Uuid
    recordId   String   @db.Uuid
    record     Record   @relation(fields: [recordId], references: [id], onDelete: Cascade)
    agentId    String   @db.Uuid
    agent      Agent    @relation(fields: [agentId], references: [userId], onDelete: Cascade)
    /// s1. to the agent's key: { title, type, fields }. What the gateway enforces.
    sealedStub String
    /// The same field names in clear, for the owner's screens. The server sees field names on every request anyway; it cannot widen the sealed stub.
    fields     String[]
    createdAt  DateTime @default(now())

    @@unique([recordId, agentId])
    @@index([agentId])
  }
  ```
- Owner routes (`requireAuth`, private-lock refused), with the same record and agent checks as `POST /records/:id/agent-grants` (Task 4):
  - `PUT /records/:id/agent-reveal/:agentId { sealedStub: <s1.>, fields: string[] (1–20, each matching REVEAL_REF) }` → `{ ok: true }`; `403 { error: "reveal_disabled" }` when `rules.reveal` is `off`; `409 agent_item_limit` at 200 stubs for the agent. Event `agent.item_reveal_on` (`meta { fields }`).
  - `DELETE /records/:id/agent-reveal/:agentId` → 204; event `agent.item_reveal_off`.
- `personalAgentSync.reveal`: `{ recordId, sealedStub }[]` for the owner's live private records; `[]` when `rules.reveal` is `off`.
- `/sync` (Personal): `agentGrants` entries become `{ agentId, use: boolean, write: boolean, reveal?: string[] }`; an agent holding only a stub appears with `use: false`.

- [ ] **Step 1: Write the failing tests.**
  - Crypto:
    ```ts
    const body = { v: 2, type: "login", title: "T", username: "u", password: "p", totpSecret: "JBSWY3DPEHPK3PXP", fields: [{ id: "f1", label: "Acct", kind: "text", value: "42" }] } as RecordBody;
    expect(validateRevealFields(["username", "field:f1", "totp"], body)).toEqual(["field:f1", "totp", "username"]);
    for (const bad of [[], ["totpSecret"], ["username", "username"], ["data.nope"], ["field:zz"], ["a,b"], Array(21).fill("username")]) expect(() => validateRevealFields(bad, body)).toThrow();
    expect(() => validateRevealFields(["totp"], { type: "login" })).toThrow();
    const out = await revealFieldsOf(body, ["username", "totp", "notes"], 0);
    expect(out).toEqual({ username: "u", totp: await totpCode("JBSWY3DPEHPK3PXP", 0) });
    expect(JSON.stringify(out)).not.toContain("JBSWY3DPEHPK3PXP");                                  // spec §8
    expect(agentRevealRequestMessage({ requestId: "q", ownerUserId: "u", agentId: "a", recordId: "r", fields: ["username", "password"], requestPublicKey: "k", expiresAt: "2026-11-15T10:00:00.000Z" }))
      .toBe("agent-reveal-request:q:u:a:r:password,username:k:2026-11-15T10:00:00.000Z");
    expect(agentRevealAad("q", "r", "a")).toBe("agent-reveal:q:r:a");
    expect(personalAgentStubAad("u", "a", "r")).toBe("personal-agent-stub:u:a:r");
    ```
    Both seal pairs round-trip and fail under another id.
  - API: `PUT` → 200 and the agent's sync lists the stub; **no `RecordAccess` row** for the agent was created; `/sync` shows `agentGrants: [{ agentId, use: false, write: false, reveal: ["username"] }]`. Refusals as for grants (team-folder record `409 team_record`, another user's agent `400 user_not_active`), plus `fields: ["totpSecret"]` → 400 and policy `reveal: "off"` → `403 reveal_disabled` with the sync's `reveal` then `[]`.
  - Review Focus 2: moving the record into a team folder deletes the stub; a trashed record's stub is not in the sync; revoking the agent deletes its stubs.
- [ ] **Step 2: Run** `npx vitest run test/agents.test.ts` in `packages/crypto` and `npx vitest run test/agent-reveals.test.ts` in `apps/api`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** both, plus `npx vitest run test/personal-agents-access.test.ts test/records.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: reveal field scope and per-item reveal stubs (crypto, API)"`

### Task 17: API — reveal requests: ask, approve, deny, expire, pause, notify

**Files:**
- Modify: `apps/api/prisma/schema.prisma` and the Task 16 migration
- Modify: `apps/api/src/routes/agentReveals.ts`, `apps/api/src/routes/myAgents.ts`, `apps/api/src/lib/personalAgents.ts`, `apps/api/src/lib/email.ts`, `apps/api/src/lib/gateway.ts`, `apps/api/src/app.ts` (sweep)
- Test: `apps/api/test/agent-reveals.test.ts`

**Interfaces:**
- Schema: `enum AgentRevealStatus { pending approved denied expired delivered }`;
  ```prisma
  model AgentRevealRequest {
    id               String            @id @db.Uuid          // generated by the gateway; part of the signed message
    agentId          String            @db.Uuid
    agent            Agent             @relation(fields: [agentId], references: [userId], onDelete: Cascade)
    ownerUserId      String            @db.Uuid
    recordId         String            @db.Uuid
    fields           String[]
    reason           String
    requestPublicKey String
    signature        String
    connectedApp     String
    status           AgentRevealStatus @default(pending)
    sealed           String?
    expiresAt        DateTime
    createdAt        DateTime          @default(now())

    @@index([ownerUserId, status])
    @@index([agentId, status])
  }
  ```
  `Agent.revealPausedUntil DateTime?`; `User.agentRevealEmail Boolean @default(true)`, `User.agentRevealEmailedAt DateTime?`.
- Gateway routes (`requireAgent`; organisation agents → `409 reveal_off`):
  - `POST /agent/reveals { id: uuid, recordId: uuid, fields: string[] (1–20, REVEAL_REF, sorted, unique), reason: string (1–300), requestPublicKey, signature: /^q1\./, expiresAt: ISO }` → `201 { id, expiresAt }`. In order: `rules.reveal` `off`, or no `AgentRevealGrant` for (record, agent) → `409 reveal_off`; `revealPausedUntil` in the future → `409 denied`; a `pending`, unexpired request of this agent → `409 busy`; `expiresAt` not within (now, now + 5 min + 30 s], or the signature failing `gatewaySigned` over `agentRevealRequestMessage` → `409 reveal_off`. Event `agent.reveal_request` (`recordId`, `meta { requestId, fields, app }`). Then the email (below), never awaited.
  - `GET /agent/reveals/:id` (the agent's own, else 404) → `{ status: "pending" }` | `{ status: "approved", sealed }` | `{ status: "denied" }` | `{ status: "expired" }`. A `pending` or `approved` row past `expiresAt` is claimed as `expired` (`updateMany`, so it logs once: `agent.reveal_expired`) and its `sealed` is nulled. Returning `approved` moves the row to `delivered`, nulls `sealed` and logs `agent.reveal` (`recordId`, `meta { requestId, fields, app }`) in one transaction; a second `GET` → `expired`.
- Owner routes (`requireAuth`, private-lock refused):
  - `GET /me/agent-reveals` → `{ requests: { id, agentId, agentName, app, recordId, fields, reason, requestPublicKey, signature, expiresAt, createdAt }[], paused: { agentId, agentName, until }[] }`: `pending`, unexpired requests only.
  - `POST /me/agent-reveals/:id/approve { sealed: <s1.> }` → `{ ok: true }`; not `pending` or past `expiresAt` → `409 expired`; `rules.reveal` `off` → `403 reveal_disabled`.
  - `POST /me/agent-reveals/:id/deny` → `{ ok: true }`; event `agent.reveal_denied`; when it is the third such event for the agent within 10 minutes, `revealPausedUntil = now + 1 h`.
  - `PATCH /me/agents/settings { revealEmail: boolean }` → `{ ok: true }`; `GET /me/agents` returns the stored value as `revealEmail`.
- `lib/email.ts`: `export function agentRevealEmail(productName: string, appUrl: string): { subject: string; text: string }` — subject *"An agent is asking for a secret"*, text *"An agent is asking for a secret. Open <productName> to answer: <appUrl>"*, where `appUrl` is `config.publicUrl` with no path or query for the request. Sent with `sendEmail` only when `agentRevealEmail` is true and `agentRevealEmailedAt` is null or more than 10 minutes old (claimed with `updateMany`).
- `lib/gateway.ts`: `GatewayClient.revealMode(): Promise<RevealMode>` reads `reveal` from `/internal/health` (absent → `"off"`). `GET /me/agents` returns `gateway.reveal` (`"off"` when the gateway is unreachable).
- `revokePersonalAgent` now fills `rotate.revealed` from the agent's `agent.reveal` events (record id, union of field names) and expires its open requests. `sweepAgentWrites` nulls `sealed` on, and expires, requests past `expiresAt`.

- [ ] **Step 1: Write the failing tests** (requests built by a helper that plays the gateway: a real one-time key pair and a `q1` signature by the fake gateway's identity key):
  - The happy path: `POST` → 201; `GET /me/agent-reveals` lists it with the token label as `app`; `approve` with a real `sealReveal` box; `GET /agent/reveals/:id` → `approved` with that box, which opens with the one-time key; a second `GET` → `expired`; the row is `delivered` with `sealed` null. Events in order: `agent.reveal_request`, `agent.reveal`; their `meta` has field names and no value.
  - No stub → `409 reveal_off`. A second request while one is pending → `409 busy`. A signature over another `requestPublicKey` → `409 reveal_off`. `expiresAt` an hour ahead → `409 reveal_off`.
  - Review Focus 1: with nobody answering, at `expiresAt` + 1 s `GET` → `expired`, exactly one `agent.reveal_expired` event across two calls; `approve` afterwards → `409 expired`; an approved-but-unfetched request past `expiresAt` → `expired`, `sealed` null.
  - Three `deny` calls within 10 minutes → the next `POST` is `409 denied`, `GET /me/agent-reveals` lists the agent under `paused`; an hour later it is accepted again.
  - Policy `reveal: "off"` after a request was made → `approve` is `403 reveal_disabled`.
  - Another user cannot list, approve or deny it (404). A private-locked session → `403 totp_step_up_required`.
  - Email: the first request sends one message whose text contains neither the item's id, the reason nor `/agent-reveals`; a second request two minutes later sends none; with `revealEmail: false` none.
  - No organisation's event log returns any `agent.reveal*` row. Revoke returns `rotate.revealed: [{ id, fields: ["username"] }]`.
- [ ] **Step 2: Run** `npx vitest run test/agent-reveals.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the file and `npx vitest run test/personal-agents.test.ts test/personal-agents-revoke.test.ts test/health-events.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: reveal requests with in-app approval, expiry, denial pause and a notification email"`

### Task 18: Gateway — `GATEWAY_REVEAL`, `get_secret`, five tools

**Files:**
- Modify: `apps/gateway/src/config.ts` (`reveal`, `revealPerHour`), `apps/gateway/src/app.ts` (`/internal/health` adds `reveal`), `apps/gateway/src/apiClient.ts`, `apps/gateway/src/items.ts`, `apps/gateway/src/mcp.ts`
- Create: `apps/gateway/src/reveal.ts`
- Modify: `apps/gateway/test/fakeApi.ts`
- Test: `apps/gateway/test/reveal.test.ts`, `mcp.test.ts`, `config.test.ts`, `noPlaintext.test.ts`

**Interfaces:**
- Consumes: Tasks 16, 17; `Identity.signMessage` (Task 6).
- `config.ts`: `reveal: "off" | "approval" | "standing"` from `GATEWAY_REVEAL` (default `off`; any other value is a config error), `revealPerHour` from `GATEWAY_REVEAL_PER_HOUR` (default 10, min 1).
- `apiClient.ts`:
  ```ts
  createReveal(token: string, r: { id: string; recordId: string; fields: string[]; reason: string; requestPublicKey: string; signature: string; expiresAt: string }): Promise<{ ok: true } | { refused: "reveal_off" | "busy" | "denied" }>;
  reveal(token: string, id: string): Promise<{ status: "pending" | "denied" | "expired" } | { status: "approved"; sealed: string }>;
  ```
- `reveal.ts`:
  ```ts
  export type RevealResult = { fields: Record<string, string> } | { status: "pending"; request_id: string } | { error: "refused"; reason: "reveal_off" | "field" | "denied" | "expired" | "busy" | "not_found" };
  /** In memory, per process: the one-time private key of each open request. A request can only be completed by the gateway process that made it; a restart turns it into "expired". */
  export class PendingReveals { /* add, take(requestId, agentId), sweep(now) — zeroes keys on removal */ }
  export interface RevealDeps { cfg: GatewayConfig; api: ApiClient; identity: Identity; held: HeldSecrets; pending: PendingReveals; pollMs?: number; waitMs?: number; now?: () => number }   // defaults 2000 and 50000
  export async function requestReveal(d: RevealDeps, p: AgentPrincipal, sync: PersonalAgentSync, keys: MembershipKeys, input: { item: string; fields: string[]; reason: string }): Promise<RevealResult>;
  export async function resumeReveal(d: RevealDeps, p: AgentPrincipal, requestId: string): Promise<RevealResult>;
  ```
  `requestReveal`, in order: `cfg.reveal === "off"` or `sync.policy.reveal === "off"` → `reveal_off` **with no API call**; the item has no stub → `reveal_off`; a field not in the stub's `fields` → `field`; a one-time X25519 pair, `expiresAt = now + 5 min`, the `q1` signature; `createReveal`; then poll `reveal()` every `pollMs` until `waitMs`: `approved` → `openReveal`, hold every value in `held` until the result is written, zero and forget the key, `{ fields }`; `denied`/`expired` → that reason; still pending → `{ status: "pending", request_id }`. `resumeReveal` polls an existing request of this agent the same way; unknown or another agent's → `expired`.
- `items.ts`: for a personal sync `ItemSummary` gains `modes: ("use" | "reveal")[]` and `reveal?: { fields: string[]; approval: true }`. An item with only a stub is listed from `openRevealStub` (title, type, no hosts) under the same `personal/<slug>` namespace.
- `mcp.ts`: a personal session registers five tools — `list_secrets`, `http_request`, `save_secret`, `update_secret`, `get_secret` — and uses the personal instructions from Global Constraints. An organisation session registers today's two with today's instructions. `get_secret` input is `{ item: string, fields: string[] (1–20), reason: string (1–300) }` or `{ request_id: uuid }`; a new request counts against `reveal:<agentId>` (`cfg.revealPerHour` per hour, HTTP 429 before the transport); resuming does not. A session is `busy` for other calls while it waits.

- [ ] **Step 1: Write the failing tests** (`pollMs: 5`, `waitMs: 60`):
  - `GATEWAY_REVEAL` unset: `get_secret` → `reveal_off` and the fake API received **no** `/agent/reveals` call (spec §8). `config`: `GATEWAY_REVEAL=always` → `config_error`.
  - With `approval`: the fake API's "owner" approves with `sealReveal({ username: "u" }, …)` → the tool returns `{ fields: { username: "u" } }`; the request the API received carries a `q1` signature that verifies over `agentRevealRequestMessage` with the request's own `requestPublicKey`.
  - Asking for `password` when the stub allows `username` → `field`, no API call. An item with a key but no stub → `reveal_off`.
  - The owner denies → `denied`. Nobody answers → `{ status: "pending", request_id }` after `waitMs`; `get_secret { request_id }` after approval → the fields; after expiry → `expired`; the session's `busy` flag is false afterwards (Review Focus 1). Another agent's `request_id` → `expired`.
  - The API answering `409 busy` → `busy`. The 11th new request in an hour → HTTP 429.
  - `list_secrets`: a use-and-reveal item has `modes: ["use", "reveal"]` and `reveal: { fields: ["username"], approval: true }`; a reveal-only item is listed with `modes: ["reveal"]` and `http_request` on it → `not_found`.
  - `tools/list`: personal → exactly the five names; organisation → exactly two (spec §8). `/internal/health` includes `reveal`.
  - `noPlaintext`: a revealed value appears in the MCP response for `get_secret` **only**, and in no log line or API request body.
- [ ] **Step 2: Run** `npx vitest run` in `apps/gateway`. Expected: the new cases FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and the typecheck. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: get_secret with approval per reveal, behind GATEWAY_REVEAL (default off)"`

### Task 19: Web — *Can reveal*, the approval sheet

**Files:**
- Create: `apps/web/src/features/vault/reveals.ts`, `apps/web/src/features/vault/RevealApproval.tsx`
- Modify: `apps/web/src/routes.tsx` (mount `<RevealApproval />` once, for every unlocked screen), `apps/web/src/features/vault/RecordAgentsSection.tsx`, `useVault.ts`, `apps/web/src/features/settings/MyAgentsSection.tsx`, `myAgents.ts`
- Test: `apps/web/src/features/vault/RevealApproval.test.tsx`, `apps/web/src/features/vault/RecordAgents.test.tsx`

**Interfaces:**
- Consumes: Tasks 16, 17; `verifyGatewayMessage`, `agentRevealRequestMessage`, `revealFieldsOf`, `sealReveal`, `sealRevealStub`, `validateRevealFields`.
- `reveals.ts`:
  ```ts
  export interface RevealRequest { id: string; agentId: string; agentName: string; app: string; recordId: string; fields: string[]; reason: string; requestPublicKey: string; signature: string; expiresAt: string; createdAt: string }
  /** Polls GET /me/agent-reveals every 5 s while the session is unlocked; a 404 (feature off) stops it for good. */
  export function useRevealRequests(): { requests: RevealRequest[]; paused: { agentId: string; agentName: string; until: string }[] };
  /** "ok" only when the q1 signature verifies against pinnedGateway(me, PERSONAL_SLOT) over the message built from the request as shown, the record is mine in the Personal space, and every asked field is in that agent's `agentGrants.reveal` for it. */
  export async function checkRequest(r: RevealRequest, me: string, record: VaultRecord | undefined): Promise<"ok" | "unsigned" | "unknown_item" | "fields">;
  /** revealFieldsOf(record.body, r.fields) → sealReveal(…, r.requestPublicKey) → POST approve. Sends nothing when checkRequest is not "ok". */
  export function useApproveReveal(); export function useDenyReveal();
  ```
  The Personal vault is loaded and decrypted for the check when the active space is an organisation.
- `RevealApproval`: a blocking sheet for the oldest request: the agent, the connected app, the item's title (from the user's own vault, never from the request), the field labels, the time, and the reason under *"Written by the agent. It may not be true."* Buttons **Allow once** and **Deny**. When `checkRequest` is not `ok` there is **no Allow button** and one line says why (*"This request was not signed by your gateway."* / *"This asks for an item or fields you did not allow."*). A countdown to `expiresAt`; an expired request leaves the sheet. A `paused` entry shows a notice: *"<agent> was denied three times. Its requests are paused until <time>."*
- `RecordAgentsSection`: the mode select becomes *None* / *Can use* / *Can reveal* / *Can use and reveal*. Reveal opens a field picker (the record's own fields; `username` preselected, `password` unticked; `totp` labelled *Current one-time code*) with the sentence *"Can reveal lets the AI model read these fields. Clane Vault cannot take them back afterwards."* and, below it, *"Prefer Can use. Reveal only what can't be sent in an HTTP call and is easy to change."* Saving seals `{ title, type, fields }` with `sealRevealStub` after `verifyPersonalAgentKey` and calls `PUT /records/:id/agent-reveal/:agentId`. The reveal options are absent when `rules.reveal` or `gateway.reveal` (from `GET /me/agents`) is `off`. Renaming a revealable record reseals its stubs.
- `MyAgentsSection`: the switch *Email me when an agent asks for a secret* (`PATCH /me/agents/settings`); the revoke dialog also lists `rotate.revealed`: *"These fields were shown to the AI model. Change them."*

- [ ] **Step 1: Write the failing tests** (real crypto, a test identity pinned in `PERSONAL_SLOT`):
  - A valid request shows the sheet with the vault's title for the record and the reason label; **Allow once** posts a `sealed` box that opens with the request's private key to exactly `{ username: "u" }` — no other key, and never `totpSecret` (spec §8).
  - A request whose `requestPublicKey` was replaced after signing: no Allow button, the unsigned line, and no `approve` call is possible (spec §8). The same for a request naming a record that is not in my Personal vault, and for one asking `password` when I allowed `username`.
  - **Deny** posts `deny`. An expired request disappears. Polling stops after a 404.
  - `RecordAgents`: choosing *Can reveal* with defaults sends `fields: ["username"]` and a stub that opens with the agent key to `{ title, type, fields: ["username"] }`; **no** `agent-grants` call is made (the agent gets no record key); with `gateway.reveal: "off"` the option is absent.
- [ ] **Step 2: Run** the two files in `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and the typecheck in `apps/web`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: Can reveal with a field picker, and the in-app approval sheet"`

### Task 20: Extension — a notification that an agent is asking (R6)

**Files:**
- Modify: `apps/extension/src/background/core.ts`, `apps/extension/src/background/index.ts`, `apps/extension/src/shared/messages.ts`, `apps/extension/src/popup/App.tsx`, `apps/extension/scripts/build.mjs` (manifest permission `notifications`)
- Modify: `apps/extension/test/fakeApi.ts`
- Test: `apps/extension/test/core.test.ts`

**Interfaces:**
- Consumes: `GET /me/agent-reveals` (Task 17).
- `Platform` gains `setBadge(text: string): void`, `notify(id: string, message: string): void`, `scheduleRevealCheck(): void` (an alarm named `reveals`, every 0.5 minutes, the MV3 minimum; `index.ts` routes it to `core.onRevealAlarm`).
- `core.ts`: `checkReveals(): Promise<number>` — only when signed in and unlocked; `GET /me/agent-reveals` without an organisation header; sets the badge to the count (`""` for 0); for each request id not yet notified (ids kept in session storage) calls `notify(id, "An agent is asking for a secret. Open Clane Vault to answer.")`. A 404 or 403 clears the badge and is not retried until the next unlock. `PopupMessage` gains `{ type: "reveals" }` → `{ count: number }`; the popup calls it every 5 s while open.
- Popup: with `count > 0`, a row *"An agent is asking for a secret"* with **Open Clane Vault** (opens the configured server's web app in a tab). The extension shows no item, no reason and no Allow button, and decrypts nothing for this.

- [ ] **Step 1: Write the failing tests:** unlocked with one pending request → `setBadge("1")` and one `notify`; a second check with the same request → no second `notify`; the request gone → `setBadge("")`; locked → no request is made; the fake API answering 404 → no badge and no further calls until unlock; the notification text contains no title or reason.
- [ ] **Step 2: Run** `npx vitest run test/core.test.ts` in `apps/extension`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` and `npm run typecheck -w @clane-vault/extension`; `npm run test:extension -w e2e`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: the extension notifies when an agent asks for a secret"`

### Task 21: Phase C acceptance — e2e and docs

**Files:**
- Modify: `e2e/playwright.agents.config.ts` (gateway env `GATEWAY_REVEAL: "approval"`), `e2e/agents/personal.spec.ts`
- Modify: `docs/agents.md`, `SECURITY.md`, `docs/extension.md`, `CHANGELOG.md` (*Unreleased*), `deploy/client/README.md`, `deploy/client/.env.example`, `deploy/client/docker-compose.yml` (pass `GATEWAY_REVEAL`, `GATEWAY_REVEAL_PER_HOUR`)

- [ ] **Step 1: Extend the test:**
  1. On "Echo" choose *Can use and reveal* with the default field. MCP `list_secrets` shows `modes: ["use", "reveal"]`.
  2. Start `get_secret { item: "personal/echo", fields: ["username"], reason: "e2e" }` without awaiting it. The web app shows the sheet with "Echo", *username*, and the reason label. **Allow once** → the tool call resolves to `{ fields: { username: … } }`. Activity shows the request and the reveal.
  3. A second request → **Deny** → `refused: denied`.
  4. `get_secret` for `password` → `refused: field`, and no sheet appears.
  5. With the vault locked, a request returns `{ status: "pending", request_id }`.
- [ ] **Step 2: Run** `npm run test:agents -w e2e`. Expected: PASS.
- [ ] **Step 3: Write the docs.**
  - `docs/agents.md`: *Letting an agent read a value* — what changes, in the words of spec §5.1 (the value leaves the vault's control for good; treat it as disclosed to the model provider); the threat table; the recommendation (prefer *Can use*); field scope and `totp`; the approval flow, that it needs an unlocked web app, that the email and the extension only notify (R6); expiry, the denial pause, the limits; `get_secret`; `GATEWAY_REVEAL` and `GATEWAY_REVEAL_PER_HOUR`; that a pending request is answered by the gateway process that made it. The sentence "There is no tool that returns a credential" becomes true for organisation agents only, and says so.
  - `SECURITY.md`: the *Can reveal, approval mode* row, and items 1, 5 and 6 of spec §6's list (the model sees values; more gateway code handles plaintext; an MCP client that auto-approves tools auto-approves `get_secret` — the approval inside Clane Vault is the control).
  - `docs/extension.md`: the notification and the `notifications` permission.
  - `CHANGELOG.md`: the feature, migration `20261117000000_agent_reveal`, "`GATEWAY_REVEAL` is `off` by default: nothing reads a value until the gateway's operator sets it".
- [ ] **Step 4: Run** `npm test`, `npm run typecheck`, and `npm run e2e` with agents off. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: Phase C acceptance (e2e) and docs"`

---

## Phase D — standing reveal (off unless the operator and every policy say otherwise)

### Task 22: Crypto, API and gateway — `agentReveal` in the record body, the standing path

**Files:**
- Modify: `packages/crypto/src/agents.ts`, `packages/crypto/src/records.ts`; Test: `packages/crypto/test/agents.test.ts`, `records.test.ts`
- Modify: `apps/api/src/routes/agentReveals.ts`; Test: `apps/api/test/agent-reveals.test.ts`
- Modify: `apps/gateway/src/apiClient.ts`, `apps/gateway/src/reveal.ts`, `apps/gateway/src/items.ts`; Test: `apps/gateway/test/reveal.test.ts`, `noPlaintext.test.ts`

**Interfaces:**
- Crypto: `export interface AgentReveal { v: 1; agents: string[]; fields: string[] }`; `export function validateAgentReveal(p: unknown, body: Pick<RecordBody, "type" | "fields" | "totpSecret">): AgentReveal` (unknown keys refused; `agents` 1–20 unique UUIDs; `fields` through `validateRevealFields`). `RecordBody.agentReveal?: AgentReveal`, validated in `validateV2` after `agentPolicy`; on a lenient read an invalid one is dropped, as `agentPolicy` is. A client from before this field drops it on save: standing reveal then stops (fails closed).
- API: `POST /agent/reveals/standing { recordId: uuid, fields: string[] }` (`requireAgent`) → `201 { ok: true }`. `409 reveal_off` unless `rules.reveal === "standing"` and the agent holds a `RecordAccess` row for the owner's live private record. Event `agent.reveal` (`recordId`, `meta { fields, app, standing: true }`). No schema change, so Phase D has no migration.
- Gateway `apiClient.ts`: `standingReveal(token: string, r: { recordId: string; fields: string[] }): Promise<{ ok: true } | { refused: "reveal_off" }>`.
- Gateway `requestReveal`: before the approval path, the **standing path** applies when all of these hold: `cfg.reveal === "standing"`; `sync.policy.reveal === "standing"`; the agent holds the record's key; the decrypted `body.agentReveal?.agents` includes the agent's id; every asked field is in `body.agentReveal.fields`. Then `standingReveal` is called first — only a `201` releases values — and `revealFieldsOf(body, fields)` is returned, held in `held` until written. If any condition fails, the approval path of Task 18 runs as before (so an item can have both).
- `items.ts`: `reveal` becomes `{ fields: string[]; approval: boolean }`; `approval: false` exactly when the standing path would apply to those fields.

- [ ] **Step 1: Write the failing tests:**
  - Crypto: a body with `agentReveal: { v: 1, agents: [uuid], fields: ["username"] }` round-trips `encryptRecordBody` → `decryptRecordBody` (`toEqual`); `fields: ["totpSecret"]`, an extra key, `agents: []` or a non-UUID agent → `normalizeRecordBody` throws; a stored invalid one is dropped on read.
  - API: with policy `standing` and a grant → 201 and one `agent.reveal` event with `standing: true`; with policy `approval` → `409 reveal_off`; without a grant row → `409 reveal_off`.
  - Gateway, `GATEWAY_REVEAL=standing` and sync policy `standing`: `get_secret` returns the value at once and the fake API saw `/agent/reveals/standing` and no `/agent/reveals`. Each of these alone sends it down the approval path instead (and, with no stub, to `reveal_off`): `GATEWAY_REVEAL=approval`; sync policy `approval`; the agent's id not in `agents`; a field outside `agentReveal.fields`. The API answering `409 reveal_off` → `reveal_off` and **no value** in the result.
  - `buildUpdate` (Task 12) leaves `agentReveal` byte-identical; `update_secret` has no input that reaches it.
  - `noPlaintext` runs a standing reveal.
- [ ] **Step 2: Run** the named files in the three packages. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `packages/crypto`, `apps/api`, `apps/gateway` and `apps/extension` (it reuses the body validation). Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Personal agents: standing reveal in the encrypted body, gated by GATEWAY_REVEAL=standing and every policy"`

### Task 23: Web and Phase D acceptance — the editor, e2e, docs

**Files:**
- Create: `apps/web/src/features/vault/AgentRevealEditor.tsx`
- Modify: `apps/web/src/features/vault/RecordEditor.tsx`, `RecordAgentsSection.tsx`
- Test: `apps/web/src/features/vault/AgentRevealEditor.test.tsx`
- Modify: `e2e/playwright.agents.config.ts` (`GATEWAY_REVEAL: "standing"`), `e2e/agents/personal.spec.ts`
- Modify: `docs/agents.md`, `SECURITY.md`, `docs/policies.md`, `CHANGELOG.md` (*Unreleased*), `deploy/client/README.md`

**Interfaces:**
- Consumes: Task 22; `grantAgent` (Task 8).
- `AgentRevealEditor`: a section of the record editor, *Reading without approval*, present only for the owner's Personal items and only when both `rules.reveal` and `gateway.reveal` are `standing`. Per verified personal agent: a switch and the field picker of Task 19. Turning a switch on needs the item's title typed exactly, under the §5.1 warning and the line *"The AI model can read these fields whenever it asks. Nobody is asked first."* On save the body gets `agentReveal`, and each listed agent that holds no key yet is granted one (`grantAgent`, with the attestation check). Leaving the section untouched keeps `agentReveal` byte for byte. `RecordAgentsSection` shows *Reads without approval* beside such an agent.

- [ ] **Step 1: Write the failing tests:** the section is absent when either setting is below `standing`; the switch stays off until the typed title matches; saving produces a body whose `agentReveal` is `{ v: 1, agents: [agentId], fields: ["username"] }` and one `agent-grants` call for an agent without a key; an untouched save leaves `JSON.stringify(body.agentReveal)` unchanged; a record-type change that removes a listed field is refused with the validator's message.
- [ ] **Step 2: Run** `npx vitest run src/features/vault/AgentRevealEditor.test.tsx` in `apps/web`. Expected: FAIL. Then implement and re-run with the typecheck. Expected: PASS.
- [ ] **Step 3: Extend the e2e test:** the admin sets *Reading values: Without approval*; the member turns *Reading without approval* on for "Echo" and "My helper" by typing the title; `get_secret { item: "personal/echo", fields: ["username"], reason: "e2e" }` resolves at once and **no approval sheet appears**; Activity shows the reveal. The admin sets the policy back to *With approval* → the same call opens the sheet again. Run `npm run test:agents -w e2e`. Expected: PASS (the Phase C steps too: `standing` on the gateway still serves approval).
- [ ] **Step 4: Write the docs.**
  - `docs/agents.md`: *Reading without approval* — that this mode gives up "the model never sees plaintext" with no person in the loop; the three switches that must all be on (`GATEWAY_REVEAL=standing`, `reveal: "standing"` in every organisation the person belongs to, the item's own setting inside its encrypted body); that an older app drops the setting on save; that it is the operator's decision whether a server offers it at all, and the default is that it does not (decision 3).
  - `SECURITY.md`: the *Items with standing reveal* row. `docs/policies.md`: the three values of `personalAgents.reveal`. `CHANGELOG.md`: the feature, "no migration". Deploy README: `GATEWAY_REVEAL=standing` and the warning.
- [ ] **Step 5: Run** `npm test`, `npm run typecheck`, `npm run e2e` with agents off; then **commit** `git commit -m "Personal agents: standing reveal editor, Phase D acceptance (e2e) and docs"`

---

## Self-review notes

- **Spec coverage.**
  - §3.1 → Task 2; §3.2 → Tasks 1, 3, 6, 7; §3.3 → Tasks 2, 3 (R2); §3.4 → Tasks 2, 4, 8 (R1); §3.5 → Tasks 4, 6, 8; §3.6 → Tasks 3, 5, 8; §3.7 → Tasks 4, 5 (R3; the owner's key change is the `owner_key_changed` test in Task 6); §3.8 → Tasks 2, 3, 5, 8.
  - §4.1–§4.3 → Tasks 10, 14; §4.4 → Tasks 11, 12, 14; §4.5 → Tasks 10, 12; §4.6 → Task 13.
  - §5.2 → Task 16; §5.3 → Tasks 16–20 (R5, R6); §5.4 → Tasks 12, 13, 18; §5.5 → Tasks 17, 18; §5.6 → Tasks 22, 23.
  - §6 → the docs steps of Tasks 9, 15, 21, 23. §7's KMS note → Task 9.
  - §8, line by line: no membership / pickers → Task 3; grant refusals → Task 4; swapped owner key → Tasks 4, 6; attestation with another owner key → Tasks 1, 7; the `s1.` guard → Task 8; deposit signatures and `/sync` → Tasks 10, 14; `not_writable`, restore, policy bytes → Tasks 11, 12, 14; `GATEWAY_REVEAL=off` → Task 18; changed `requestPublicKey`, approved fields only, no `totpSecret` → Tasks 16, 19; no plaintext in logs → Tasks 12, 13, 18, 22; suspension and admin log → Tasks 3, 4, 9; two tools for organisation agents → Tasks 6, 12, 18.
  - §9 → *Resolved decisions*.
- **Out of scope, on purpose:** web push to a closed PWA (spec §5.3 calls it a follow-up); record-key rotation on removing a grant (the open follow-up in `docs/sharing.md`); a batch grant route (the multi-select calls the single route); any approval surface outside the web app (R6).
- **Names used across tasks.**
  - Crypto: `PersonalIds`, `personalAgentKeyMessage`, `personalAgentPrivateKeyAad`, `personalAgentRecordAad`, `signGatewayMessage` / `verifyGatewayMessage`, `signPersonalAgentKey` / `verifyPersonalAgentAttestation`, `sealPersonalAgentRecordKey` / `openPersonalAgentRecordKey`, `sha256B64`, `agentDepositMessage`, `agentUpdateMessage`, `agentDepositOwnerAad`, `sealDepositKeyToOwner` / `openDepositKey`, `REVEAL_REF`, `validateRevealFields`, `revealFieldsOf`, `RevealStub`, `sealRevealStub` / `openRevealStub`, `agentRevealRequestMessage`, `agentRevealAad`, `sealReveal` / `openReveal`, `AgentReveal`, `validateAgentReveal`.
  - API: `personalAgentRules`, `strictest`, `PersonalAgentRules`, `RevealMode`, `assertPersonalAgentSlot`, `logLifecycle`, `gatewaySigned`, `createPersonalAgentKey`, `personalAgentSync`, `revokePersonalAgent`, `revokePersonalAgentsOf`, `PersonalRotation`, `connectedApp`, `sweepAgentWrites`, `agentRevealEmail`, `revealMode`, `createTestPersonalAgent`.
  - Gateway: `wrapPersonalAgentKey` / `unwrapPersonalAgentKey`, `Identity.signPersonal` / `signMessage`, `PersonalAgentSync`, `isPersonal`, `OwnerKeyChanged`, `buildDeposit`, `buildUpdate`, `SaveInput`, `pointerValue`, `WriteRefused`, `PendingReveals`, `requestReveal`, `resumeReveal`, `RevealResult`.
  - Web: `PERSONAL_SLOT`, `allGatewayPins`, `personalGatewayPinStatus`, `verifyPersonalAgentKey`, `MyAgent`, `grantAgent`, `revokeAgentGrant`, `openDeposit`, `OpenedDeposit`, `checkRequest`, `RevealRequest`.
