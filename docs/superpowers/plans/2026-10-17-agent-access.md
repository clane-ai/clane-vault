# Agent access through a hosted gateway (Phases 1 and 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cloud AI agents use credentials from team folders through one remote MCP server (`list_secrets`, `http_request`), never seeing a value. Agents are Use-only organisation members whose key is born, KMS-wrapped and used only in a new gateway service.

**Architecture:** An agent is a `User` row with `kind = agent` plus an `Agent` row. Folder keys, groups, shares and pinning reach it unchanged; a server-side cap holds it to `use`. A new stateless service, `apps/gateway`, generates the agent's X25519 key, signs it with its pinned Ed25519 identity and wraps it under a KEK (`file:`, `aws-kms:`, `gcp-kms:`). The wrapped key is stored in the API database. Per MCP call the gateway reads the agent's ciphertext from the API's new `/agent/*` routes, opens the one record named, and makes the outbound HTTPS call itself (allowlist, SSRF pinning, redirect rules, strip-then-inject, size and time caps). It returns the response with every form of the secret scrubbed. The API is also the OAuth 2.1 authorization server, and issues ES256 agent tokens that no human route accepts. Static `cvat_` tokens come first; OAuth comes late in the plan.

**Tech Stack:** Fastify 5, Prisma 6 / Postgres, zod, jose (ES256, JWKS), vitest (API against real Postgres via `test/helpers.ts`); new `apps/gateway`: `node:http`, `@modelcontextprotocol/sdk` 1.32 (Streamable HTTP server transport), `undici` 7, `@clane-vault/crypto`, `@aws-sdk/client-kms`, esbuild bundle on distroless Node 22; web: React, TanStack Query, msw; Playwright e2e.

**Spec:** `docs/design/2026-10-17-agent-access.md` (§1–§5, §7–§10; §6 Phases 3–5 are out of scope). §11 rulings, approved: wrapped agent keys in the API database (gateway stateless); OAuth consent by owners/admins only; disclose now, enclave later; cache TTL default 60 s; `GATEWAY_ALLOW_PRIVATE_CIDRS` exists, off by default, never set on hosted; `agentLimit` Team 3 / Business 10 / self-hosted unlimited; add-on price out of scope. Query-string injection ships with the weaker label; ES256 with JWKS.

## Global Constraints

- Agent features are off unless `GATEWAY_INTERNAL_URL` is set on the API. Then `GATEWAY_PUBLIC_URL`, `GATEWAY_API_TOKEN` (32+ chars) and `AGENT_TOKEN_PRIVATE_KEY` are required too, or `loadConfig` throws. Off means every agent, `/agent/*` and `/oauth/*` route is 404. With agents off and `BILLING_MODE=off`, the existing e2e suite passes unchanged.
- An agent's `User`: `kind agent`, `email` `agent+<userId>@agents.invalid`, `authHash`/`kdfSalt`/`wrappedUserKey`/`wrappedPrivateKey` `""`, `kdfParams {}`, `publicKey` = the agent key, `status active` until revoked (then `disabled`). Its `Membership` is `role member`, `status invited` until verified, then `active`. One `MembershipKey`: the agent's `publicKey`, `wrappedPrivateKey ""`, `userKeyGen 1`, `state current`.
- The API never holds an agent private key in any usable form. `Agent.wrappedPrivateKey` is `k1.<kekId>.<wrappedDek>.<v1. envelope>`. Inside the v1 envelope the private key's AAD is `agent-private-key:<orgId>:<agentId>:<publicKey>`. `kekId` and `wrappedDek` contain no `.`.
- Attestation: `g1.<gatewayKeyId>.<sig>`, an Ed25519 signature over the UTF-8 of `agent-key:<orgId>:<agentId>:<publicKey>`. Base64url throughout, as in `@clane-vault/crypto`.
- Agents hold `use` only. An explicit request for more gets `400 { error: "agent_use_only" }`; group grants are capped silently. Agents are not seats and add no pooled storage.
- Agent access token: ES256 JWT with claims `scope: "agent"`, `sub` (agent user id), `org`, `aud` (= `GATEWAY_PUBLIC_URL`), `iss` (= API `PUBLIC_URL`), `jti`, `grant` (an `AgentToken.id` or `AgentGrant.id`), `exp` 15 min. `kid` is the JWK thumbprint. Refresh tokens: `<grantId>.<secret>` (`newRefreshToken`), 30 days, rotating, hash only.
- Static token: `cvat_<AgentToken.id>_<base64url 32 random bytes>`. It is shown once; only `hashToken(token)` is kept.
- Error bodies follow `reply.code(N).send({ error: "<snake>" , ...extra })`. Codes used:
  - `400 agent_use_only`, `400 user_not_active`
  - `402 { error: "agent_limit", used, allowed }`
  - `401 unauthorized`, `403 agent_expired`, `403 agent_unverified`
  - `409 stale_key`, `409 is_agent`
  - `503 gateway_unavailable`, `503 gateway_identity_changed`
  - The OAuth endpoints use RFC 6749 bodies, which have the same `error` key: `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_target`.
- Gateway env and defaults:
  - `API_URL` (the API's origin plus base path)
  - `GATEWAY_API_TOKEN`
  - `PUBLIC_URL` (e.g. `https://vault.clane.ai/mcp`; the MCP route is its path)
  - `GATEWAY_KEK` = `aws-kms:<key arn>` | `gcp-kms:<resource name>` | `file:<path to 32 random bytes>`
  - `GATEWAY_IDENTITY_KEY_FILE`
  - `GATEWAY_CACHE_TTL_SECONDS` 60 (`0` = no cache)
  - `GATEWAY_AGENT_RATE_PER_MINUTE` 60
  - `GATEWAY_MAX_RESPONSE_BYTES` 4194304
  - `GATEWAY_UPSTREAM_TIMEOUT_MS` 30000
  - `GATEWAY_ALLOW_PRIVATE_CIDRS` empty
  - `PORT` 3002 (public: `/mcp` and metadata); `INTERNAL_PORT` 3003 (`/internal/*` only); `TRUST_PROXY` 0 (hop count, API semantics)
- No tool ever returns a credential. There is no `get_secret`, and `list_secrets` never returns a field of a secret kind (`SECRET_KINDS`) or the policy's secret. Scrub marker: `[clane:redacted]`.
- No value is ever passed to a logger, an error message, a stack trace or a response, other than as the injected header or query value. Gateway logs and `agent.*` events carry `recordId`, `host`, `method`, `reason`, `truncated` only: no paths, query strings or bodies.
- Plans: `agentLimit` is personal 0, Team 3 (also during the Business trial, like seats), Business 10, `unlimited` null. Live agents are those with `revokedAt` null. `Feature` gains `agentApprovals` and `agentPathPolicy` (both Business). A downgrade blocks new agents only.
- Restricted-credential warning, shown above the confirm button every time a human shares to an agent, never dismissable, exact copy:
  - *"Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent."*
  - followed by *"Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted."*
- `apps/api` gains no dependency. Neither `apps/api` nor `apps/web` imports from `apps/gateway`. Both talk to it over HTTP only.
- Migration name: `20261026000000_agent_access`.

## Review Focus

1. **An admin uses the People page routes on an agent.** `DELETE /admin/members/:id`, disable, enable, reset-2fa or a role change would offboard it but leave a live wrapped key and live tokens. Expected: every such route answers `409 { error: "is_agent" }`, and agents are revoked only through `DELETE /admin/agents/:id`. *Test in Task 3.*
2. **Agents quietly change org numbers.** Expected: agents never count as seats in hosted mode, never raise the pooled attachment quota, and never appear in the People page, the risk dashboard, password health or the provisioning/onboarding lists. *Tests in Task 3.*
3. **Gateway down or replaced when the API starts or when an admin creates an agent.** Expected: the API still starts when the gateway is unreachable (it logs a warning and pins the identity on first contact). Creating an agent returns `503 gateway_unavailable` and creates nothing. A changed gateway identity stops the API at start, or refuses creation with `503 gateway_identity_changed`, unless `GATEWAY_ACCEPT_NEW_IDENTITY=true`. Existing agents' ciphertext is untouched. *Tests in Task 4.*
4. **Editing a record that has an `agentPolicy`.** Expected: a save that doesn't touch the policy keeps it, byte for byte. Changing the record type so that `secret` names a field the type no longer has is refused by `validate()`, and the editor says why instead of losing data. An older client that doesn't know the field drops it on save (`validateV2` rebuilds the body): the agent then gets `no_policy`, which fails closed, and `docs/agents.md` says so. *Tests in Task 1 and Task 15.*
5. **Hostile upstream bodies.** Expected:
   - A secret echoed across chunk boundaries is still scrubbed (the scrub runs on the whole capped body, not per chunk).
   - A gzip bomb is cut at `GATEWAY_MAX_RESPONSE_BYTES` of *decompressed* bytes and marked `truncated: true`.
   - A slow-drip response ends at `GATEWAY_UPSTREAM_TIMEOUT_MS` total with `reason: "timeout"` and no partial secret.

   *Tests in Task 10.*

---

### Task 1: Crypto — agent attestation, envelope AADs, usage policy in the record body

**Files:**
- Create: `packages/crypto/src/agents.ts`; export it from `packages/crypto/src/index.ts`
- Modify: `packages/crypto/src/records.ts`: add `agentPolicy` to `RecordBody` (L18-22) and validate it in `validateV2` (L91-110), after `fields`, so `field:<id>` can be checked
- Test: `packages/crypto/test/agents.test.ts`, `packages/crypto/test/records.test.ts`

**Interfaces:**
- Produces (in `agents.ts`):
  ```ts
  export const AGENT_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
  export type AgentMethod = (typeof AGENT_METHODS)[number];
  export type AgentInject = { kind: "bearer" } | { kind: "basic" } | { kind: "header"; name: string; prefix?: string } | { kind: "query"; name: string };
  export interface AgentPolicy { v: 1; hosts: string[]; inject: AgentInject; secret?: string; methods?: AgentMethod[]; paths?: string[]; approval?: boolean }
  /** Throws Error with a readable message; returns the cleaned policy (hosts lower-cased). */
  export function validateAgentPolicy(p: unknown, body: Pick<RecordBody, "type" | "fields">): AgentPolicy;
  /** apiKey → "data.secret"; login, server, database → "password"; any other type → null. */
  export function defaultSecretRef(type: RecordType): string | null;
  /** The value the policy injects, or null when the field is empty or no ref applies. */
  export function agentSecretOf(body: RecordBody): string | null;
  /** Basic auth username: body.username ?? body.data?.keyId ?? "". */
  export function basicUsername(body: RecordBody): string;
  export const agentKeyMessage: (orgId: string, agentId: string, publicKeyB64: string) => string; // "agent-key:<org>:<agent>:<pub>"
  export const agentPrivateKeyAad: (orgId: string, agentId: string, publicKeyB64: string) => string; // "agent-private-key:<org>:<agent>:<pub>"
  /** Ed25519: raw public key, pkcs8 private key. */
  export function generateIdentityKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  /** First 16 chars of base64url(SHA-256(raw public key)). */
  export function gatewayKeyId(publicKeyRaw: Uint8Array): Promise<string>;
  export function signAgentKey(identityPrivatePkcs8: Uint8Array, keyId: string, ids: { orgId: string; agentId: string; publicKey: string }): Promise<string>; // "g1.<keyId>.<sig>"
  export function verifyAgentAttestation(att: string, ids: { orgId: string; agentId: string; publicKey: string }, identity: { keyId: string; publicKey: string }): Promise<boolean>;
  ```
- Policy rules (spec §5.1):
  - Unknown keys in the policy or in `inject` are refused.
  - `hosts`: 1–32 entries, lower-cased, each matching `^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+(:\d{1,5})?$`, port 1–65535. A host whose last label is all digits (an IPv4 literal) is refused: the regex alone accepts `10.0.0.5`.
  - `header.name`: `^[A-Za-z0-9-]{1,64}$`, and not `host`, `content-length`, `transfer-encoding`, `connection`, `cookie` or `proxy-authorization`. `prefix`: at most 32 printable ASCII characters, no CR or LF.
  - `query.name`: `^[A-Za-z0-9_.-]{1,64}$`.
  - `secret`: `"password"` (the type's core fields include it), `"data.<key>"` (in `dataKeysOf(type)`) or `"field:<id>"` (an id in `body.fields`). Without `secret`, `defaultSecretRef(type)` must be non-null.
  - `methods`: a subset of `AGENT_METHODS`. `paths`: at most 32, each starting with `/`, at most 256 characters.
  - `approval`: boolean.

- [ ] **Step 1: Write the failing tests** in `agents.test.ts`:
  ```ts
  const ok = { v: 1, hosts: ["API.Stripe.com", "*.github.com:8443"], inject: { kind: "bearer" } };
  expect(validateAgentPolicy(ok, { type: "apiKey" }).hosts).toEqual(["api.stripe.com", "*.github.com:8443"]);
  for (const bad of [{ ...ok, extra: 1 }, { ...ok, hosts: [] }, { ...ok, hosts: ["10.0.0.5"] }, { ...ok, hosts: ["a.b:70000"] }, { ...ok, hosts: Array(33).fill("a.b") },
    { ...ok, inject: { kind: "header", name: "Host" } }, { ...ok, inject: { kind: "header", name: "X-Key", prefix: "a\r\n" } }, { ...ok, inject: { kind: "bearer", x: 1 } },
    { ...ok, paths: ["v1"] }, { ...ok, methods: ["TRACE"] }, { ...ok, secret: "data.nope" }])
    expect(() => validateAgentPolicy(bad, { type: "apiKey" })).toThrow();
  expect(() => validateAgentPolicy(ok, { type: "note" })).toThrow(); // no default secret for a note
  expect(validateAgentPolicy({ ...ok, secret: "field:f1" }, { type: "note", fields: [{ id: "f1", label: "Key", kind: "secret", value: "x" }] }).secret).toBe("field:f1");
  expect(agentSecretOf({ v: 2, type: "apiKey", title: "S", data: { secret: "sk_test_1" }, agentPolicy: validateAgentPolicy(ok, { type: "apiKey" }) })).toBe("sk_test_1");
  expect(basicUsername({ v: 2, type: "apiKey", title: "S", data: { keyId: "kid" } })).toBe("kid");
  const id = await generateIdentityKeyPair(); const keyId = await gatewayKeyId(id.publicKey);
  const ids = { orgId: "o", agentId: "a", publicKey: "pub" };
  const att = await signAgentKey(id.privateKey, keyId, ids);
  expect(att.startsWith(`g1.${keyId}.`)).toBe(true);
  const identity = { keyId, publicKey: b64url.encode(id.publicKey) };
  expect(await verifyAgentAttestation(att, ids, identity)).toBe(true);
  expect(await verifyAgentAttestation(att, { ...ids, publicKey: "other" }, identity)).toBe(false); // tampered key (spec §10)
  expect(await verifyAgentAttestation(att.replace(keyId, "x".repeat(16)), ids, identity)).toBe(false);
  ```
  In `records.test.ts`:
  - A v2 apiKey body with a valid `agentPolicy` round-trips `encryptRecordBody` → `decryptRecordBody` unchanged, `toEqual` (Review Focus 4).
  - The same body with `type` changed to `note` (`secret` defaulted from apiKey) → `normalizeRecordBody` throws.
  - A body with an invalid policy → `normalizeRecordBody` throws.
- [ ] **Step 2: Run** `npx vitest run test/agents.test.ts test/records.test.ts` in `packages/crypto`. Expected: FAIL, `agents.js` not found.
- [ ] **Step 3: Implement** `agents.ts`, using WebCrypto `Ed25519` (`sign`/`verify`; `importKey` `raw` for public, `pkcs8` for private), and the `RecordBody.agentPolicy?: AgentPolicy` field validated in `validateV2`.
- [ ] **Step 4: Run** `npx vitest run` and `npx tsc --noEmit -p tsconfig.json` in `packages/crypto`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: attestation, envelope AADs and usage policy in the record body (crypto)"`

### Task 2: API — schema, migration, agent config, `agentLimit`

**Files:**
- Modify: `apps/api/prisma/schema.prisma`:
  - Add the spec §4.1 models, written one field per line (the spec's `;`-separated one-liners are not valid Prisma).
  - `User` gains `kind UserKind @default(person)`, `agent Agent?` and `@@index([kind])`.
  - `Organization` gains `agents Agent[]`.
  - `AgentGrant` gains `refreshGen Int @default(0)`, which refresh-reuse detection needs and the spec omits. (Built as generation-based refresh secrets in Task 12a round 2, replacing the first draft's `prevRefreshHash`; spec §13.)
  - `AgentOAuthCode` gains `@@index([expiresAt])`.
- Create: `apps/api/prisma/migrations/20261026000000_agent_access/migration.sql` (Prisma's SQL; `kind` defaults to `person`, so existing rows backfill)
- Modify: `apps/api/src/config.ts`: the env schema (L9-67), `Config` (L99-150) and `loadConfig` (L250-272)
- Modify: `apps/api/src/lib/plans.ts`: `Feature`, `FEATURES`, `Entitlements`, `UNLIMITED`/`TEAM`/`BUSINESS`, `getEntitlements`, `getPersonalEntitlements`
- Modify: `apps/api/test/helpers.ts` `resetDb` (L14): add `"AgentOAuthClient","AgentOAuthCode","GatewayIdentity"` to the TRUNCATE (the `Agent*` rows cascade from `User`)
- Test: `apps/api/test/plans-unit.test.ts`, `apps/api/test/agents-unit.test.ts`

**Interfaces:**
- Produces, in `config.ts`:
  ```ts
  export interface AgentConfig { gatewayInternalUrl: string; gatewayPublicUrl: string; gatewayApiToken: string; tokenPrivateKeyPem: string; acceptNewGatewayIdentity: boolean }
  // Config gains: agents?: AgentConfig   (absent = agent features off)
  ```
  - Env: `GATEWAY_INTERNAL_URL`, `GATEWAY_PUBLIC_URL`, `GATEWAY_API_TOKEN` (min 32), `AGENT_TOKEN_PRIVATE_KEY` and `GATEWAY_ACCEPT_NEW_IDENTITY` (`true|false`, default false).
  - `AGENT_TOKEN_PRIVATE_KEY` is a PKCS#8 PEM for P-256; a literal `\n` in the env value is turned into a newline.
  - Setting any of the first four without the rest throws `GATEWAY_INTERNAL_URL, GATEWAY_PUBLIC_URL, GATEWAY_API_TOKEN and AGENT_TOKEN_PRIVATE_KEY go together (docs/agents.md)`.
- Produces, in `plans.ts`:
  - `Feature` adds `"agentApprovals" | "agentPathPolicy"`.
  - `Entitlements` adds `agentLimit: number | null`, with `UNLIMITED` null, `TEAM` 3, `BUSINESS` 10 and personal 0.
  - In trial, `agentLimit` is `TEAM.agentLimit`.
- Produces: the Prisma models `Agent`, `AgentToken`, `AgentOAuthClient`, `AgentOAuthCode`, `AgentGrant` and `GatewayIdentity`, and the enum `UserKind`, with the field names of spec §4.1.

- [ ] **Step 1: Write the failing tests.**
  - `plans-unit.test.ts`:
    - `getEntitlements(on, team).agentLimit` is 3, Business is 10, `off` is null, `getPersonalEntitlements(on).agentLimit` is 0, trial is 3.
    - `team.features.agentApprovals` and `team.features.agentPathPolicy` are false, and both are true on Business.
    - The existing "every Team feature is off" assertions still hold.
  - `agents-unit.test.ts`:
    - `loadConfig({ ...baseEnv })` has no `agents`.
    - With all four variables, `agents.gatewayPublicUrl` is the value given.
    - With only `GATEWAY_INTERNAL_URL`, it throws `/go together/`.
    - A `GATEWAY_API_TOKEN` of 31 characters throws.
- [ ] **Step 2: Run** `npx vitest run test/plans-unit.test.ts test/agents-unit.test.ts` in `apps/api`. Expected: FAIL.
- [ ] **Step 3: Implement** the schema, migration, config and plans changes.
- [ ] **Step 4: Run** the two files, then `npx prisma migrate diff --from-migrations prisma/migrations --to-schema-datamodel prisma/schema.prisma --shadow-database-url "$TEST_DATABASE_URL" --exit-code`. Expected: PASS; exit 0, no drift.
- [ ] **Step 5: Commit** `git commit -m "Agent access: schema, migration 20261026000000_agent_access, agent config, agentLimit"`

### Task 3: API — agent members in the existing paths (Use-only cap, exclusions)

**Files:**
- Create: `apps/api/src/lib/agents.ts`
- Create: `apps/api/test/agentHelpers.ts`
- Modify:
  - `lib/seats.ts` `seatEmails` (L15-23): add `AND u.kind = 'person'` to both `Membership` unions.
  - `lib/attachments/quota.ts:80`: count `user: { kind: "person" }` only.
  - `routes/admin.ts`:
    - `/people` (L103): memberships of `user: { kind: "person" }`.
    - `target()` (L145-152): select `user.kind`; an agent returns `"agent"`. `refuse` maps `"agent"` to `[409, "is_agent"]`, which covers disable, enable, reset-2fa, `GET`/`DELETE`/`PATCH /members/:userId`.
  - `routes/orgs.ts` `POST /org/transfer` (L223): an agent target → `409 is_agent`.
  - `routes/auth.ts` `POST /login` (L250): `user.kind === "agent"` takes the same dummy-verify path → `401 invalid_credentials`.
  - `routes/users.ts`: select and return `kind`.
  - `routes/sync.ts`: folder `members[].kind` (add `kind` to the `user` select, L39).
  - `lib/groups.ts`:
    - `recomputeMember` (L37-51): `eff` is passed through `capForAgent` before the compare.
    - `pendingGroupAccess` (L84-108): each item gains `kind`.
  - `routes/folders.ts` `POST /folders/:id/members` (L91) and `PATCH /folders/:id/members/:userId` (L122), and `routes/records.ts` `POST /records/:id/shares` (L202) and `PATCH /records/:id/shares/:userId` (L227): an explicit permission above `use` for an agent → `400 agent_use_only`.
  - `routes/groups.ts` `POST /folders/:id/group-access` (L146): the row it creates uses `capForAgent` (silent cap).
  - Lists that must show people only (`user: { kind: "person" }`): `routes/risk.ts:80-81`, `routes/passwordHealth.ts:26`, `routes/provisioning.ts:63,65,226,309,311`.
  - `folderSuccessor` (`lib/orgs.ts:86`) already skips `use` holders: no change.
- Test: `apps/api/test/agents-members.test.ts`

**Interfaces:**
- Produces, in `lib/agents.ts`:
  ```ts
  export const agentEmail = (userId: string) => `agent+${userId}@agents.invalid`;
  export async function isAgentUser(db: Db, userId: string): Promise<boolean>;
  /** "use" for an agent user, `permission` unchanged for a person. */
  export async function capForAgent(db: Db, userId: string, permission: Permission): Promise<Permission>;
  ```
- Produces, in `test/agentHelpers.ts` (used by every later API task):
  ```ts
  /** Inserts the rows enrolment makes (§4.1), with a real X25519 pair; verified → membership active. */
  export async function createTestAgent(t: { prisma: PrismaClient }, o: { orgId: string; createdById: string; verified?: boolean; expiresAt?: Date; name?: string }):
    Promise<{ id: string; publicKey: string; privateKey: Uint8Array }>;
  ```

- [ ] **Step 1: Write the failing tests**, with an owner, a member and agent A (verified), plus agent B (unverified):
  - `GET /users` lists A with `kind: "agent"` and not B. `GET /group-access/pending` never lists B. A is listed with `kind: "agent"` once it is in a group shared with a folder the caller owns.
  - Adding B to a folder: `POST /folders/:id/members` → `400 user_not_active`.
  - Adding A with `edit` or `view` → `400 agent_use_only`; with `use` → 201. `PATCH` of A's folder member and of a record share to `view` → `400 agent_use_only`. `POST /records/:id/shares` to A with `view` → `400 agent_use_only`; with `use` → 201.
  - A in a group with `edit` on a folder, then approved through `POST /folders/:id/group-access` → A's `FolderMember.permission` is `use`. A `recomputeMember` after raising the group to `edit` keeps `use`.
  - Hosted (`billingMode: "hosted"`): `seatsUsed` is the same before and after creating A and B (Review Focus 2).
  - The pooled storage quota (`checkQuota` for an org charge) is the same before and after creating A (Review Focus 2).
  - `GET /admin/people` doesn't list A or B. A doesn't appear in `GET /admin/risk/members` or in the password-health member list.
  - `POST /admin/users/:A/disable`, `/enable`, `/reset-2fa`, `DELETE /admin/members/:A` and `PATCH /admin/members/:A { role: "admin" }` each → `409 is_agent`, and A's membership is unchanged. `POST /org/transfer` to A → `409 is_agent` (Review Focus 1).
  - `POST /auth/login` with A's email → `401 invalid_credentials`.
- [ ] **Step 2: Run** `npx vitest run test/agents-members.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** `lib/agents.ts`, the helper and the changes listed.
- [ ] **Step 4: Run** the new file and `npx vitest run test/sharing.test.ts test/groups.test.ts test/admin.test.ts test/plans-seats.test.ts test/risk.test.ts test/provisioning.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: agents as Use-only members; kept out of seats, storage, People, risk and health"`

### Task 4: API — gateway client, identity pin, create / list / verify / update agents

**Files:**
- Create: `apps/api/src/lib/gateway.ts`
- Create: `apps/api/src/routes/agents.ts`
- Modify: `apps/api/src/app.ts`:
  - When `opts.config.agents` is set, decorate `app.gateway`, register `agentAdminRoutes` (prefix `/admin/agents`, `preHandler: [requireAuth, orgAdmin]`) and register `orgAgentRoutes`.
  - The error handler maps `AgentLimitError` → `402 { error: "agent_limit", used, allowed }` and `GatewayUnavailable` → `503 gateway_unavailable`.
- Modify: `apps/api/src/server.ts` (after the server-secret check, L16-22):
  - When agents are on, `pinGatewayIdentity(prisma, await client.health(), { accept })`.
  - `GatewayIdentityChanged` → `console.error` with event `gateway_identity_changed` and `process.exit(1)`.
  - `GatewayUnavailable` → a warning line, and start anyway.
- Modify: `apps/api/src/lib/agents.ts`: add the slot functions.
- Modify: `apps/api/src/routes/plan.ts`: add `agents: { used, allowed }`.
- Create: `apps/api/test/fakeGateway.ts`
- Test: `apps/api/test/agents-admin.test.ts`

**Interfaces:**
- Consumes: `capForAgent`, `agentEmail`, `createTestAgent` (Task 3); `agentLimit` (Task 2); `signAgentKey`, `generateIdentityKeyPair`, `gatewayKeyId`, `verifyAgentAttestation`, `generateKeyPair` (Task 1, tests only).
- Produces, in `lib/gateway.ts`:
  ```ts
  export interface GatewayIdentityInfo { keyId: string; publicKey: string }
  export interface AgentKeyResult { publicKey: string; wrappedPrivateKey: string; kekId: string; attestation: string }
  export class GatewayUnavailable extends Error {}
  export class GatewayIdentityChanged extends Error { constructor(public pinned: GatewayIdentityInfo, public seen: GatewayIdentityInfo) }
  export interface GatewayClient { health(): Promise<GatewayIdentityInfo>; createAgentKey(ids: { agentId: string; orgId: string }): Promise<AgentKeyResult>; dropAgent(agentId: string): Promise<void> }
  export function gatewayClient(cfg: AgentConfig, fetchImpl?: typeof fetch): GatewayClient; // 5 s timeout; non-2xx or network error → GatewayUnavailable
  /** First sight creates the row; same → "ok"; different → throws GatewayIdentityChanged unless accept (then updates). */
  export async function pinGatewayIdentity(db: Db, seen: GatewayIdentityInfo, opts: { accept: boolean }): Promise<"created" | "ok" | "accepted">;
  ```
- Produces, in `lib/agents.ts`:
  ```ts
  export class AgentLimitError extends Error { constructor(public used: number, public allowed: number) }
  export async function liveAgents(db: Db, orgId: string): Promise<number>; // revokedAt null
  /** lockSeats(tx, cfg, orgId) then count; throws AgentLimitError. No-op with billing off. */
  export async function assertAgentSlot(tx: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<void>;
  ```
- Produces, routes:
  - `POST /admin/agents` with `{ name: displayName, expiresAt?: ISO string in the future | null }`:
    1. `assertAgentSlot` outside any transaction, as a fast refusal.
    2. `ensureIdentity()`: `health` → `pinGatewayIdentity`.
    3. `createAgentKey({ agentId: <new uuid>, orgId })`.
    4. One transaction: `assertAgentSlot` again, then the `User`, `Membership`, `MembershipKey` and `Agent` rows.
    5. `201 { id, name, publicKey, attestation, gateway: { keyId, publicKey } }`.
    6. Event `agent.create` (`targetUserId`, `meta.gatewayKeyId`).

    The spec's `fingerprint` fields are left out: the browser computes both itself (`fingerprintOf`), and the API can't load `@clane-vault/crypto` at runtime.
  - `GET /admin/agents` → `{ agents: AgentView[] }` with
    ```ts
    AgentView = { id, name, status: "awaiting_verification" | "active" | "expired" | "revoked", publicKey, attestation, expiresAt, lastUsedAt,
      createdAt, verifiedAt, folders: { id: string }[], groups: { id: string; name: string }[], tokens: [], grants: [] }
    ```
    `tokens` and `grants` are filled in Tasks 5 and 12.
  - `POST /admin/agents/:id/verify { publicKey }`:
    - `≠ MembershipKey.publicKey` → `409 stale_key`, nothing changed.
    - Otherwise set `verifiedById`, `verifiedAt` and `Membership.status active`; event `agent.verify`.
  - `PATCH /admin/agents/:id { name?, expiresAt? (nullable) }` → event `agent.update`.
  - `GET /org/agents/gateway` (`requireAuth` + `orgRequired`) → `{ url: cfg.agents.gatewayPublicUrl, identityKeyId, identityPublicKey }` from the `GatewayIdentity` row. With no row yet, it calls `ensureIdentity()`; unreachable → `503 gateway_unavailable`.
  - Every `/admin/agents/:id…` route resolves the agent within `req.org`; an agent elsewhere → `404 not_found`.
- Produces, `test/fakeGateway.ts`:
  ```ts
  export async function startFakeGateway(o?: { down?: boolean }): Promise<{ url: string; token: string; identity: GatewayIdentityInfo; setDown(d: boolean): void; rotateIdentity(): Promise<void>;
    created: { agentId: string; orgId: string }[]; dropped: string[]; close(): Promise<void> }>;
  ```
  It is a `node:http` server on port 0, checks `X-Gateway-Token`, and answers `/internal/health`, `POST /internal/agents` (a real key pair and a real `signAgentKey` attestation; the envelope is the opaque string `k1.file-test.<x>.v1.<y>`) and `DELETE /internal/agents/:id`.

- [ ] **Step 1: Write the failing tests** (`makeTestApp({ agents: { gatewayInternalUrl: fake.url, gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: fake.token, tokenPrivateKeyPem, acceptNewGatewayIdentity: false } })`):
  - **Gateway down.** `POST /admin/agents` → `503 gateway_unavailable`, and `prisma.agent.count()`, `user.count({ where: { kind: "agent" } })` and the membership count are unchanged. With agents configured and the gateway down, `buildApp` still resolves (Review Focus 3).
  - **Gateway up.**
    - 201. The `Agent` row has `wrappedPrivateKey` starting `k1.` and `attestation` starting `g1.`.
    - `MembershipKey.wrappedPrivateKey === ""`, the membership is `invited`, and `User.email` is `agent+<id>@agents.invalid`.
    - `verifyAgentAttestation(body.attestation, { orgId, agentId: body.id, publicKey: body.publicKey }, body.gateway)` is true.
    - One `agent.create` event, whose `meta.gatewayKeyId` equals `fake.identity.keyId`.
  - **Verify.** With another key → `409 stale_key`, still `invited`. With the right key → 200, `active`, `agent.verify` logged.
  - **Identity changed.** After `fake.rotateIdentity()`, `POST /admin/agents` → `503 gateway_identity_changed`. `pinGatewayIdentity` with the new identity and `accept: true` → `"accepted"` (Review Focus 3).
  - **Members.** A member calling `POST /admin/agents` → 403.
  - **Lists.** `GET /admin/agents` shows the status per row. An expired agent (`createTestAgent` with `expiresAt` in the past) reads `expired`.
  - **Hosted limits.** Team org with billing hosted: 3 agents succeed, and the 4th → `402 { error: "agent_limit", used: 3, allowed: 3 }`. `GET /org/plan` has `agents: { used: 3, allowed: 3 }`. Billing off: 12 agents all 201.
  - **Agents off.** `makeTestApp({})` → `GET /admin/agents` is 404.
- [ ] **Step 2: Run** `npx vitest run test/agents-admin.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** `lib/gateway.ts`, `routes/agents.ts`, the slot functions, the error mapping, the start-up pin and the plan field.
- [ ] **Step 4: Run** the new file and `test/plans.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: enrolment through the gateway, identity pin, verify, agent_limit"`

### Task 5: API — ES256 agent tokens, `requireAgent`, static tokens, `/agent/sync`, `/agent/events`

**Files:**
- Modify: `apps/api/src/lib/tokens.ts` (add the agent token functions; `verifyToken` stays HS256-only)
- Create: `apps/api/src/plugins/agent.ts` (`registerAgent`, called in `buildApp` after `registerOrg` when agents are on)
- Create: `apps/api/src/lib/sync.ts`: move the `/sync` handler body (`routes/sync.ts` L26-150) into `syncFor`; `routes/sync.ts` becomes the query parsing plus a call
- Create: `apps/api/src/routes/agentApi.ts` (`/agent/sync`, `/agent/events`)
- Create: `apps/api/src/routes/oauth.ts`. In this task it carries `POST /oauth/token` for `grant_type=urn:clane:agent-token` only, and `GET /.well-known/jwks.json`. It has its own `application/x-www-form-urlencoded` content-type parser (`parseAs: "string"` → `Object.fromEntries(new URLSearchParams(body))`), scoped to this plugin; no new dependency.
- Modify: `apps/api/src/routes/agents.ts`: token routes; `tokens` in `AgentView`
- Test: `apps/api/test/agents-api.test.ts`

**Interfaces:**
- Consumes: `AgentConfig` (Task 2); `createTestAgent` (Task 3); agent routes (Task 4).
- Produces, in `tokens.ts`:
  ```ts
  export async function signAgentAccess(cfg: Config, p: { agentId: string; orgId: string; grant: string }): Promise<{ token: string; expiresIn: 900 }>;
  export async function verifyAgentAccess(cfg: Config, token: string): Promise<{ sub: string; org: string; grant: string; jti: string }>; // ES256 only, aud + iss checked
  export async function agentJwks(cfg: Config): Promise<{ keys: JsonWebKey[] }>;
  ```
- Produces, in `plugins/agent.ts`:
  - `app.requireAgent` and `req.agent: { userId: string; orgId: string; grantId: string; via: "token" | "grant" }`.
  - Order of checks:
    1. `X-Gateway-Token` equals `cfg.agents.gatewayApiToken` (`timingSafeEqual` on SHA-256s), else 401.
    2. `verifyAgentAccess`, else 401.
    3. The `Agent` row exists with `revokedAt` null, and the user is `active`, else 401.
    4. The grant is an `AgentToken` or `AgentGrant` with that id and that agent, `revokedAt` null and not expired, else 401.
    5. `Agent.expiresAt <= now` → `403 agent_expired`, logging `agent.expired` once (only when no such event exists yet for that `actorId`).
    6. `verifiedAt` null or membership not `active` → `403 agent_unverified`.
- Produces, in `lib/sync.ts`: `export async function syncFor(db: PrismaClient, cfg: Config, o: { userId: string; orgId: string | null; orgOnly: boolean; locked?: boolean }): Promise<SyncBody>`.
- Produces, routes:
  - `POST /admin/agents/:id/tokens { label: 1–60 chars, expiresAt? }` → `201 { id, token }`; event `agent.token_create` (`meta.tokenId`). On a revoked agent → `409 agent_revoked`.
  - `DELETE /admin/agents/:id/tokens/:tokenId` → 204; event `agent.token_revoke`.
  - `AgentView.tokens` is `{ id, label, createdAt, expiresAt, lastUsedAt, revokedAt }[]`, never the token.
  - `POST /oauth/token`, form body `grant_type=urn:clane:agent-token&token=cvat_…`, with `X-Gateway-Token`:
    - Success → `{ access_token, token_type: "Bearer", expires_in: 900 }`, and `AgentToken.lastUsedAt` is set.
    - Bad gateway token → `401 { error: "invalid_client" }`; an unknown, revoked or expired token → `400 { error: "invalid_grant" }`; any other `grant_type` → `400 { error: "unsupported_grant_type" }`.
    - Rate limit 30/min per address.
  - `GET /agent/sync` (`requireAgent`) → `syncFor(..., { userId, orgId, orgOnly: true })` plus `{ wrappedPrivateKey, kekId, expiresAt, entitlements: { approvals: <agentApprovals feature> } }`. It logs `agent.sync` (`meta.records`) when `lastSyncLoggedAt` is null or more than 1 h old, and updates `lastSyncLoggedAt`.
  - `POST /agent/events` (`requireAgent`):
    - Body: `{ events: { at: ISO, recordId?: uuid, action: "use"|"refused"|"reflected", host: string ≤ 255, method: AgentMethod, reason?: string ≤ 64, truncated?: boolean }[] }`, 1–200 events.
    - Each becomes an `Event` with `action: "agent.<action>"`, `actorId` = the agent, `orgId`, and `meta { host, method, reason?, truncated? }`. `recordId` is kept only when `accessFor(prisma, agentId, recordId, orgId)` is non-null.
    - `Agent.lastUsedAt` is set when any event is `use`. → `{ ok: true }`.

- [ ] **Step 1: Write the failing tests** (`tokenPrivateKeyPem` from `jose.generateKeyPair("ES256", { extractable: true })` + `exportPKCS8`):
  - **Static token.**
    - `POST /admin/agents/:id/tokens` returns a `token` matching `/^cvat_[0-9a-f-]{36}_[A-Za-z0-9_-]{43}$/`.
    - `GET /admin/agents` never contains it, and the DB holds only `hashToken(token)`.
    - Exchanging it at `/oauth/token` with the gateway header → an `access_token`. Its decoded claims satisfy `scope === "agent"`, `aud === "https://gw.test/mcp"`, `sub === agentId` and `grant === tokenId`, and the header has `alg === "ES256"`. The JWKS verifies it.
  - **Route walls.**
    - `GET /agent/sync` with the access token and `X-Gateway-Token` → 200, `wrappedPrivateKey` starts with `k1.`, and a folder whose key the owner sealed to the agent (`sealOrgFolderKey` to `agent.publicKey`, then `POST /folders/:id/members` with `use`) is listed with that `wrappedFolderKey`.
    - Without `X-Gateway-Token` → 401. With a person's access token → 401.
    - The agent token on `GET /sync`, `GET /users`, `GET /me/orgs` and `GET /admin/people` → 401 each (spec §10).
  - **Expiry and state.**
    - `PATCH expiresAt` into the past → `403 agent_expired` on two calls, and exactly one `agent.expired` event.
    - An unverified agent → `403 agent_unverified`.
    - `DELETE` of the token → the next sync is 401, and the next exchange is `invalid_grant`. A token with `expiresAt` in the past → `invalid_grant`.
  - **`agent.sync`.** Logged once across two syncs within the hour.
  - **Events.**
    - `POST /agent/events` with a `recordId` the agent can't open → the event is stored with `recordId` null. With one it can open → kept.
    - 201 events → 400. `meta` has no key other than `host`, `method`, `reason`, `truncated`.
  - **No regression.** The existing `GET /sync` tests are unchanged.
- [ ] **Step 2: Run** `npx vitest run test/agents-api.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new file and `npx vitest run test/sharing.test.ts test/membership-keys.test.ts test/session.test.ts`. Expected: PASS (`/sync` unchanged after the move).
- [ ] **Step 5: Commit** `git commit -m "Agent access: ES256 agent tokens, requireAgent, static cvat_ tokens, /agent/sync and /agent/events"`

### Task 6: API — revocation and the rotation prompt

**Files:**
- Modify: `apps/api/src/routes/agents.ts` (`DELETE /admin/agents/:id`)
- Test: `apps/api/test/agents-revoke.test.ts`

**Interfaces:**
- Consumes: `offboard` (`lib/orgs.ts:104`), `GatewayClient.dropAgent` (Task 4), `requireAgent` (Task 5).
- Produces: `DELETE /admin/agents/:id`, with an optional JSON body `{ reason?: string ≤ 64 }`:
  1. One transaction:
     - collect the live team folders it is a member of and the number of records it can open (records in those folders plus direct shares to it in this org);
     - `offboard(tx, orgId, userId, "remove")`;
     - set `revokedAt` on every `AgentToken` and `AgentGrant`;
     - `Agent.wrappedPrivateKey = null`, `revokedAt`, `revokedById`;
     - `User.status disabled`.
  2. Then `gateway.dropAgent(id)`, best effort (errors are logged only).
  3. → `{ rotate: { folders: [{ id }], records: n } }`; event `agent.revoke` with `meta { reason?, folders: n, records: n }`.
  4. Already revoked → `409 agent_revoked`.

- [ ] **Step 1: Write the failing test.** Set up an agent in two folders and with one direct share, a static token, and an `AgentGrant` row inserted directly. `DELETE` it:
  - `rotate.folders` has both ids and `rotate.records` equals the count.
  - Its `FolderMember`, `RecordAccess`, `Membership` and `MembershipKey` rows are gone, while the `User` row is kept, `disabled`.
  - The token and grant both have `revokedAt` set, `wrappedPrivateKey` is null and `fake.dropped` contains the id.
  - `GET /agent/sync` with the old access token → 401.
  - Hosted Team: at 3 live agents, revoking one lets the next create succeed (spec §10).
  - With the gateway down, the `DELETE` still succeeds.
- [ ] **Step 2: Run** `npx vitest run test/agents-revoke.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new file. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: revocation with the folders to rotate"`

### Task 7: Gateway — package, config, KEK backends, envelope, identity key

**Files:**
- Create: `apps/gateway/package.json` (`@clane-vault/gateway`):
  - dependencies: `@clane-vault/crypto`, `@modelcontextprotocol/sdk ^1.32.1`, `jose ^6.2.12`, `undici ^7.30.0`, `@aws-sdk/client-kms`
  - devDependencies: `esbuild ^0.28.2`, `tsx`, `typescript`, `vitest`, `@types/node`
  - scripts: `dev`, `build` (`node build.mjs`), `test`, `typecheck`
- Create: `apps/gateway/tsconfig.json` (extends `../../tsconfig.base.json`, `types: ["node"]`), `apps/gateway/vitest.config.ts` (`include: ["test/**/*.test.ts"]`)
- Create: `apps/gateway/build.mjs`: esbuild bundles `src/server.ts` and `src/cli.ts` to `dist/` (`platform: "node"`, `format: "esm"`, `splitting: true`, every dependency bundled, so the runtime image needs no `node_modules`).
- Create: `apps/gateway/src/config.ts`, `src/kek.ts`, `src/envelope.ts`, `src/identity.ts`, `src/cli.ts` (`identity`: prints the key id and the `keyFingerprint` of the identity key)
- Modify: root `package.json` `test` script: add `-w apps/gateway`. Then run `npm install` to update `package-lock.json`.
- Test: `apps/gateway/test/kek.test.ts`, `test/envelope.test.ts`, `test/identity.test.ts`, `test/config.test.ts`

**Interfaces:**
- Produces:
  ```ts
  // config.ts
  export interface GatewayConfig { apiUrl: string; apiToken: string; publicUrl: string; kek: string; identityKeyFile: string; cacheTtlSeconds: number; agentRatePerMinute: number;
    maxResponseBytes: number; upstreamTimeoutMs: number; allowPrivateCidrs: string[]; port: number; internalPort: number; trustProxy: number }
  export function loadConfig(env?: NodeJS.ProcessEnv): GatewayConfig; // defaults from Global Constraints; apiToken min 32; publicUrl https (http only for localhost)
  // kek.ts
  export type KekContext = Record<string, string>;
  export interface Kek { readonly id: string; wrap(dek: Uint8Array, ctx: KekContext): Promise<string>; unwrap(wrapped: string, ctx: KekContext): Promise<Uint8Array> }
  export interface AwsKmsLike { encrypt(i: { KeyId: string; Plaintext: Uint8Array; EncryptionContext: KekContext }): Promise<{ CiphertextBlob?: Uint8Array }>;
    decrypt(i: { KeyId: string; CiphertextBlob: Uint8Array; EncryptionContext: KekContext }): Promise<{ Plaintext?: Uint8Array }> }
  export interface KekDeps { aws?: AwsKmsLike; fetch?: typeof fetch; readFile?: (p: string) => Promise<Uint8Array> }
  export async function loadKek(spec: string, deps?: KekDeps): Promise<Kek>;
  // envelope.ts
  export class EnvelopeError extends Error { constructor(public code: "kek_mismatch" | "bad_envelope") }
  export async function sealWithKek(kek: Kek, ctx: KekContext, aad: string, plaintext: Uint8Array): Promise<string>;  // "k1.<kek.id>.<wrappedDek>.<v1…>"
  export async function openWithKek(kek: Kek, ctx: KekContext, aad: string, envelope: string): Promise<Uint8Array>;
  export const wrapAgentKey: (kek: Kek, ids: { orgId: string; agentId: string; publicKey: string }, privateKey: Uint8Array) => Promise<string>; // ctx { orgId, agentId }, AAD agentPrivateKeyAad
  export const unwrapAgentKey: (kek: Kek, ids: { orgId: string; agentId: string; publicKey: string }, envelope: string) => Promise<Uint8Array>;
  // identity.ts
  export interface Identity { keyId: string; publicKey: string; sign(ids: { orgId: string; agentId: string; publicKey: string }): Promise<string> }
  export async function loadOrCreateIdentity(file: string, kek: Kek): Promise<Identity>;
  ```
- Backends:
  - **`file:<path>`** reads exactly 32 bytes (otherwise it throws `GATEWAY_KEK file must hold exactly 32 bytes`).
    - `id` is `file-` + the first 12 characters of base64url(SHA-256(key)).
    - `wrap` is `aeadEncrypt(key, dek, "kek:" + canonical(ctx))` with the leading `v1.` removed. `canonical` is the sorted `k=v` pairs joined with `;`.
  - **`aws-kms:<arn>`**:
    - `id` is `aws-` + 12 characters of the hash of the ARN.
    - It calls `Encrypt`/`Decrypt` with `EncryptionContext: ctx`, and the result is base64url of `CiphertextBlob`.
    - The real client is `new KMSClient({})` from a dynamic `import("@aws-sdk/client-kms")`; tests pass `deps.aws`.
  - **`gcp-kms:<resource>`**:
    - `id` is `gcp-` + 12 characters of the hash of the resource name.
    - It calls the Cloud KMS REST API, `POST https://cloudkms.googleapis.com/v1/<resource>:encrypt|decrypt`, with `additionalAuthenticatedData` = base64 of `canonical(ctx)`. The bearer comes from the metadata server's `service-accounts/default/token`.
    - This replaces the spec's `@google-cloud/kms`: its gRPC proto files don't bundle, and REST needs no dependency. `deps.fetch` is the test double.
  - Any other prefix throws.
  - The DEK is `fill(0)`ed after use in `sealWithKek`/`openWithKek`.
- Identity file:
  - JSON `{ v: 1, publicKey, sealed }` with `sealed = sealWithKek(kek, { purpose: "gateway-identity" }, "gateway-identity-key:" + publicKey, pkcs8)`.
  - It is created with flag `wx` and mode `0o600`; `EEXIST` means read it instead (two replicas starting at once).
  - A KEK that can't open it throws `EnvelopeError`, and the gateway refuses to start.

- [ ] **Step 1: Write the failing tests:**
  - **file backend.**
    - It round-trips a 32-byte DEK. Unwrap with a different 32-byte file → throws. With a different ctx → throws.
    - `wrap` output contains no `.`.
  - **aws backend (mocked `AwsKmsLike`).** It round-trips, and `encrypt` was called with `EncryptionContext: { orgId: "o", agentId: "a" }` (spec §10).
  - **gcp backend (mocked fetch).** It round-trips, and the request URL ends with `:encrypt`.
  - **Envelope.**
    - `wrapAgentKey` → a string matching `/^k1\.file-[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]+\.v1\.[A-Za-z0-9_-]+$/`. `unwrapAgentKey` with the same ids → the original bytes.
    - With a different `publicKey` (wrong AAD) → throws `CryptoError`. With another file KEK → `EnvelopeError("kek_mismatch")` (spec §10).
  - **Identity.**
    - The first call creates the file, and a second call returns the same `keyId`/`publicKey`.
    - `verifyAgentAttestation(await identity.sign(ids), ids, identity)` is true.
    - The file opened under another KEK → throws.
  - **Config.** Defaults: `cacheTtlSeconds` 60, `agentRatePerMinute` 60, `maxResponseBytes` 4194304, `upstreamTimeoutMs` 30000, `allowPrivateCidrs` `[]`, `port` 3002, `internalPort` 3003.
- [ ] **Step 2: Run** `npx vitest run` in `apps/gateway`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run`, `npx tsc --noEmit -p tsconfig.json` and `npm run build` in `apps/gateway`. Expected: PASS, and `dist/server.js` and `dist/cli.js` exist.
- [ ] **Step 5: Commit** `git commit -m "Gateway: package, config, file/aws/gcp KEK, k1 envelope, identity key"`

### Task 8: Gateway — internal service, secret-aware logging, process guards

**Files:**
- Create: `apps/gateway/src/log.ts`, `src/internal.ts`, `src/app.ts`, `src/server.ts`
- Test: `apps/gateway/test/internal.test.ts`, `test/log.test.ts`

**Interfaces:**
- Consumes: `Identity`, `Kek`, `wrapAgentKey`, `GatewayConfig` (Task 7); `generateKeyPair` (crypto).
- Produces:
  ```ts
  // log.ts
  export class HeldSecrets { hold(value: string, basicUser?: string): () => void; redact(text: string): string } // redacts every variantsOf() form (Task 10 moves variantsOf into scrub.ts; until then defined here and re-exported)
  export interface Logger { info(f: Record<string, unknown>): void; error(f: Record<string, unknown>): void }
  export function createLogger(held: HeldSecrets, write?: (line: string) => void): Logger; // one JSON line per call, every string passed through held.redact
  export function safeError(e: unknown, held: HeldSecrets): { class: string; message: string };  // no stack
  export function installCrashHandlers(proc: Pick<NodeJS.Process, "on">, log: Logger, exit: (code: number) => void): void; // uncaughtException / unhandledRejection: log { event: "crash", class } only, then exit(1)
  export function assertNoInspector(execArgv: string[], nodeOptions: string | undefined): void; // throws on --inspect*, --heapsnapshot-signal, --heap-prof, --cpu-prof
  // app.ts
  export interface GatewayDeps { kek: Kek; identity: Identity; log: Logger; held: HeldSecrets; fetch?: typeof fetch; now?: () => number } // Task 11 adds resolve?: Resolver (Task 10)
  export async function createGateway(cfg: GatewayConfig, deps: GatewayDeps): Promise<{ publicServer: Server; internalServer: Server; close(): Promise<void>; keys: AgentKeyCache }>;
  ```
- Routes on `INTERNAL_PORT`, each requiring `X-Gateway-Token` (timing-safe; otherwise 401 `{ error: "unauthorized" }`):
  - `GET /internal/health` → `{ ok: true, identity: { keyId, publicKey } }`.
  - `POST /internal/agents { agentId: uuid, orgId: uuid }`:
    1. `generateKeyPair()`.
    2. `wrapAgentKey`.
    3. `identity.sign`.
    4. `privateKey.fill(0)`.
    5. → `{ publicKey, wrappedPrivateKey, kekId: kek.id, attestation }`.
  - `DELETE /internal/agents/:id` → `keys.drop(id)`, then 204.

  `AgentKeyCache` arrives in Task 9: here, `keys` is a stub with `drop` that Task 9 replaces.
- `server.ts`:
  1. `assertNoInspector(process.execArgv, process.env.NODE_OPTIONS)`.
  2. `installCrashHandlers(process, log, process.exit)`.
  3. `loadConfig`, `loadKek`, `loadOrCreateIdentity`.
  4. `createGateway`, then listen.

  The image starts it as `node --disable-sigusr1 dist/server.js`: `prlimit` can't run in a distroless image with no shell, so core dumps are turned off with compose `ulimits` (Task 17).

- [ ] **Step 1: Write the failing tests:**
  - **Internal routes.**
    - `POST /internal/agents` without the token → 401.
    - With the token → 200. `verifyAgentAttestation(r.attestation, { orgId, agentId, publicKey: r.publicKey }, identity)` is true, and `unwrapAgentKey` of `r.wrappedPrivateKey` yields a key whose `publicKeyFromPrivateKey` is `r.publicKey`.
    - `GET /internal/health` returns the identity.
    - Nothing on `PORT` answers `/internal/health` (404).
  - **Logging.**
    - With `held.hold("sk_live_SECRET123")`, `log.error({ msg: "boom sk_live_SECRET123", b64: btoa("sk_live_SECRET123") })` writes a line containing neither form, but containing `[clane:redacted]`.
    - `safeError(new Error("x sk_live_SECRET123"))` has no secret and no `stack`.
  - **Crash.** `installCrashHandlers` with a fake process: emitting `uncaughtException` with `new TypeError("sk_live_SECRET123")` writes `{"event":"crash","class":"TypeError"}`, and `exit(1)` is called.
  - **Inspector.** `assertNoInspector(["--inspect"], undefined)` throws, and so does `assertNoInspector([], "--heapsnapshot-signal=SIGUSR2")`. `assertNoInspector([], "")` doesn't.
- [ ] **Step 2: Run** `npx vitest run test/internal.test.ts test/log.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `apps/gateway`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Gateway: internal enrolment routes, secret-aware logger, crash and inspector guards"`

### Task 9: Gateway — API client, key cache, opening items

**Files:**
- Create: `apps/gateway/src/apiClient.ts`, `src/keys.ts`, `src/items.ts`
- Create: `apps/gateway/test/fakeApi.ts`
- Test: `apps/gateway/test/items.test.ts`, `test/keys.test.ts`

**Interfaces:**
- Consumes: `unwrapAgentKey`, `Kek` (Task 7); the `/agent/sync`, `/agent/events` and `/oauth/token` shapes (Task 5). From crypto: `openOrgFolderKey`, `openOrgRecordShare`, `unwrapKey`, `decryptRecordBody`, `decryptFolderName`, `agentSecretOf`, `basicUsername`, `SECRET_KINDS`.
- Produces:
  ```ts
  // apiClient.ts
  export interface AgentSync { orgId: string; wrappedPrivateKey: string; kekId: string; membershipKeys: { publicKey: string }[]; expiresAt: string | null;
    folders: { id: string; kind: "team" | "private"; encName: string; wrappedFolderKey?: string; sealedTo?: string | null }[];
    records: { id: string; folderId: string | null; encBody: string; holderType: "user" | "folder"; keyFolderId: string | null; wrappedRecordKey: string }[];
    entitlements: { approvals: boolean } }
  export interface UseEvent { at: string; recordId?: string; action: "use" | "refused" | "reflected"; host: string; method: AgentMethod; reason?: string; truncated?: boolean }
  export class ApiRefused extends Error { constructor(public status: 401 | 403, public code: string) }
  export interface ApiClient { sync(accessToken: string): Promise<AgentSync>; events(accessToken: string, events: UseEvent[]): Promise<void>;
    exchangeStatic(cvat: string): Promise<{ accessToken: string; expiresIn: number }>; jwksUrl: URL }
  export function apiClient(cfg: Pick<GatewayConfig, "apiUrl" | "apiToken">, fetchImpl?: typeof fetch): ApiClient; // every call sends X-Gateway-Token; base `${apiUrl}/api/v1`
  // keys.ts
  export class AgentKeyCache {
    constructor(o: { ttlMs: number; kek: Kek; now?: () => number });
    /** The agent's opened X25519 keys; a KEK unwrap only on a miss. ttlMs 0: never stored. */
    open(agentId: string, sync: AgentSync): Promise<MembershipKeys>;
    drop(agentId: string): void;   // fill(0) the private key
    has(agentId: string): boolean; // test hook
  }
  export class SyncCache { constructor(o: { ttlMs: number; api: ApiClient; now?: () => number }); get(agentId: string, token: string): Promise<AgentSync>; drop(agentId: string): void }
  // items.ts
  export interface ItemSummary { handle: string; recordId: string; title: string; type: RecordType; hosts: string[]; inject: AgentInject; approval: boolean; methods?: AgentMethod[]; paths?: string[] }
  export async function listItems(sync: AgentSync, keys: MembershipKeys, agentId: string): Promise<ItemSummary[]>;
  export async function withItem<T>(sync: AgentSync, keys: MembershipKeys, agentId: string, item: string, held: HeldSecrets,
    f: (x: { recordId: string; host: string; policy: AgentPolicy; secret: string; username: string }) => Promise<T>): Promise<T | { error: "refused"; reason: "not_found" | "no_policy" }>;
  ```
- Rules:
  - **Handles.**
    - A handle is `<folder name slug>/<title slug>`, or `shared/<title slug>` for direct shares. The slug is lower-case, with runs of anything outside `[a-z0-9]` turned into `-`, trimmed, at most 60 characters.
    - Collisions get `-2`, `-3`… in record-id order, so a handle is stable while the set of items doesn't change.
    - `item` matches a handle or a record id.
  - **Cost.** `listItems` must decrypt every body to read titles and policies (the spec's "decrypt only the record the call names" can hold only for `http_request`); it keeps the summary fields and drops the bodies at once. `withItem` decrypts only the named record. Neither returns `password`, `data`, `fields` or `notes`.
  - **Opening keys.**
    - A folder row: `openOrgFolderKey(folder.wrappedFolderKey, { orgId, folderId }, keys)`, then `unwrapKey(wrappedRecordKey, folderKey, \`record-key:${id}\`)`.
    - A user row: `openOrgRecordShare(wrappedRecordKey, { orgId, recordId }, keys)`.

    The spec's `openRecordKey` can't be used here: it needs an account user key and the pre-org share AAD.
  - **Zeroing.** Every folder key, record key and the secret buffer is `fill(0)`ed in `finally`. `withItem` holds the secret in `HeldSecrets` for the duration of `f`.
  - **No policy.** A record without `agentPolicy` is listed with `hosts: []` and `inject: { kind: "none" }`, and `withItem` refuses it with `no_policy`. To allow that value, `ItemSummary.inject` is `AgentInject | { kind: "none" }`.
- `test/fakeApi.ts`:
  ```ts
  export async function startFakeApi(o: { kek: Kek }): Promise<{ url: string; token: string; agent: { id: string; orgId: string; publicKey: string };
    addFolderRecord(folderName: string, body: RecordBody): Promise<string>; addSharedRecord(body: RecordBody): Promise<string>;
    issueToken(): Promise<string>; staticToken: string; revoke(): void; expire(): void; syncCalls: number; events: UseEvent[]; close(): Promise<void> }>;
  ```
  It builds real ciphertext: a real agent key pair wrapped with `wrapAgentKey`, folder keys sealed with `sealOrgFolderKey`, bodies from `encryptRecordBody`, and ES256 tokens and JWKS from jose.

- [ ] **Step 1: Write the failing tests:**
  - **Listing.**
    - Two folders, "Payments" and "Ops", both holding a record titled "Stripe", plus one direct share titled "GitHub". `listItems` → handles `payments/stripe`, `ops/stripe` and `shared/github`.
    - The same records titled "Stripe" twice in one folder → `payments/stripe` and `payments/stripe-2`, in the same order on a second call.
    - `JSON.stringify(listItems(...))` contains none of the secret values.
  - **Opening.**
    - `withItem(..., "payments/stripe", f)` gives `f` the `data.secret`. After it returns, `HeldSecrets.redact(secret)` no longer redacts it (it was released).
    - A record without a policy → `{ error: "refused", reason: "no_policy" }`. An unknown handle → `not_found`.
  - **Cache.**
    - With `ttlMs: 60_000` and a counting KEK double, two `open` calls make 1 unwrap.
    - With `ttlMs: 0`, two calls make 2 unwraps (spec §10: "every call hits the KEK once").
    - Advancing the clock past the TTL → `has(agentId)` is false, and the cached private key buffer's bytes are all 0.
    - `drop` zeroes it at once.
  - **Refusals.** `SyncCache.get` after `fakeApi.revoke()` throws `ApiRefused(401)`, and the cache is dropped.
- [ ] **Step 2: Run** `npx vitest run test/items.test.ts test/keys.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `apps/gateway`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Gateway: API client, short key and sync caches, opening agent items"`

### Task 10: Gateway — outbound calls: allowlist, SSRF pinning, redirects, strip-then-inject, limits, scrubbing

**Files:**
- Create: `apps/gateway/src/outbound/ssrf.ts`. Its address checks are copied from `apps/api/src/lib/netGuard.ts` `isPrivateAddress` and extended, since the gateway can't depend on `apps/api`.
- Create: `apps/gateway/src/outbound/request.ts`, `src/outbound/scrub.ts`; move `variantsOf` here from `log.ts`
- Test: `apps/gateway/test/ssrf.test.ts`, `test/request.test.ts`, `test/scrub.test.ts`

**Interfaces:**
- Consumes: `AgentPolicy`, `AgentMethod` (Task 1); `GatewayConfig` (Task 7).
- Produces:
  ```ts
  // ssrf.ts
  export type Resolver = (host: string) => Promise<{ address: string; family: 4 | 6 }[]>; // default: dns.promises.lookup(host, { all: true, verbatim: true })
  export interface Cidr { family: 4 | 6; bits: bigint; prefix: number }
  export function parseCidrs(list: string[]): Cidr[]; // throws on a bad entry
  /** Loopback, link-local, private, CGNAT, multicast, unspecified, IPv4-mapped forms of these, 169.254.169.254, fd00:ec2::254. `allow` lifts a range except the metadata addresses. */
  export function isBlockedAddress(ip: string, allow: Cidr[]): boolean;
  export function matchHost(policyHosts: string[], url: URL): string | null; // the matching policy entry; no port in policy = default port only; "*.a.com" = exactly one label
  export async function resolveChecked(host: string, o: { resolve: Resolver; allow: Cidr[] }): Promise<{ address: string; family: 4 | 6; viaAllow: boolean }>; // throws Refused("ssrf"); metadata.google.internal refused by name; ANY blocked address refuses
  // scrub.ts
  export function variantsOf(secret: string, basicUser?: string): string[]; // raw, base64, base64url (unpadded), encodeURIComponent, hex lower, hex upper, base64(`${user}:${secret}`)
  export function scrub(text: string, variants: string[]): { text: string; hits: number }; // longest variant first
  export const REDACTED = "[clane:redacted]";
  // request.ts
  export interface OutboundInput { method: AgentMethod; url: string; headers?: Record<string, string>; body?: string }
  export type OutboundOutcome =
    | { ok: true; host: string; reflected: boolean; result: { status: number; headers: Record<string, string>; body: string; truncated?: true } }
    | { ok: false; host: string; reason: "host" | "scheme" | "ssrf" | "method" | "path" | "timeout" | "request_too_large" | "upstream_error" };
  export async function performRequest(input: OutboundInput, ctx: { policy: AgentPolicy; secret: string; username: string;
    cfg: Pick<GatewayConfig, "maxResponseBytes" | "upstreamTimeoutMs">; allow: Cidr[]; resolve: Resolver; onConnect?: (address: string) => void }): Promise<OutboundOutcome>;
  ```
- Rules (spec §5.4), in order:
  1. Parse the URL. Scheme `https:`; `http:` only when the resolved address is in `allow` (`viaAllow`), else `scheme`.
  2. `matchHost`, else `host`. When `policy.methods` is present, the method must be listed (`method`); when `policy.paths` is present, a prefix must match the URL path (`path`).
  3. Body at most 1 MiB of UTF-8 bytes (`request_too_large`).
  4. `resolveChecked`. Then `undici.fetch` with a fresh `new Agent({ connect: { lookup: (_h, _o, cb) => cb(null, [{ address, family }]) } })` for this hop, so the checked address is the one connected to. `Host` and SNI stay the URL host. `onConnect(address)` is called from the lookup.
  5. Strip `authorization`, `proxy-authorization`, `cookie` and `x-api-key` from the agent's headers, any case, plus the policy's header name and query name. Then inject:
     - bearer: `Authorization: Bearer <secret>`;
     - basic: base64 of `username:secret`;
     - header: `<name>: <prefix><secret>`;
     - query: `searchParams.set(name, secret)`.
  6. `redirect: "manual"`. A 3xx with `Location` is followed (up to 3 hops) only when the new URL passes steps 1–4 against the same policy, and the credential is re-injected. Otherwise the 3xx is returned as is (scrubbed). On a 4th redirect the 3xx is returned. 303 (and 301/302 after a POST) turn into a GET with no body.
  7. The total time is `AbortSignal.timeout(upstreamTimeoutMs)` across every hop and the body read → `timeout`.
  8. The response body is read from undici's decompressed stream up to `maxResponseBytes`, then the stream is cancelled and `truncated: true` set. `content-encoding` and `content-length` are dropped from the returned headers.
  9. Headers and the whole capped body (decoded as UTF-8) go through `scrub`. `reflected` = hits > 0.
  10. Every `Agent` is closed in `finally`. Error messages never include the URL's query or the headers.

- [ ] **Step 1: Write the failing tests**, against local upstreams (`http.createServer` and `https` with a self-signed cert on 127.0.0.1). The stubbed resolver maps `api.test` and `other.test` to `127.0.0.1`, and `allow = parseCidrs(["127.0.0.0/8"])`:
  - **SSRF.**
    - `resolveChecked` with no `allow` refuses hosts resolving to `127.0.0.1`, `10.0.0.5`, `169.254.169.254`, `fd00::1` and `::ffff:10.0.0.1`, plus `metadata.google.internal` by name. A spy on `onConnect` and a counting `net.connect` see no socket (spec §10).
    - A host resolving to `[8.8.8.8, 10.0.0.1]` → refused.
    - `169.254.169.254` is refused even with `allow = 169.254.0.0/16`.
  - **DNS rebinding.** A resolver returns `127.0.0.1` on the first call and `10.9.9.9` on the second. With `allow = 127.0.0.0/8`, the request still reaches the 127.0.0.1 server, `onConnect` saw `127.0.0.1`, and the resolver was called once per hop (spec §10).
  - **Host matching.**
    - `matchHost(["*.github.com"], new URL("https://api.github.com/x"))` matches; `a.b.github.com` and `github.com` don't.
    - `matchHost(["api.test"], new URL("https://api.test:8443/"))` → null; `["api.test:8443"]` matches.
    - A host that isn't in the policy → `{ ok: false, reason: "host" }`, with no socket opened.
  - **Redirects.**
    - A 302 to `other.test` (not in the policy) is returned with status 302, without being followed, and the second server sees no request.
    - A 302 to another policy host is followed, and the second server receives `Authorization: Bearer <secret>`.
    - Four chained 302s → the 4th 302 is returned (spec §10).
  - **Strip, then inject.**
    - The agent sends `Authorization: Bearer fake`, `Cookie: a=1` and `X-Key: mine` (policy `header` `X-Key`). Upstream sees exactly `X-Key: <prefix><secret>`, no `Cookie`, and no agent `Authorization`.
    - `query` injection replaces an agent-supplied `?key=` (spec §10).
  - **Scrubbing.**
    - Upstream echoes the secret raw, base64, base64url, URL-encoded and hex, plus base64 of `user:secret`, in a header and in the body. The result contains `[clane:redacted]` in both and no form of the secret, and `reflected` is true (spec §10).
    - A gzip-encoded echo is scrubbed the same way.
    - The secret written in two `res.write` calls split mid-value is still scrubbed (Review Focus 5).
  - **Limits.**
    - A 5 MiB body with `maxResponseBytes` 4 MiB → `truncated: true` and a 4 MiB body.
    - A gzip bomb (10 MiB of zeros compressed) → at most `maxResponseBytes` read, `truncated: true` (Review Focus 5).
    - Upstream drips one byte every 100 ms with `upstreamTimeoutMs: 300` → `{ ok: false, reason: "timeout" }` (Review Focus 5).
    - A body of 1 MiB + 1 byte → `request_too_large`.
    - `http://api.test` with no `allow` → `scheme`.
- [ ] **Step 2: Run** `npx vitest run test/ssrf.test.ts test/request.test.ts test/scrub.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `apps/gateway`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Gateway: outbound allowlist, pinned SSRF checks, redirect rules, strip-then-inject, caps, scrubbing"`

### Task 11: Gateway — MCP endpoint with static tokens, rate limits and use events

**Files:**
- Create: `apps/gateway/src/auth.ts`, `src/rateLimit.ts`, `src/mcp.ts`, `src/events.ts`
- Modify: `apps/gateway/src/app.ts`: mount `mcpHandler` at `new URL(cfg.publicUrl).pathname` on `PORT`; wire `AgentKeyCache`, `SyncCache`; `DELETE /internal/agents/:id` drops both caches
- Test: `apps/gateway/test/mcp.test.ts`, `test/noPlaintext.test.ts`

**Interfaces:**
- Consumes: `ApiClient`, `AgentKeyCache`, `SyncCache`, `listItems`, `withItem` (Task 9); `performRequest`, `variantsOf` (Task 10); `HeldSecrets`, `Logger` (Task 8).
- Produces:
  ```ts
  // auth.ts
  export interface AgentPrincipal { agentId: string; orgId: string; accessToken: string; exp: number }
  /** "cvat_…": exchanged at the API, cached by SHA-256 of the token until exp − 30 s. Otherwise an ES256 JWT verified against the API's JWKS (aud = cfg.publicUrl). */
  export function bearerAuth(cfg: GatewayConfig, api: ApiClient): (authorization: string | undefined) => Promise<AgentPrincipal | null>;
  // rateLimit.ts
  export class RateLimiter { constructor(now?: () => number); take(key: string, limit: number, windowMs: number): { ok: true } | { ok: false; retryAfterSeconds: number } }
  // events.ts
  export class EventQueue { constructor(api: ApiClient, log: Logger); push(p: AgentPrincipal, e: UseEvent): void; flush(p: AgentPrincipal): Promise<void> } // ≤ 200 kept per agent; oldest dropped
  // mcp.ts
  export function mcpHandler(deps: { cfg: GatewayConfig; api: ApiClient; auth: ReturnType<typeof bearerAuth>; keys: AgentKeyCache; syncs: SyncCache; events: EventQueue;
    limiter: RateLimiter; log: Logger; held: HeldSecrets; resolve: Resolver }): (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  ```
- Behaviour:
  - **Auth.** No bearer, or an invalid one → HTTP 401 with `WWW-Authenticate: Bearer` and `{ error: "unauthorized" }`. Task 12 adds `resource_metadata`.
  - **Sessions.**
    - The handler reads and parses the JSON body itself (max 1 MiB + 64 KiB) and passes it to `StreamableHTTPServerTransport.handleRequest(req, res, body)`. Sessions are stateful (`sessionIdGenerator: randomUUID`).
    - Each session is bound to the principal's `agentId`; a request on it from another agent → 403 `{ error: "forbidden" }`.
    - Sessions idle for 30 min are closed.
  - **Rate limits, before the transport:**
    - per client address: 600/min (address from `X-Forwarded-For` per `TRUST_PROXY` hops, else the socket);
    - `tools/call` `http_request`: `cfg.agentRatePerMinute` per agent;
    - `list_secrets`: 20/min per agent.

    A refusal is HTTP 429 with `Retry-After: <seconds>` and `{ error: "rate_limited" }`.
  - **Tools.** The definitions are static. Server `instructions`: *"Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential. No tool returns a secret."*
    - `list_secrets` (no input) → `listItems`, mapped to `{ handle, title, type, hosts, inject, approval, methods?, paths? }`.
    - `http_request` input (zod): `{ item: string ≤ 200, method: enum AGENT_METHODS, url: string ≤ 4096, headers?: record<string ≤ 8192> (≤ 50 entries), body?: string }` → `withItem` → `performRequest`.
      - It returns `{ status, headers, body, truncated? }`, or `{ error: "refused", reason }` (`busy`, `no_policy`, `not_found` or a `performRequest` reason).
      - It pushes one `use` or `refused` event (plus `reflected` when the response had to be scrubbed), then flushes.
    - Results are `content: [{ type: "text", text: JSON.stringify(x) }]` with `structuredContent: x`.
  - **One call at a time.** A session already running a tool call answers a second one with `{ error: "refused", reason: "busy" }`.
  - **API refusals.** `ApiRefused` from the API (401, `agent_expired`) drops that agent's key and sync caches at once, and the MCP request gets HTTP 401.

- [ ] **Step 1: Write the failing tests** (`startFakeApi`, `createGateway` on port 0, `@modelcontextprotocol/sdk` `Client` with `StreamableHTTPClientTransport` and `requestInit.headers.Authorization`):
  - **Auth.**
    - No `Authorization` → 401 with a `WWW-Authenticate` header.
    - A static token → `listTools` gives exactly `list_secrets` and `http_request` (no `get_secret`), and `list_secrets` returns the handles and contains no secret value (spec §10).
    - Two connects with the same static token make one `/oauth/token` exchange.
  - **Calls.**
    - `http_request` to the upstream with a stubbed resolver (allow `127.0.0.0/8`) → status 200, upstream saw the injected header, and `fakeApi.events` has one `use` event with `recordId`, `host` and `method`, and no `url` or path field.
    - A record with no policy → `reason: "no_policy"` and one `refused` event.
  - **Rate limits.**
    - `cfg.agentRatePerMinute: 60`: the 61st `http_request` in a minute → HTTP 429 with `Retry-After` (spec §10).
    - The 21st `list_secrets` → 429.
  - **Revocation.** After `fakeApi.revoke()`, the next MCP call → 401 and `keys.has(agentId)` is false (spec §10).
  - **Busy.** Two concurrent `http_request` on one session (upstream delays 200 ms) → one result, and one `reason: "busy"`.
  - **Session binding.** A session id reused with a second agent's token → 403.
  - **No plaintext** (`noPlaintext.test.ts`), with a known secret `sk_live_PLAINTEXT_CANARY_42`. Capture every `log` line, `process.stdout`/`process.stderr` writes, the MCP responses and the fake API's request bodies, then run:
    - a bad KEK (the wrapped key under another file KEK);
    - an upstream timeout;
    - a scrub hit;
    - an uncaught exception raised in the tool (through `installCrashHandlers` with a fake exit);
    - a refused host.

    Assert that the canary and its base64 form appear in none of them (spec §10).
- [ ] **Step 2: Run** `npx vitest run test/mcp.test.ts test/noPlaintext.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run` in `apps/gateway`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Gateway: MCP endpoint (list_secrets, http_request), static tokens, rate limits, use events"`

### Task 12: OAuth 2.1 — authorization server in the API, protected resource in the gateway

**Files:**
- Modify: `apps/api/src/routes/oauth.ts` (add metadata, DCR, authorize info and consent, the code and refresh grants, revoke)
- Modify: `apps/api/src/app.ts`:
  - Register the AS metadata route outside `apiPrefix`, at `/.well-known/oauth-authorization-server${basePath}` (RFC 8414 path insertion: the hosted issuer is `https://vault.clane.ai/app`) and, when `basePath` isn't empty, also at `${basePath}/.well-known/oauth-authorization-server`. Register it before `registerWeb`.
  - Add `prisma.agentOAuthCode.deleteMany({ where: { expiresAt: { lt: old } } })` to the sweep (L122-126).
- Modify: `apps/api/src/routes/agents.ts`: `grants` in `AgentView`; `DELETE /admin/agents/:id/grants/:grantId`
- Modify: `apps/gateway/src/app.ts`, `src/auth.ts`, `src/mcp.ts`:
  - Serve `GET <publicPath>/.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource<publicPath>` → `{ resource: cfg.publicUrl, authorization_servers: [issuer], bearer_methods_supported: ["header"] }`. The issuer comes from `GET ${API_URL}/.well-known/oauth-authorization-server`, fetched at start and cached. It isn't `API_URL`: that is the internal address, which clients can't reach.
  - 401s carry `WWW-Authenticate: Bearer resource_metadata="<publicUrl>/.well-known/oauth-protected-resource"`.
  - JWT verification also checks `iss` = issuer.
- Test: `apps/api/test/oauth.test.ts`; `apps/gateway/test/mcp.test.ts` (extend)

**Interfaces:**
- Consumes: `signAgentAccess`, `requireAgent`, `newRefreshToken`, `splitRefresh`, `hashToken` (`lib/tokens.ts`); `orgAdmin` (`plugins/org.ts`).
- Produces, API routes (under `apiPrefix` unless noted; `/oauth/*` rate limited to 30/min per address):
  - **Metadata** (outside the prefix):
    ```
    { issuer: publicUrl, authorization_endpoint: `${publicUrl}/oauth/authorize`, token_endpoint: `${publicUrl}/api/v1/oauth/token`,
      registration_endpoint: `${publicUrl}/api/v1/oauth/register`, revocation_endpoint: `${publicUrl}/api/v1/oauth/revoke`,
      jwks_uri: `${publicUrl}/api/v1/.well-known/jwks.json`, response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"] }
    ```
  - **`POST /oauth/register`**, JSON `{ client_name: 1–100 chars, redirect_uris: 1–10 }`. Each URI must be `https:`, or `http:` on `127.0.0.1`, `[::1]` or `localhost`, and carry no fragment. → `201 { client_id, client_name, redirect_uris, token_endpoint_auth_method: "none", grant_types, response_types: ["code"] }`.
  - **`GET /oauth/authorize/info`** (`requireAuth`), query `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method`, `state?`, `resource?`:
    - Errors: `400 invalid_client`, `invalid_redirect_uri` (not an exact match), `invalid_request` (`code_challenge_method` isn't `S256`, so `plain` is refused, or `response_type` isn't `code`) and `invalid_target` (`resource` given and ≠ `GATEWAY_PUBLIC_URL`).
    - Success → `{ client: { name }, agents: [{ id, name, orgId, orgName }] }`: verified, live, unexpired agents of orgs where the caller is an active owner or admin. Members get `agents: []`.
  - **`POST /oauth/authorize`** (`requireAuth` + `orgAdmin`, with `X-Org-Id` = the agent's org, so that org's SSO and IP policies apply). Body `{ clientId, redirectUri, codeChallenge, codeChallengeMethod: "S256", state?, resource?, agentId }`:
    - The agent must be in `req.org` and be verified, live and unexpired.
    - It stores an `AgentOAuthCode` (hash of 32 random bytes, `expiresAt` +5 min, `grantedById` = caller).
    - → `{ redirectTo: "<redirectUri>?code=…&state=…&iss=<issuer>" }`.
  - **`POST /oauth/token`**, form:
    - `grant_type=authorization_code`, with `code`, `code_verifier` (43–128 chars), `client_id`, `redirect_uri` and `resource?`:
      - Checks: the code is unused and unexpired, and is marked used atomically (`updateMany where usedAt null`, count 1). The client and redirect URI match exactly, and `base64url(SHA-256(verifier)) === codeChallenge`.
      - It creates an `AgentGrant` (30 days) with `refreshHash`. Event `agent.grant` (`actorId` grantedById, `targetUserId` agent, `meta.clientName`).
      - → `{ access_token, token_type: "Bearer", expires_in: 900, refresh_token }`. Any failure → `400 invalid_grant`.
    - `grant_type=refresh_token`, with `refresh_token` and `client_id`, splits the token with `splitRefresh`:
      - the secret is HMAC-SHA256(K, `agent-refresh:<grantId>:<gen>`), K = HKDF-SHA256 of `JWT_SECRET`; the server finds which generation was presented:
      - the current generation and the grant is live → rotate (`refreshGen` + 1, new `refreshHash`, `rotatedAt`) and return a new pair;
      - an older generation (outside the concurrent-request grace) → revoke the grant, log `agent.grant_revoke` with `meta.reason: "refresh_reuse"`, and answer `invalid_grant`;
      - anything else → `invalid_grant`.
    - `urn:clane:agent-token` stays as Task 5 built it.
  - **`POST /oauth/revoke`**, form `token` (a refresh token) → revoke that grant. Always 200.
  - **`DELETE /admin/agents/:id/grants/:grantId`** → 204, event `agent.grant_revoke`. `AgentView.grants` is `{ id, clientName, grantedBy: { id, name }, createdAt }[]` for live grants.

- [ ] **Step 1: Write the failing tests** (`oauth.test.ts`; PKCE pair built in the test):
  - **Metadata and DCR.**
    - `GET /.well-known/oauth-authorization-server` → `issuer` = `publicUrl` and `code_challenge_methods_supported` `["S256"]`. With `basePath: "/app"`, both `/.well-known/oauth-authorization-server/app` and `/app/.well-known/oauth-authorization-server` answer.
    - DCR with an `http://evil.test/cb` redirect → 400. With `https://claude.ai/api/mcp/auth_callback` → 201.
  - **Authorize.**
    - `info` with `code_challenge_method=plain` → `invalid_request`; with a redirect URI that isn't registered → `invalid_redirect_uri`.
    - A member gets `agents: []`, and `POST /oauth/authorize` as a member → 403.
  - **Code exchange.**
    - Admin consent → `redirectTo` has `code` and the `state` given.
    - Exchanging the code → an `access_token` whose `aud === GATEWAY_PUBLIC_URL`, `sub === agentId` and `grant === <AgentGrant.id>`, and one `agent.grant` event.
    - The same code again → `invalid_grant`. The wrong `code_verifier` → `invalid_grant`.
  - **Refresh.**
    - Refresh → a new pair, and `GET /agent/sync` works with the new access token.
    - Reusing the first refresh token → `invalid_grant`, the grant gets `revokedAt`, and the new access token now gets 401 at `/agent/sync` (spec §10).
    - A fresh grant ended by `/oauth/revoke`, and another by `DELETE /admin/agents/:id/grants/:grantId` → the next `/agent/sync` with each one's access token is 401.
  - **Gateway** (`mcp.test.ts`, with `startFakeApi` gaining a metadata route):
    - A 401 has `WWW-Authenticate` containing `resource_metadata="…/mcp/.well-known/oauth-protected-resource"`.
    - That URL returns `authorization_servers: [<fake issuer>]`.
    - A JWT with the wrong `iss` → 401.
- [ ] **Step 2: Run** `npx vitest run test/oauth.test.ts` in `apps/api` and `npx vitest run test/mcp.test.ts` in `apps/gateway`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full API suite, `npx vitest run` in `apps/api`, and `npx vitest run` in `apps/gateway`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: OAuth 2.1 authorization server (DCR, PKCE S256, rotating refresh) and protected-resource metadata"`

### Task 13: Web — sharing to agents (bot icon, Use locked, restricted-credential warning)

**Files:**
- Create: `apps/web/src/features/vault/AgentWarning.tsx` (`AGENT_WARNING` and `AGENT_DISCLOSURE` copy constants and `<AgentWarning />`; not dismissable)
- Modify: `apps/web/src/features/vault/types.ts`: `Person` (L16) and `FolderMember` (L11) gain `kind?: "person" | "agent"`
- Modify: `apps/web/src/features/vault/PeoplePicker.tsx`: when the selected person is an agent, show a `Bot` icon (lucide), set and disable the `PermissionSelect` to `use`, and render `<AgentWarning />` above the Add button. Agent rows in the options carry the Bot icon.
- Modify: `apps/web/src/features/vault/people.tsx` `PersonRow` (L65): a Bot badge for agents
- Modify: `apps/web/src/features/groups/GroupAccessBanner.tsx`: pending items with `kind: "agent"` are marked *Agent*, and `<AgentWarning />` sits above approve when any selected item is an agent
- Modify: the record share sheet (`apps/web/src/features/vault/ShareSheet.tsx` / `RecordSharing.tsx`, wherever its confirm button is) and `FolderPeopleSheet.tsx`, so both go through the picker behaviour above
- Test: `apps/web/src/features/vault/Sharing.test.tsx` (extend), `apps/web/src/features/groups/Groups.test.tsx` (extend)

**Interfaces:**
- Consumes: `kind` on `GET /users`, `/sync` members and `/group-access/pending` (Task 3).

- [ ] **Step 1: Write the failing tests** (msw):
  - `/api/v1/users` lists `{ id: "a1", name: "Billing bot", kind: "agent", … }`. Selecting it in the PeoplePicker → the permission control shows *Use only* and is disabled, the exact `AGENT_WARNING` text is visible, and Add posts `permission: "use"`.
  - Selecting a person → no warning.
  - The warning shows again on the next agent selection after an add, and it has no close button.
  - The record share sheet with an agent → the warning is visible above the confirm button.
  - `GroupAccessBanner` with a pending agent → an *Agent* label and the warning are shown.
- [ ] **Step 2: Run** `npx vitest run src/features/vault/Sharing.test.tsx src/features/groups/Groups.test.tsx` in `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same files, plus `npx tsc --noEmit -p .` and `npx oxlint src`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access (web): agents in pickers locked to Use, bot icon, restricted-credential warning"`

### Task 14: Web — Admin → Agents page (create, verify with both fingerprints, connect, tokens, grants, revoke)

**Files:**
- Modify: `apps/web/src/lib/paths.ts` `ORG_ADMIN_SECTIONS` (L43): add `"agents"`
- Modify: `apps/web/src/features/admin/AdminArea.tsx`: an `adminNav` item `item("agents", "Agents", Bot)` after Groups (L41), and the page switch (L99-120)
- Modify: `apps/web/src/lib/orgKeys.ts`: add the gateway pin helpers next to `pinStatus` (L62)
- Modify: `apps/web/src/features/admin/plan.ts`: `PlanFeature` gains `agentApprovals | agentPathPolicy`, and `OrgPlan` gains `agents?: { used: number; allowed: number | null }`
- Create: `apps/web/src/features/admin/agents.ts`, `AgentsPage.tsx`, `AgentVerifyDialog.tsx`, `AgentConnectSheet.tsx`
- Test: `apps/web/src/features/admin/AgentsPage.test.tsx`

**Interfaces:**
- Consumes: the Task 4–6 and 12 routes; `verifyAgentAttestation` (Task 1); `fingerprintOf`, `pinKey`, `pinStatus` (`orgKeys.ts`).
- Produces, in `orgKeys.ts`:
  ```ts
  /** The gateway identity is pinned under one fixed slot, so a replaced gateway with a new key id reads as "changed", not "new". */
  export const gatewayPinStatus = (me: string, identityPublicKey: string) => pinStatus(me, "gateway", "identity", identityPublicKey);
  export const pinGateway = (me: string, identityPublicKey: string) => pinKey(me, "gateway", "identity", identityPublicKey);
  ```
  The spec's `pinStatus(me, "gateway", identityKeyId, …)` keys the pin by key id, so a new id would read *New*.
- Produces, in `agents.ts`:
  - Queries: `useAgents()` (`GET /admin/agents`) and `useGateway()` (`GET /org/agents/gateway`).
  - Mutations: `useCreateAgent`, `useVerifyAgent` (`POST /verify { publicKey }`, then `pinGateway(me, identityPublicKey)` and `pinKey(me, orgId, agentId, publicKey)`), `useUpdateAgent`, `useRevokeAgent(reason?)`, `useCreateToken`, `useRevokeToken`, `useRevokeGrant`.
  - Copy helpers: `connectSnippets(url: string, token?: string): { id: "claude-ai" | "chatgpt" | "claude-code" | "claude-code-token" | "claude-api" | "openai"; label: string; text: string }[]`. The text is exactly spec §7, with the beta header `anthropic-beta: mcp-client-2025-11-20` and the prompt line; `token` replaces `cvat_…` when given.
- Page behaviour (spec §4.7):
  - **List.** Each row shows name, status label (*Awaiting verification*, *Active*, *Expired*, *Revoked*), agent fingerprint, gateway fingerprint with its pin state, expiry, last use, and folder and group counts.
  - **New agent.** A name and an optional expiry, then the verify dialog opens straight away.
  - **Verify dialog.** It shows the agent fingerprint, the gateway fingerprint and the pin state: *Pinned*, *New*, or *Changed — compare it with the published fingerprint*.
    - If `verifyAgentAttestation` fails, it shows *The gateway did not sign this key* and only offers **Revoke** (reason `attestation_failed`).
    - On *Changed*, **Matches** stays disabled until *I compared the gateway fingerprint with the published one* is ticked.
  - **Connect.** The URL, the snippets, **Create API token** (shown once, with copy), and the grants with *Revoke*.
  - **Revoke.** A confirmation, then the rotation list: *"The gateway could open these folders for this agent. Rotate the credentials in them."*, with folder names resolved from the vault.
  - **Hosted limit.** At `agents.used >= agents.allowed`, `New agent` is replaced by `LockLine`.

- [ ] **Step 1: Write the failing tests** (msw; real `generateIdentityKeyPair` and `signAgentKey` from `@clane-vault/crypto` to build the attestation):
  - **Create and verify.**
    - Create → the verify dialog shows both fingerprints (`fingerprintOf` of each key) and *New*.
    - **Matches** posts `{ publicKey }`, and afterwards `gatewayPinStatus(me, pub).status === "same"` and `pinStatus(me, orgId, agentId, agentPub).status === "same"` (spec §10: "Matches pins both").
  - **Changed gateway.** `/org/agents/gateway` answers a different identity with a new `identityKeyId` → *Changed — compare it with the published fingerprint*, and **Matches** is disabled until the box is ticked (spec §10).
  - **Bad attestation.** A tampered `publicKey` → *The gateway did not sign this key* and no **Matches**. **Revoke** sends `reason: "attestation_failed"`.
  - **Connect.** The connect sheet shows `https://gw.test/mcp` in every snippet, and the Claude API snippet contains `mcp-client-2025-11-20`.
  - **Tokens.** **Create API token** shows `cvat_…` once; after closing and reopening, it isn't shown.
  - **Revoke.** It shows the rotation list with the folder names from the response.
  - **Plan lock.** `/org/plan` with `agents: { used: 3, allowed: 3 }` → `Available on the Business plan.` and no **New agent** button.
- [ ] **Step 2: Run** `npx vitest run src/features/admin/AgentsPage.test.tsx`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run`, `npx tsc --noEmit -p .` and `npx oxlint src` in `apps/web`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access (web): Agents admin page with fingerprint verification, connect snippets, tokens, grants, revoke"`

### Task 15: Web — usage policy editor in the record editor

**Files:**
- Create: `apps/web/src/features/vault/AgentPolicyEditor.tsx`
- Modify: `apps/web/src/features/vault/RecordEditor.tsx`: an **Agent use** section for edit holders (owner and edit), for types where `defaultSecretRef(type)` is non-null or the body has a secret-kind custom field
- Test: `apps/web/src/features/vault/RecordEditor.test.tsx` (extend)

**Interfaces:**
- Consumes: `AgentPolicy`, `validateAgentPolicy`, `defaultSecretRef` (Task 1).
- Produces: `<AgentPolicyEditor body={RecordBody} value={AgentPolicy | undefined} onChange={(p: AgentPolicy | undefined) => void} />`, with these fields:
  - **Allowed hosts:** one per line.
  - **Send it as:** bearer, basic, header (with name and prefix) or query (name), with *"Weaker: URLs end up in logs."* under the query option.
  - **Secret:** the default, `password`, a `data.*` field of the type, or a secret-kind custom field.

  An empty hosts list removes the policy. `methods` and `paths` (Phase 3) aren't shown, and any present are kept unchanged. Errors from `validateAgentPolicy` appear under the section, and Save is disabled while one stands.

- [ ] **Step 1: Write the failing tests:**
  - **Create.** A new apiKey record with hosts `api.stripe.com` and bearer → the saved body (captured from the encrypt mock or msw) has `agentPolicy: { v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" } }`.
  - **Keep.** Editing only the title of a record with a policy (and with `methods: ["GET"]`) keeps `agentPolicy` deep-equal (Review Focus 4).
  - **Bad host.** Typing `10.0.0.5` shows the validation message, and Save is disabled.
  - **Type change.** Switching a record with a `data.secret` policy to *Secure note* shows the error (the secret field is gone), and nothing is saved until the policy is removed or changed (Review Focus 4).
  - **Use-only holders** don't see the section.
- [ ] **Step 2: Run** `npx vitest run src/features/vault/RecordEditor.test.tsx`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run`, `npx tsc --noEmit -p .` and `npx oxlint src` in `apps/web`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access (web): Agent use section in the record editor"`

### Task 16: Web — OAuth consent page

**Files:**
- Create: `apps/web/src/features/auth/OAuthAuthorize.tsx`
- Modify: `apps/web/src/routes.tsx`: `<Route path="/oauth/authorize" element={<OAuthAuthorize />} />` next to `/sso/complete` (L143). Signed out, it does what `Guard` does (L123): `Navigate` to `/sign-in` with `state.from` = this path and search.
- Test: `apps/web/src/features/auth/OAuthAuthorize.test.tsx`

**Interfaces:**
- Consumes: `GET /oauth/authorize/info` and `POST /oauth/authorize` (Task 12).
- Produces the page (spec §4.7):
  - It reads the query, calls `info`, and shows *"<client> wants to use vault credentials as agent …"* with an agent picker (name and org).
  - **Allow** posts with `X-Org-Id` set to the chosen agent's org, then `window.location.assign(redirectTo)`.
  - **Deny** navigates to `redirect_uri?error=access_denied&state=…`, only after `info` succeeded, so an unvalidated redirect is never followed.
  - `info` errors → one line, *"This connection request isn't valid. Start again from your AI app."*, with no redirect.
  - An empty `agents` list → *"Only owners and admins can connect agents."* (members), with no **Allow**.

- [ ] **Step 1: Write the failing tests** (msw):
  - With two agents → choosing the second and **Allow** posts `agentId` of the second, with its org's `X-Org-Id`, and assigns the returned `redirectTo`.
  - `info` → 400 → the invalid-request line, and `location.assign` is never called.
  - `agents: []` → the owners-and-admins line, and no **Allow** button.
  - Signed out → navigates to `/sign-in` with `from.search` holding the original query.
- [ ] **Step 2: Run** `npx vitest run src/features/auth/OAuthAuthorize.test.tsx`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx vitest run`, `npx tsc --noEmit -p .` and `npx oxlint src` in `apps/web`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access (web): OAuth consent page for owners and admins"`

### Task 17: Deploy and docs

**Files:**
- Create: `apps/gateway/Dockerfile`. Its context is the repo root.
  - Build stage: the same Node 22 slim base and manifests as the root `Dockerfile` (L9-20, plus `apps/gateway/package.json`), then `npm ci` and `npm run build -w @clane-vault/gateway`.
  - Runtime: `gcr.io/distroless/nodejs22-debian13:nonroot`, holding only `dist/`, with `USER` nonroot, `EXPOSE 3002 3003` and `CMD ["--disable-sigusr1", "dist/server.js"]`.
  - Image `ghcr.io/clane-ai/clane-gateway`, with OCI labels as in the root `Dockerfile`.
- Modify: root `Dockerfile` (L13-20): `COPY apps/gateway/package.json apps/gateway/`, so `npm ci` matches the lockfile.
- Modify: `deploy/client/docker-compose.yml`: a `gateway` service under `profiles: ["agents"]`, so existing installs without a KEK don't fail on upgrade:
  - `image: ${CLANE_GATEWAY_IMAGE:-ghcr.io/clane-ai/clane-gateway}:${CLANE_VAULT_VERSION}`;
  - `environment` with `API_URL=http://clane-vault:3001${BASE_PATH}` and `GATEWAY_KEK=file:/run/secrets/gateway-kek`;
  - `GATEWAY_IDENTITY_KEY_FILE=/data/identity.key`;
  - `secrets: [gateway-kek]` (file `./secrets/gateway-kek`);
  - `volumes: [gateway-data:/data]`;
  - `ulimits: { core: 0 }`, `read_only: true`, `tmpfs: [/tmp]`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`;
  - `ports: ["${GATEWAY_BIND:-127.0.0.1}:${GATEWAY_PORT:-8081}:3002"]`, and port 3003 never published;
  - networks: `default`, for outbound calls, plus `internal` (`internal: true`), which the `clane-vault` service joins too.
- Modify: `deploy/client/.env.example` (next to `BILLING_MODE`, L102): commented `GATEWAY_INTERNAL_URL=http://gateway:3003`, `GATEWAY_PUBLIC_URL`, `GATEWAY_API_TOKEN`, `AGENT_TOKEN_PRIVATE_KEY`, `GATEWAY_ACCEPT_NEW_IDENTITY`, `GATEWAY_ALLOW_PRIVATE_CIDRS` and `COMPOSE_PROFILES` (add `agents`), each with a one-line comment. The `GATEWAY_ALLOW_PRIVATE_CIDRS` comment reads `# Self-hosted only. Never set on a hosted service.`
- Modify: `deploy/client/README.md`: a section "Agent access (optional)" covering:
  - generating the KEK (`openssl rand 32 > secrets/gateway-kek`), the token key (`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`) and `GATEWAY_API_TOKEN` (`openssl rand -hex 32`);
  - the reverse-proxy rules: forward `/mcp` (no prefix stripping) to the gateway port, and with a base path also `/.well-known/oauth-authorization-server<base>` to the app. Never forward `/internal`.
- Create: `docs/agents.md`:
  - what an agent is;
  - enrolment and the gateway fingerprint, how to publish it (`docker compose exec gateway /nodejs/bin/node dist/cli.js identity`) and the hosted published fingerprint;
  - scopes (folders, groups, shares, Use only);
  - the usage policy and its rules, the weaker query option, and that an older client may drop the policy on edit (Review Focus 4);
  - the connection steps of spec §7, with the OpenAI shape flagged for verification;
  - static tokens and OAuth;
  - revocation, and why it prompts for rotation;
  - KMS setup on AWS (key policy limited to the gateway's role, `kms:EncryptionContext` keys `orgId`/`agentId`) and GCP (REST API, metadata-server credentials);
  - the file-key fallback and its weaker standing, and backing up the KEK (lose it and every agent must be re-enrolled; nothing else is affected);
  - `GATEWAY_*` settings, limits and errors;
  - that JavaScript can't guarantee zeroing, and that the enclave (Phase 5) is the real answer.
- Modify: `SECURITY.md` ("Security model", L40): a subsection "Agent access: the disclosed exception". It gives the spec §8.1 table and the §8.1 sentence verbatim, the residual risks of §8.2 (a hijacked agent's legitimate-looking calls, gateway host breach, insider until Phase 5, legal compulsion, re-encoding hosts, self-reported `agent.use`), and "rotate every agent-scoped credential after a gateway incident".
- Modify: `CHANGELOG.md` (Unreleased): migration `20261026000000_agent_access` (a `kind` column with a default, and six new tables); agent access off unless the `GATEWAY_*` settings are set; the gateway image and compose profile; one line on the disclosed exception, linking `SECURITY.md`.
- Modify: `docs/sharing.md` (*Trust limits*): one paragraph on the gateway pin, linking `docs/agents.md`.
- Test: none new. This task's deliverable is verified by building.

- [ ] **Step 1: Build** with `docker build -f apps/gateway/Dockerfile -t clane-gateway:test .` and `docker build -t clane-vault:test .`. Expected: both succeed.
- [ ] **Step 2: Run** `docker run --rm -e GATEWAY_KEK=file:/nope clane-gateway:test`. Expected: it exits non-zero, with a one-line config error that contains no stack trace.
- [ ] **Step 3: Validate** with `docker compose -f deploy/client/docker-compose.yml --profile agents config`. Expected: exit 0, and the gateway service shows `read_only: true` and `ulimits.core: 0`, with only 3002 published.
- [ ] **Step 4: Check** that every env name in `docs/agents.md` and `.env.example` exists in `apps/gateway/src/config.ts` or `apps/api/src/config.ts` (grep each one). Expected: none missing.
- [ ] **Step 5: Commit** `git commit -m "Agent access: gateway image and compose profile, docs/agents.md, SECURITY.md disclosure, CHANGELOG"`

### Task 18: End-to-end acceptance

**Files:**
- Create: `e2e/playwright.agents.config.ts`. It follows `playwright.config.ts`, with:
  - the API `webServer` env plus `GATEWAY_INTERNAL_URL=http://127.0.0.1:3003`, `GATEWAY_PUBLIC_URL=http://localhost:3002/mcp`, a generated `GATEWAY_API_TOKEN` and `AGENT_TOKEN_PRIVATE_KEY`;
  - a gateway `webServer` (`npm run dev -w @clane-vault/gateway`, `GATEWAY_KEK=file:<tmp>`, `GATEWAY_ALLOW_PRIVATE_CIDRS=127.0.0.0/8`, `NODE_OPTIONS=--import=./test/fixtures/hosts.mjs`);
  - the web server.
- Create: `apps/gateway/test/fixtures/hosts.mjs`, a test-only module that maps `echo.test` to `127.0.0.1` in `dns.promises.lookup`.
- Create: `e2e/agents/agents.spec.ts`, which starts an echo HTTPS upstream on `echo.test` (self-signed cert; the gateway webServer gets `NODE_EXTRA_CA_CERTS`).
- Modify: `e2e/package.json`: script `"test:agents": "playwright test -c playwright.agents.config.ts"`
- Test: `e2e/agents/agents.spec.ts`

**Interfaces:**
- Consumes: everything above. The MCP client is `@modelcontextprotocol/sdk` `Client` with `StreamableHTTPClientTransport`.

- [ ] **Step 1: Write the test** (one flow, desktop project). As an admin:
  1. Admin → Agents → **New agent** "Billing bot" → the verify dialog shows two fingerprints → **Matches**. The row reads *Active*.
  2. Create a team folder "Payments" with an *API key / secret* record "Echo" (secret `sk_test_E2E_CANARY`, Agent use host `echo.test`, bearer). Add Billing bot through the people sheet: the warning is visible and the permission is locked to *Use only*.
  3. **Connect** → **Create API token**, and read the `cvat_…` text from the dialog.
  4. MCP client with `Authorization: Bearer <token>`:
     - `list_secrets` contains `payments/echo` and not the canary.
     - `http_request { item: "payments/echo", method: "GET", url: "https://echo.test/headers" }`: the echo server received `Authorization: Bearer sk_test_E2E_CANARY`, and the tool result body contains `[clane:redacted]` and not the canary.
  5. Admin → Event log shows `agent.use` for "Echo".
  6. **Revoke** → the rotation list names "Payments". The next MCP call → HTTP 401.
- [ ] **Step 2: Run** `npm run test:agents -w e2e`. Expected: FAIL before the fixtures are wired, then PASS.
- [ ] **Step 3: Run** the existing suite unchanged, `npm run e2e` from the repo root, with no `GATEWAY_*` and `BILLING_MODE` unset (spec §10). Expected: PASS.
- [ ] **Step 4: Run** `npm test` and `npm run typecheck` from the repo root. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Agent access: end-to-end acceptance (enrol, verify, share, MCP use, scrub, revoke)"`

---

## Self-review notes

- **Spec coverage.** Each spec section maps to a task:
  - §4.1 → Task 2; §4.2 → Tasks 4, 8, 14; §4.3 → Tasks 3, 13; §4.4 → Tasks 5, 12.
  - §4.5 → Tasks 5 (expiry) and 6; §4.6 → Tasks 4–6, 12 and 11 (gateway-reported events); §4.7 → Tasks 13, 14, 16.
  - §5.1 → Tasks 1, 15; §5.2 → Tasks 7, 8, 11; §5.3 → Tasks 7, 9; §5.4 → Task 10; §5.5 → Task 11; §5.6 → Tasks 5, 11, 12; §5.7 → Task 17.
  - §7 → Tasks 14, 17; §8 → Task 17 (`SECURITY.md`) and Task 13 (UI sentence); §9 → Tasks 2, 4, 14.
  - The §10 acceptance lines are assigned in each task's tests. Exception: "approval routes return 402 `plan_required` on Team" is Phase 3, since Phases 1–2 have no approval routes. Only the `agentApprovals` flag is pinned (Task 2).
- **Names used across tasks:**
  - `capForAgent`, `createTestAgent`, `startFakeGateway`, `pinGatewayIdentity`, `GatewayUnavailable`, `AgentLimitError` (API);
  - `signAgentAccess`/`verifyAgentAccess`, `requireAgent`/`req.agent`, `syncFor`;
  - `Kek`, `sealWithKek`/`openWithKek`, `wrapAgentKey`/`unwrapAgentKey`, `Identity`, `HeldSecrets`, `AgentKeyCache`/`SyncCache`, `listItems`/`withItem`, `performRequest`, `variantsOf`/`scrub`, `bearerAuth`, `mcpHandler`, `startFakeApi` (gateway);
  - `gatewayPinStatus`/`pinGateway`, `AgentWarning`, `connectSnippets` (web).
