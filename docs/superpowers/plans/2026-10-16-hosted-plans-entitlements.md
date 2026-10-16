# Hosted plans: entitlements and enforcement (plan 1 of 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Behind `BILLING_MODE=hosted`, every organisation and Personal space resolves to a plan whose features and limits (seats, storage, one-time links, event-log window, Business-only settings) the API enforces; with `BILLING_MODE=off` (default) nothing changes.

**Architecture:** One pure module, `apps/api/src/lib/plans.ts`, maps an org's stored plan fields to an `Entitlements` object. With billing off it always returns the `unlimited` set, so every check becomes a no-op without branching at call sites. The API enforces limits at the existing write paths, inside the transactions and locks those paths already use (`lockQuota` for storage, a row lock on `Organization` for seats). The web app reads `GET /org/plan` and maps the new `402` errors to one line of text. Plans are set by an operator command until Stripe arrives (plan 2).

**Tech Stack:** Fastify 5, Prisma 6 / Postgres, zod, vitest (API against real Postgres via `test/helpers.ts`), React + TanStack Query.

**Spec:** `docs/design/2026-10-16-hosted-plans.md` (§2, §3, §4.1–4.4, §4.6 "Over limit" and "Business → Team", §7). The other plans in the series:
- Plan 2, Stripe billing and lifecycle (§4.3 `BillingEvent`, §4.5, §4.6 past_due/canceled/retention, §4.7 Plan & billing page and pricing modal).
- Plan 3, waitlist and invite-only hosted sign-up (§5).
- Plan 4, 7-day demo sandbox (§6).

## Global Constraints

- `BILLING_MODE` = `off` (default) | `hosted`. `off`: existing self-hosted installs behave exactly as today, and no billing route is registered.
- Plans are `personal` (implicit, a user's own space), `team` (default for every org) and `business`; with billing off everything resolves to `unlimited`.
- Seats = active memberships + pending invitations (`acceptedAt` null, `expiresAt` > now), counted per org and per distinct email. `disabled` memberships don't count.
- Trial (as Keeper and Zoho Vault do): with billing hosted, a new organisation (`POST /orgs`, customer orgs) gets `trialEndsAt` = creation + 14 days, no card. While `trialEndsAt > now` and it has no paid subscription it gets Business features with Team's seat allowance (10). Afterwards it is Team (free ≤10 seats) with nothing to run: the switch is computed from `trialEndsAt`, no job.
- Team: 10 seats free; an org with `seatsPaid` set gets exactly `seatsPaid`. Business always needs `seatsPaid`. There is no "first 10 free" on a paid Team org.
- Limits from §3:
  - one-time links: Personal 5 active, orgs unlimited;
  - storage: Personal 1 GB per user, Team 2 GB per seat pooled, Business 10 GB per seat pooled;
  - event log: Team 30 days, Business 365 days plus CSV export.
- Business-only: SSO config, domain verification (and domain auto-join), policy edits, admin recovery, risk dashboard, org logo, event export.
- Errors follow the codebase convention `reply.code(N).send({ error: "<snake_code>", ...extra })`, not the spec's `{ code }`:
  - `402 { error: "plan_required", feature, requiredPlan: "business" }`
  - `402 { error: "seat_limit", used, allowed }`
  - `402 { error: "link_limit", limit }`
  - storage refusals keep the existing quota error shape.
- Never block reading, decrypting, exporting or deleting. Over-limit blocks only: new invites, new records in team folders, and attachment uploads.
- Members never see upgrade prompts; owners and admins see one line of text.
- 1 GB = 1024 MiB (the codebase's `MIB` unit).

## Review Focus

1. **Turning hosted mode on over existing orgs.** Every org starts as `team`, so an org that already uses SSO with `requireSso` would stop being offered SSO. Expected: a stored `requireSso` / `ssoTrusted` policy isn't enforced on Team, so its members can still sign in with password and authenticator. Nobody is locked out, and no stored setting is deleted. *Test in Task 3.*
2. **Concurrent invites at the last free seat.** Two parallel invites at 9 used seats: exactly one succeeds and the other gets `seat_limit`. *Test in Task 4.*
3. **One person, two rows.** An existing account who is invited has both an `Invite` row and an `invited` membership. They count as one seat, and accepting the invite needs no extra seat. Re-enabling a `disabled` member does need one. *Tests in Task 4.*
4. **Bulk invite crossing the limit.** 8 seats used and a bulk invite of 5: the first 2 rows succeed, the other 3 get status `seat_limit` in the per-row results, and nothing is half-created. *Test in Task 4.*
5. **Billing off.** A gated route (`PUT /admin/settings/policies`) and the 11th invite behave exactly as today, and `GET /org/plan` is `404`. *Test in Task 1 (route absent) and Task 2 (gate inert).*

---

### Task 1: Mode switch, plan columns, entitlements module, `GET /org/plan`

**Files:**
- Modify: `apps/api/src/config.ts` (env schema near `HOSTED_MODE` L22; `Config` L96-150; `loadConfig` L248-266)
- Modify: `apps/api/prisma/schema.prisma` (`Organization` L100-147)
- Create: `apps/api/prisma/migrations/20261025000000_org_plans/migration.sql`
- Create: `apps/api/src/lib/plans.ts`
- Create: `apps/api/src/routes/plan.ts`; register it in `apps/api/src/routes/orgs.ts` inside the `orgRequired` block (L157) only when `app.config.billingMode === "hosted"`
- Create: `apps/api/src/scripts/set-plan.ts`; add `"set-plan"` to `apps/api/package.json` scripts, same shape as `reset-2fa`
- Modify: `deploy/client/.env.example` (next to `HOSTED_MODE`, L100)
- Test: `apps/api/test/plans-unit.test.ts`, `apps/api/test/plans.test.ts`

**Interfaces:**
- Produces, in `config.ts`: `Config.billingMode: "off" | "hosted"`, parsed from `BILLING_MODE`.
- Produces, in Prisma:
  - `enum OrgPlan { team business }` and `enum BillingStatus { free active past_due canceled }`.
  - New `Organization` columns:
    - `plan OrgPlan @default(team)`
    - `billingStatus BillingStatus @default(free)`
    - `seatsPaid Int?`
    - `currentPeriodEnd DateTime? @db.Timestamptz`
    - `stripeCustomerId String? @unique`
    - `stripeSubscriptionId String? @unique`
    - `trialEndsAt DateTime? @db.Timestamptz`, set by `POST /orgs` (`orgs.ts:139`) and `createCustomerOrg` (`customerOrgs.ts:87`) only when `billingMode === "hosted"`
  - The spec's `storageBytesUsed` is **not** added: `orgUsage`/`userUsage` in `lib/attachments/quota.ts` already compute usage under `lockQuota`, and a counter column could drift.
- Produces, in `lib/plans.ts`:
  ```ts
  export type PlanId = "personal" | "team" | "business" | "unlimited";
  export type Feature = "sso" | "domains" | "policyEdit" | "adminRecovery" | "risk" | "orgLogo" | "eventExport";
  export interface Entitlements {
    plan: PlanId; features: Record<Feature, boolean>;
    seatsAllowed: number | null;          // null = unlimited
    storageBytesPerSeat: number | null;   // pooled per active member; personal: per user
    activeLinkLimit: number | null;
    eventLogDays: number | null;
  }
  export type OrgPlanFields = { plan: "team" | "business"; billingStatus: string; seatsPaid: number | null; trialEndsAt: Date | null };
  export const PLAN_SELECT: { plan: true; billingStatus: true; seatsPaid: true; trialEndsAt: true };
  /** `trial` is true while a Team org without a subscription is inside its 14-day Business trial. */
  export function getEntitlements(cfg: Pick<Config, "billingMode">, org: OrgPlanFields, now?: Date): Entitlements & { trial: boolean };
  export function getPersonalEntitlements(cfg: Pick<Config, "billingMode">): Entitlements;
  export async function orgEntitlements(db: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<Entitlements>;
  export const planRequired: (feature: Feature) => { error: "plan_required"; feature: Feature; requiredPlan: "business" };
  ```
  `seatsAllowed` is `org.seatsPaid ?? (plan === "team" ? 10 : 0)`. In trial, the features and storage/event-log values come from Business and `seatsAllowed` stays 10.
- Produces: `GET /org/plan`, for owners and admins (403 `forbidden` for members, like `orgAdmin`). It returns `{ plan, billingStatus, seatsPaid, currentPeriodEnd, trialEndsAt, entitlements }`. Seat and storage *usage* fields are added by Tasks 4 and 5.
- Produces: `npm run set-plan -- --org <id> --plan team|business [--seats N]`. It updates the row and logs the existing event `org.plan_change` with meta `{ from, to, seatsPaid, by: "operator" }` through `lib/events.ts`.

- [ ] **Step 1: Write the failing unit tests** in `plans-unit.test.ts`:
  ```ts
  const off = { billingMode: "off" as const }, on = { billingMode: "hosted" as const };
  expect(getEntitlements(off, { plan: "team", billingStatus: "free", seatsPaid: null }).plan).toBe("unlimited");
  expect(getEntitlements(off, { plan: "team", billingStatus: "free", seatsPaid: null }).seatsAllowed).toBeNull();
  const team = getEntitlements(on, { plan: "team", billingStatus: "free", seatsPaid: null });
  expect(team).toMatchObject({ plan: "team", seatsAllowed: 10, storageBytesPerSeat: 2 * 1024 ** 3, activeLinkLimit: null, eventLogDays: 30 });
  expect(Object.values(team.features).every((x) => !x)).toBe(true);
  expect(getEntitlements(on, { plan: "team", billingStatus: "active", seatsPaid: 15 }).seatsAllowed).toBe(15);
  const biz = getEntitlements(on, { plan: "business", billingStatus: "active", seatsPaid: 20 });
  expect(biz).toMatchObject({ seatsAllowed: 20, storageBytesPerSeat: 10 * 1024 ** 3, eventLogDays: 365 });
  expect(Object.values(biz.features).every(Boolean)).toBe(true);
  expect(getEntitlements(on, { plan: "business", billingStatus: "free", seatsPaid: null }).seatsAllowed).toBe(0);
  expect(getPersonalEntitlements(on)).toMatchObject({ plan: "personal", activeLinkLimit: 5, storageBytesPerSeat: 1024 ** 3 });
  expect(getPersonalEntitlements(off).plan).toBe("unlimited");
  const now = new Date("2026-11-01T00:00:00Z"), day = 864e5;
  const trial = getEntitlements(on, { plan: "team", billingStatus: "free", seatsPaid: null, trialEndsAt: new Date(+now + day) }, now);
  expect(trial).toMatchObject({ trial: true, seatsAllowed: 10, eventLogDays: 365 });
  expect(Object.values(trial.features).every(Boolean)).toBe(true);
  const after = getEntitlements(on, { plan: "team", billingStatus: "free", seatsPaid: null, trialEndsAt: new Date(+now - 1) }, now);
  expect(after).toMatchObject({ trial: false, plan: "team", eventLogDays: 30 });
  expect(after.features.sso).toBe(false);
  ```
- [ ] **Step 2: Write the failing route tests** in `plans.test.ts` (mimic `test/sso-last-domain.test.ts`):
  - `GET /api/v1/org/plan` → 404 with `makeTestApp({})`.
  - With `makeTestApp({ billingMode: "hosted" })`, an admin gets 200 `{ plan: "team", billingStatus: "free", entitlements: { seatsAllowed: 10 } }`.
  - A member gets 403.
  - With hosted on, `POST /orgs` creates an org whose `trialEndsAt` is 14 days out (±1 min), and `GET /org/plan` reports `entitlements.trial: true`; with billing off `trialEndsAt` stays null.
- [ ] **Step 3: Run** `npx vitest run test/plans-unit.test.ts test/plans.test.ts` from `apps/api`. Expected: FAIL, `plans.ts` not found.
- [ ] **Step 4: Implement** the config field, the schema change, the migration (Prisma's SQL for the two enums and six columns, with defaults so existing rows backfill to `team`/`free`), then `plans.ts`, `routes/plan.ts` and `set-plan.ts`. Add `# BILLING_MODE=off` to `.env.example` with the one-line comment `# hosted: plans and limits for the Clane Vault cloud (docs/plans.md). Self-hosted: leave off.`
- [ ] **Step 5: Run** the two test files. Expected: PASS. Then run `npx prisma migrate diff --from-migrations prisma/migrations --to-schema-datamodel prisma/schema.prisma --shadow-database-url "$TEST_DATABASE_URL" --exit-code`. Expected: exit 0, no drift.
- [ ] **Step 6: Commit** `git commit -m "Hosted plans: BILLING_MODE, org plan columns, entitlements, GET /org/plan, set-plan"`

### Task 2: Business-only write routes return 402

**Files:**
- Modify: `apps/api/src/lib/plans.ts`. Add `requireEntitlement`.
- Modify, adding `preHandler: app.requireEntitlement("<feature>")` to each route:
  - `routes/ssoSettings.ts`: `PUT /` L71 and `POST /test` L114 → `sso`; `POST /domains` L132 and `POST /domains/:domain/verify` L174 → `domains`. `DELETE` routes stay open, so turning things off always works.
  - `routes/provisioning.ts`: `PUT /admin/settings/domain-join` L267, only when the body has `enabled: true` → `domains` (inline check, same 402 body).
  - `routes/policies.ts`: `PUT /admin/settings/policies` L21 → `policyEdit`.
  - `routes/adminRecovery.ts`: `PUT /admin/settings/admin-recovery` L42 → `adminRecovery`, only when turning it on (inline check). Turning it off always works.
  - `routes/risk.ts`: `GET /admin/risk` L195, `/members` L198 and the CSVs L213, L231 → `risk`.
  - `routes/orgs.ts`: `PUT /org/logo` L195 → `orgLogo`. `DELETE` L206 stays open.
  - `routes/events.ts`: `GET /export.csv` L62 → `eventExport`.
- Test: `apps/api/test/plans-gates.test.ts`

**Interfaces:**
- Consumes: `orgEntitlements`, `planRequired`, `Feature` (Task 1).
- Produces: `app.requireEntitlement(feature: Feature): preHandlerHookHandler`, decorated in `buildApp` next to `orgAdmin`. It runs after `orgRequired`/`orgAdmin` (needs `req.org`) and replies `402 planRequired(feature)`.

- [ ] **Step 1: Write the failing test.** For each route above, make the call as an org owner with `billingMode: "hosted"`:
  - On Team: expect 402 `{ error: "plan_required", feature: <name>, requiredPlan: "business" }`.
  - After `prisma.organization.update({ data: { plan: "business", seatsPaid: 50 } })`: expect the status the route gave before this change. Use bodies the existing tests already use for these routes.
  - Then rebuild with `billingMode: "off"`: `PUT /admin/settings/policies` succeeds on a `team` org (Review Focus 5).
- [ ] **Step 2: Run** `npx vitest run test/plans-gates.test.ts`. Expected: FAIL (200s where 402 was expected).
- [ ] **Step 3: Implement** `requireEntitlement` and wire it in.
- [ ] **Step 4: Run** the new file, plus `test/sso*.test.ts test/policies.test.ts test/admin-recovery*.test.ts test/risk*.test.ts test/branding.test.ts`. Expected: all PASS (those files run with billing off).
- [ ] **Step 5: Commit** `git commit -m "Hosted plans: Business-only settings return 402 plan_required on Team"`

### Task 3: Team plan reads stored Business settings as off

Covers spec §4.6 "Business → Team". A Team org keeps its stored rows untouched, and the reads behave as below.

**Files:**
- Modify: `apps/api/src/lib/policies.ts`. `readPolicies` (L70) gains a parameter `ent: Entitlements`; when `!ent.features.policyEdit` it returns `DEFAULT_POLICIES`. Update every caller (grep `readPolicies(`), including the per-request `ipBlocked`/`ssoMissing` in `plugins/org.ts:34,56,80`.
- Modify: `apps/api/src/routes/sso.ts`. `ssoOrgsFor` (L46) and `POST /start` (L67) leave out orgs where `!features.sso`, so the `sso_not_configured` answer covers them too.
- Modify: `apps/api/src/lib/domainJoin.ts`. `requestDomainJoin` (L56) refuses when `!features.domains`, with the same answer as "auto-join off".
- Modify: `apps/api/src/lib/recovery.ts` / `routes/adminRecovery.ts`. Admin recovery is treated as off when `!features.adminRecovery`: the "is it on" read returns false, so escrow isn't offered. The stored flag is untouched.
- Modify: `apps/api/src/routes/events.ts`. `whereOf` (L17-22) gains `minAt: Date | null`, from `eventLogDays`, and clamps `from` to it.
- Test: `apps/api/test/plans-downgrade.test.ts`

**Interfaces:**
- Consumes: `orgEntitlements` (Task 1).
- Produces: `readPolicies(db, orgId, ent)`, with the signature change propagated to its callers.

- [ ] **Step 1: Write the failing tests.** Set up a Business org with SSO configured, a verified domain, auto-join on, `requireSso: true`, admin recovery on, and events dated 40 and 400 days ago. Then update it to `plan: "team", seatsPaid: null`, under `billingMode: "hosted"`, and expect:
  - `POST /auth/sso/discover` for its domain → no org listed.
  - Its member signs in with password + authenticator and calls `GET /sync` → 200, not `sso_required` (Review Focus 1).
  - `GET /admin/settings/policies` → defaults; the stored `Organization.policies` is unchanged.
  - The public domain-join request is refused.
  - The admin-recovery status reads off.
  - `GET /admin/events` returns neither the 40-day nor the 400-day event. On Business it returns the 40-day event but not the 400-day one.
  - Updating back to `business` restores every one of these with nothing re-entered.
- [ ] **Step 2: Run** `npx vitest run test/plans-downgrade.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** the changes above.
- [ ] **Step 4: Run** the new file and the full API suite, `npx vitest run`. Expected: all PASS.
- [ ] **Step 5: Commit** `git commit -m "Hosted plans: Team reads stored SSO, policies, auto-join, admin recovery and old events as off"`

### Task 4: Seats

**Files:**
- Create: `apps/api/src/lib/seats.ts`
- Modify (call `assertSeat` inside each path's transaction, before the row is created):
  - `lib/invites.ts` `sendNewInvite` (transaction L155) and `resendInvite` (L102)
  - `lib/domainJoin.ts` `requestDomainJoin` (invite.create L76)
  - `routes/orgs.ts` `POST /me/join` (L85-100)
  - `lib/ssoLink.ts` `linkAndJoin` (L22)
  - `routes/sso.ts` `POST /auth/sso/register` (L261)
  - `routes/admin.ts` `POST /admin/users/:id/enable` (L176)
- Not checked: accepting an invitation (`orgs.ts:65`) and registering via invite (`auth.ts:189`, `convertOtherInvites` L86), because the seat was counted when the invite was made. Customer-org creation (`customerOrgs.ts:64`) and `POST /orgs` aren't checked either, since they create the first seat.
- Modify: `routes/provisioning.ts` bulk handler (rows L28-60). A row refused with `seat_limit` gets `status: "seat_limit"` and the loop continues; a seat freed later is not retried.
- Modify: `routes/plan.ts`. Add `seats: { used, allowed }`.
- Test: `apps/api/test/plans-seats.test.ts`

**Interfaces:**
- Consumes: `orgEntitlements` (Task 1).
- Produces:
  ```ts
  export async function seatsUsed(db: Db, orgId: string, now?: Date): Promise<number>;
  /** Locks the org row (SELECT … FOR UPDATE), then throws SeatLimitError if `adding` more seats would pass seatsAllowed. */
  export async function assertSeat(tx: Db, cfg: Pick<Config, "billingMode">, orgId: string, adding?: number): Promise<void>;
  export class SeatLimitError extends Error { used: number; allowed: number }
  export async function overSeatLimit(db: Db, cfg: Pick<Config, "billingMode">, orgId: string): Promise<boolean>;
  ```
  - `seatsUsed` counts the distinct lower-cased emails of `active` members and of invites with `acceptedAt: null, expiresAt > now`. An `invited` membership is counted through its invite row.
  - The global error handler maps `SeatLimitError` to `402 { error: "seat_limit", used, allowed }`.
  - With billing off, `assertSeat` returns before taking the lock.

- [ ] **Step 1: Write the failing tests** (hosted, Team org, owner already one seat):
  - 9 invites succeed; the 10th seat succeeds; the 11th invite → 402 `seat_limit` `{ used: 10, allowed: 10 }`.
  - Deleting a pending invite (`DELETE /admin/invites/:id`) frees a seat. An expired invite isn't counted.
  - After `set-plan`-equivalent `seatsPaid: 11`, the 11th invite succeeds.
  - An existing account invited counts 1, and accepting keeps `used` unchanged (Review Focus 3).
  - Disable a member, fill the seat freed, then re-enable → 402 (Review Focus 3).
  - 9 used, `Promise.all` of two invites → exactly one 2xx and one 402 (Review Focus 2).
  - 8 used, bulk of 5 → the per-row statuses are 2 sent and 3 `seat_limit`, and `seatsUsed` is 10 (Review Focus 4).
  - Billing off: 15 invites all succeed.
  - SSO register and domain-join request at a full org are refused with `seat_limit`.
- [ ] **Step 2: Run** `npx vitest run test/plans-seats.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** `seats.ts`, the calls, the error mapping and the bulk row status.
- [ ] **Step 4: Run** the new file and `npx vitest run test/provisioning.test.ts test/admin.test.ts test/orgs.test.ts test/auth.test.ts`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Hosted plans: seat limits on every way into an organisation"`

### Task 5: Storage, one-time links, over-limit writes

**Files:**
- Modify: `apps/api/src/lib/attachments/quota.ts`. `checkQuota` (L79) takes the plan quota into account when `cfg.billingMode === "hosted"`:
  - For an org charge, the quota is `min(cfg.orgQuotaMb * MIB, storageBytesPerSeat × max(1, active members))`.
  - For a user charge, it is `min(cfg.userQuotaMb * MIB, personal storageBytesPerSeat)`.
  - Thread `billingMode` in through `AttachmentConfig` (`attachmentConfig` L15). The refusal shape stays `QuotaRefusal`.
- Modify: `apps/api/src/routes/links.ts`. `POST /links` (L56): when the link has no `orgId` and `activeLinkLimit` is set, count links where `revokedAt: null, expiresAt > now, encPayload not null` and `opens < maxOpens`, and refuse with `402 { error: "link_limit", limit: 5 }`. The count happens in the same transaction as the create, under `SELECT … FOR UPDATE` on the `User` row.
- Modify: `apps/api/src/routes/records.ts` (create into a team folder) and `routes/attachments.ts` `POST /records/:id/attachments` (L105). When `overSeatLimit(org)` is true, refuse with `402 { error: "seat_limit", used, allowed }`. Edits, reads, deletes, exports and moves out are untouched.
- Modify: `routes/plan.ts`. Add `storage: { used, limit }`.
- Test: `apps/api/test/plans-limits.test.ts`

**Interfaces:**
- Consumes: `getEntitlements`/`getPersonalEntitlements` (Task 1), `overSeatLimit` (Task 4), `lockQuota`/`checkQuota`.

- [ ] **Step 1: Write the failing tests** (hosted):
  - Team org with 1 member. Reserving an upload of 2 GiB + 1 byte → refused with the existing quota error. Reserving 2 GiB − 1 KiB → accepted. Deleting it frees the space, and the next reservation of the same size → accepted.
  - Personal: 5 links succeed, the 6th → 402 `link_limit`. Revoke one, then the next succeeds. Links in an org are unlimited (create 6).
  - Team org forced over the limit: an operator sets `seatsPaid: 1` while 3 seats are used. Then:
    - creating a record in a team folder → 402;
    - an attachment reservation → 402;
    - `GET /sync` → 200, and editing an existing record → 200;
    - deleting a record → 200, and the encrypted export / backup download route → 200 (spec §7 "never block read, decrypt or export").
  - Billing off: none of the above refuse.
- [ ] **Step 2: Run** `npx vitest run test/plans-limits.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full API suite, `npx vitest run`. Expected: all PASS.
- [ ] **Step 5: Commit** `git commit -m "Hosted plans: pooled storage, Personal link cap, over-limit blocks new team records and uploads"`

### Task 6: Web app — locks and limit messages; docs

**Files:**
- Create: `apps/web/src/features/admin/plan.ts`. It exports `useOrgPlan()`, a TanStack query for `GET /org/plan` scoped with `useScope()`. A `404` resolves to `null`, which means billing is off and nothing is locked. It also exports `planMessage(e: unknown): string | null`.
- Modify: the admin pages behind each gated feature, through the sections in `apps/web/src/features/admin/AdminArea.tsx` L98-115: SSO settings, Policies, Admin recovery, Risk, the org logo control, and the Events export button. When `useOrgPlan()` says the feature is off, show one line with a lock icon, `Available on the Business plan.`, in place of the form or button. Owners and admins only; members never reach these pages.
- Modify: the admin area header (`AdminArea.tsx`) shows owners/admins `Business trial: {n} days left` while `entitlements.trial`; nothing for members, nothing when billing is off.
- Modify: invite (single and bulk results), new record in a team folder, attachment upload, one-time link creation. These map `ApiError` codes through `planMessage`, following the pattern of `RiskPage.tsx:183`:
  - `seat_limit` → `All {allowed} seats are in use. An owner can add seats.`
  - `link_limit` → `You can have 5 active one-time links. Revoke one to make another.`
  - `plan_required` → `Available on the Business plan.`
  - Bulk rows with status `seat_limit` → `No seat left`.
- Create: `docs/plans.md`. It covers what `BILLING_MODE` does, the matrix from spec §3 limited to what plan 1 enforces, the error codes, `set-plan`, and the advice to set existing orgs to `business` with `set-plan` *before* switching hosted mode on.
- Modify: `CHANGELOG.md` (Unreleased).
- Test: `apps/web/src/features/admin/plan.test.ts`, plus one component test for the SSO settings page.

**Interfaces:**
- Consumes: `GET /org/plan` (Tasks 1, 4, 5) and the 402 bodies (Global Constraints).

- [ ] **Step 1: Write the failing tests.**
  - `planMessage(new ApiError(402, "seat_limit", { error: "seat_limit", used: 10, allowed: 10 }))` → `"All 10 seats are in use. An owner can add seats."`
  - `planMessage(new ApiError(500, "server_error", {}))` → `null`.
  - With msw answering `/api/v1/org/plan` with `{ entitlements: { features: { sso: false } } }`, the SSO settings page shows `Available on the Business plan.` and no form.
  - With `/org/plan` → 404, it shows the form.
- [ ] **Step 2: Run** `npx vitest run src/features/admin/plan.test.ts` from `apps/web`. Expected: FAIL.
- [ ] **Step 3: Implement** the hook, the messages, the lock lines and the docs.
- [ ] **Step 4: Run** `npx vitest run`, `npx tsc --noEmit -p .` and `npx oxlint src` in `apps/web`. Then run the e2e suite from the repo root with billing off (spec §7: unchanged). Expected: all PASS.
- [ ] **Step 5: Commit** `git commit -m "Hosted plans: web locks and limit messages, docs/plans.md"`
