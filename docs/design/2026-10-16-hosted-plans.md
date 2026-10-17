# Clane Vault — hosted plans, entitlements and billing (build spec)

Status: ready to build. Target: `clane-ai/clane-vault`. Implementation plans: `docs/superpowers/plans/2026-10-16-hosted-plans-entitlements.md` (1 of 4: entitlements and enforcement); Stripe billing, waitlist and demo follow.

## 1. Goal and non-goals

Add plans and billing for the **hosted** service (vault.clane.ai) without changing the self-hosted product.

- Self-hosted stays free (AGPL) with **every feature and no limits**. Plans only apply when billing is switched on.
- Zero-knowledge is unchanged. Plans, seats and billing use metadata the server already has; nothing reads
  plaintext, keys or ciphertext.
- Never lock anyone out of their data. Over-limit or unpaid states restrict *new* actions, never reading or
  exporting existing records.

Non-goals for this phase: monthly billing, coupons beyond Stripe's built-ins, resellers/MSP billing, SCIM.

## 2. Plans

| Plan | Who it's for | Price | Billing |
|---|---|---|---|
| **Personal** | One person, own vault | Free forever | None |
| **Team** | Small teams | Free up to 10 seats. From 11 seats, **€1 per seat per month for all seats** | Annual, EUR, per organisation |
| **Business** | Companies needing SSO, policies, audit | **€3 per seat per month** for all seats | Annual, EUR, per organisation |
| **Self-hosted** | Run on own servers | Free (AGPL) | None; optional support contract sold separately (out of scope) |

Rules:
- A **Personal** account is a user's private space. Creating or joining an organisation puts that organisation on
  Team or Business; the person's Personal space stays free.
- Each organisation is billed separately. One person in two organisations counts as a seat in each.
- **Seats** = active members + pending (unexpired) invitations. Suspended/removed members don't count.
- Team with 11+ seats must have a paid subscription covering all seats. There is no "first 10 free" on a paid Team org.
- Prices exclude VAT. Use Stripe Tax for VAT (EU reverse charge for valid VAT numbers).

## 3. Feature matrix

✓ = included, — = not included. "Self-hosted" always gets everything.

| Feature (existing doc) | Personal | Team | Business | Self-hosted |
|---|---|---|---|---|
| Unlimited records, 14 record types, custom fields | ✓ | ✓ | ✓ | ✓ |
| Web app, installable app, browser extension (`extension.md`) | ✓ | ✓ | ✓ | ✓ |
| Import from Keeper, LastPass, 1Password, Bitwarden, Zoho, Dashlane, CSV (`import.md`) | ✓ | ✓ | ✓ | ✓ |
| Password health (`password-health.md`) | ✓ | ✓ | ✓ | ✓ |
| Recovery kit (`recovery.md`) | ✓ | ✓ | ✓ | ✓ |
| Authenticator 2FA at sign-in | ✓ | ✓ | ✓ | ✓ |
| Breached-password check (HIBP, opt-in) | ✓ | ✓ | ✓ | ✓ |
| One-time links (`sharing.md`) | 5 active | ✓ | ✓ | ✓ |
| File attachments (`attachments.md`), storage | 1 GB per user | 2 GB per seat, pooled | 10 GB per seat, pooled | Unlimited |
| Organisations, shared folders, Edit/View/Use access (`sharing.md`) | — | ✓ | ✓ | ✓ |
| Invites, bulk/CSV invites, invitation management (`provisioning.md`) | — | ✓ | ✓ | ✓ |
| Groups (`groups.md`) | — | ✓ | ✓ | ✓ |
| Event log in app (`provisioning.md`, event log) | — | Last 30 days | 1 year + CSV export | ✓ |
| Organisation policies (`policies.md`) | — | Defaults only (read-only) | ✓ editable | ✓ |
| Single sign-on, OIDC (`sso.md`) | — | — | ✓ | ✓ |
| Verified domains, email-domain auto-join (`provisioning.md`) | — | — | ✓ | ✓ |
| Admin account recovery (`recovery.md`) | — | — | ✓ | ✓ |
| Risk dashboard + printable report (`risk-dashboard.md`) | — | — | ✓ | ✓ |
| Organisation logo (`branding.md`) | — | — | ✓ | ✓ |
| Instance branding / product name override | — | — | — | ✓ (instance admins) |
| Built-in encrypted backups | Managed by Clane | Managed by Clane | Managed by Clane | ✓ self-managed |
| Support | Docs, community | Email, best effort | Email, next business day | Paid contract (separate) |

## 4. Implementation

### 4.1 Mode switch
- New env var `BILLING_MODE` = `off` (default) | `hosted`.
- `off`: every org resolves to an internal `unlimited` entitlement set. No billing UI, routes or webhooks are
  registered. Existing self-hosted installs must behave exactly as today.
- `hosted`: plans, limits and billing apply.

### 4.2 Entitlements module
- `apps/api/src/lib/plans.ts`: one typed definition of plans → entitlements (booleans + numeric limits) matching §3.
  Single source of truth; the web app reads entitlements from the API, never hard-codes them.
- `getEntitlements(org)` and `getPersonalEntitlements(user)`.
- `requireEntitlement(name)` Fastify preHandler for gated routes, returning `402` with
  `{ code: "plan_required", feature, requiredPlan }`.
- Limit checks (seats, storage, active links) happen in the same transaction as the write that would exceed them.

### 4.3 Data model (Postgres migration)
On `Organization`:
- `plan`: `team` | `business` (default `team`)
- `billingStatus`: `free` | `active` | `past_due` | `canceled`
- `seatsPaid` (int, nullable), `currentPeriodEnd` (timestamptz, nullable)
- `stripeCustomerId`, `stripeSubscriptionId` (nullable, unique)
- `storageBytesUsed` (bigint), maintained on attachment upload/delete

New table `BillingEvent` (id, orgId, stripeEventId unique, type, payload jsonb, createdAt) for webhook idempotency
and audit. Log plan changes to the existing event log as `org.plan_change`.

### 4.4 Enforcement points
- **Seats:** invite (single, bulk, CSV), domain auto-join, SSO JIT join. Block when the next seat would exceed the
  free limit (Team, unpaid) or `seatsPaid`. Show "Add seats" to owners/admins.
- **Business features:** SSO config, domain verification, policy edits, admin recovery, risk dashboard, org logo,
  event-log beyond 30 days and export. Hide or show as locked with an upgrade prompt for owners/admins; members
  see no prompt.
- **Storage:** attachment upload checks the pooled limit before issuing an upload URL.
- **One-time links (Personal):** cap active links at 5.

### 4.5 Billing (Stripe)
- Stripe Checkout for new subscriptions, Stripe Customer Portal for card, invoices, VAT number, cancel.
- One annual price per plan per seat, EUR, `quantity` = seats. Seat increases mid-term are prorated immediately;
  decreases apply at renewal.
- Webhooks: `checkout.session.completed`, `customer.subscription.updated|deleted`, `invoice.paid`,
  `invoice.payment_failed`. Verify signatures; dedupe on `stripeEventId`.
- Only org **owners** can start checkout or open the portal.

### 4.6 Downgrades, failures, cancellation
- `past_due`: 14-day grace, banner for owners/admins. After grace, behave as over-limit.
- Over limit (unpaid, seats above free, or after downgrade): reading, decrypting, exporting and deleting always work;
  new invites, new records in shared folders and uploads are blocked until resolved. Never remove members or data
  automatically.
- Business → Team: SSO stops being offered at sign-in (master password still works, since SSO always needs it);
  policies revert to defaults; admin recovery turns off; existing event-log rows are kept but only 30 days shown.
- Canceled: same as unpaid over-limit; data retained 90 days after period end, with export reminders at day 0, 60, 85.

### 4.7 Web app
- Settings → **Plan & billing** for owners/admins: current plan, seats used/paid, storage used, renewal date,
  "Upgrade", "Add seats", "Manage billing".
- Pricing comparison modal built from the entitlements API.
- Locked features show a small lock and one line of text; no nagging banners for members.

## 5. Waitlist and access to hosted

- Hosted sign-up is **invite-only** at launch. vault.clane.ai has a "Join the hosted waitlist" form
  (email, company, team size, current password manager). Store in a `Waitlist` table; admin can issue invite codes.
- Gate: hosted plans open to the waitlist only after (a) automatic public-key verification for shares is fixed
  (see README security model) and (b) an independent security review is published in `docs/`.

## 6. Demo sandbox (7 days)

- Separate deployment (`DEMO_MODE=true`), separate database, never shares data with production.
- "Try the demo" creates a sandbox org pre-filled with sample records, folders and groups. Lifetime 7 days.
- Banner on every page: "Demo: data is deleted on <date>. Don't store real passwords."
- Attachments disabled; one-time links disabled; outbound email only for expiry reminders.
- Day 5 and day 7 emails: export link, "self-host it" guide, "join hosted waitlist".
- Hard purge at expiry by a scheduled job; rate-limit sandbox creation per IP and email.

## 7. Tests (acceptance)

- `BILLING_MODE=off`: full existing e2e suite passes unchanged; no billing routes registered.
- Team org: 10th seat invite succeeds, 11th blocked until subscription with ≥11 seats is active.
- Pending invitations count as seats; revoked/expired ones free the seat.
- Business-only routes return 402 on Team, succeed on Business.
- Webhook replay of the same event is a no-op.
- Downgrade and cancellation never block read, decrypt or export.
- Storage limit blocks upload URL issuance; deleting attachments frees space.
- Demo purge removes all sandbox data at expiry.

## 8. Open decisions

1. Personal attachment limit (proposed 1 GB) and Team/Business pooled storage numbers.
2. Whether Team gets editable `autoLockMinutes` (common ask) while other policies stay Business-only.
3. Founding offer: first 100 hosted orgs get 12 months of Team or Business free, then the price locked for 2 years.
