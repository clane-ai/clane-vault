# Organisation policies

Each organisation has policies. Owners and admins edit them in **Organisation settings → Policies** (account menu at the bottom left, or the organisation menu). They are
stored as JSON on the organisation (`Organization.policies`). `lib/policies.ts` validates them with zod on every write,
and missing fields take their defaults. Every change is logged as `org.policies_update`, with the changed keys in
`meta.changed`.

| Policy | Default | Enforced by |
|---|---|---|
| `autoLockMinutes`: lock the vault after this many idle minutes (1–1440, null for the app default of 15) | null | Web app and browser extension |
| `minPasswordLength` (12–128) and `minPasswordScore` (zxcvbn 0–4) for master passwords | 12, 0 | Clients: sign-up, invitation acceptance, password change |
| `links.allowed`, `links.maxExpiryHours` (1, 24, 168), `links.requirePassword` | on, 168, off | Server (`POST /links`) |
| `links.allowAttachments`: one-time links may carry files the creator picks (`docs/attachments.md`) | on | Server (`POST /links`) |
| `attachments.allowed`: members with edit rights may attach files to records | on | Server (`POST /records/:id/attachments`) |
| `attachments.maxFileMb`: largest file in MB (1–1024; null for the server's `ATTACHMENT_MAX_FILE_MB`); can only lower the server's limit | null | Server, and clients before uploading |
| `attachments.previews`: images, PDFs and text open in a preview (off: download only) | on | Web app |
| `offlineAllowed`: encrypted offline copies of the vault | on | Clients |
| `extensionAllowed`: the browser extension | on | Clients |
| `breachCheckAllowed`: members may opt in to the Have I Been Pwned check (`docs/password-health.md`) | on | Web app |
| `ipAllowlist`: IPv4 and IPv6 CIDRs that may reach the organisation (empty means anywhere) | `[]` | Server, on every org-scoped request |
| `ownerBreakGlass`: the owner reaches the organisation from anywhere despite the allowlist | on | Server |

## How clients read them

Every organisation in the org list carries `policies` (`GET /me/orgs`, and the `orgs` of sign-in and refresh
responses). This is the client view: every field above except `ipAllowlist` and `ownerBreakGlass`, plus
`ipRestricted: boolean`. Admins read and write the full set at `GET` and `PUT /admin/settings/policies`.

In the web app:
- `useOrgPolicies()` (`apps/web/src/lib/policies.ts`) gives the active organisation's policies.
- `usePolicyFlags()` gives `offlineAllowed`, `extensionAllowed`, `breachCheckAllowed` and `autoLockMinutes`, for the
  offline copy, the extension and the password health page.
- `checkMasterPassword(pw, { minLength, minScore })` and `passwordRuleText()` check a master password and state the rule.

The session uses the active organisation's `autoLockMinutes` for its idle timer.

The master password rule is applied at these points:

- **Sign-up from an invite.** `GET /auth/invite/:token` returns `passwordPolicy: { minLength, minScore }`. The form
  shows the rule and refuses a password that breaks it.
- **Accepting an invitation with an existing account.** `GET /me/orgs` invitations carry `passwordPolicy`. When it is
  stricter than the app's floor, the app asks for the master password and checks it on the device before joining. It
  checks that the password unlocks the account, then that it meets the rule. A password that doesn't meet it blocks
  joining until it is changed.
- **Password change.** Use `checkMasterPassword` with the active organisation's rule, or `strictest()` over all the
  account's organisations.

The server never sees the master password, so it can't enforce this rule. It is a client-side policy.

## One-time links

The policy applies to links that belong to the organisation: links on its team records, and links on records shared
in it. Links on a member's own private records are theirs and aren't affected. `POST /links` answers:
- `403 links_disabled` when links are off;
- `400 link_expiry_too_long` (with `maxExpiryHours`) when the expiry is too long;
- `400 link_password_required` when a password is required and missing.

The check reads the policy under a share lock on the organisation row, in the same transaction as the insert. A
concurrent change that switches links off therefore can't miss a new link. Switching links off revokes (and burns)
the organisation's live links at once. A shorter maximum expiry or a new password requirement revokes the live links
that break it (made for longer than the new maximum, or without a password); the count is in `meta.linksRevoked`.
Switching `allowAttachments` off refuses new links with files (`403 link_attachments_disabled`) and revokes the live
links that carry files; links without files stay.

## File attachments

The policy applies to records the organisation's access goes through: its team records, and records shared in it (a
member's own private records follow no organisation's policy). With `attachments.allowed` off, new uploads answer `403
attachments_disabled`; files already attached stay listed and downloadable, and can be removed. `attachments.maxFileMb`
lowers the per-file limit (`413 file_too_large` with `max`); the server's own limit (`ATTACHMENT_MAX_FILE_MB`) always
applies. `attachments.previews` off makes every file download-only in the app (the server can't tell a preview from a
download, so this one is a client policy). See `docs/attachments.md`.

## IP allowlist

When the list isn't empty, every org-scoped request (`X-Org-Id`) must come from an address inside it:
- IPv4 and IPv6 are both supported;
- IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) match IPv4 networks;
- the check uses `req.ip`, so set `TRUST_PROXY` to the number of reverse proxies in front of the app. Never set it to
  `true`: the client's own `X-Forwarded-For` header would then pick the address, and anyone could claim an allowed one.

Other requests answer `403 ip_not_allowed` with the `orgId`. Requests without the header still work: the private
vault, `GET /me/orgs` and sign-in.

**Not locking yourself out:**

- **Owner break-glass.** On by default: the owner reaches the organisation from anywhere, and the first use in each
  session is logged as `policy.ip_bypass_owner` (with the IP). Only the owner can turn it on or off (`403 owner_only`
  for admins).
- **Saving checks the caller's address.** A non-empty list that doesn't contain the caller's current address is
  refused with `409 would_lock_out`, unless the caller is the owner and break-glass stays on. So the owner can only turn
  break-glass off from inside the list, and an admin can't save a list that leaves themselves out. The settings page
  shows "Your address".
- **Admins can't shut the owner out.** While break-glass is off, the owner is held to the list, so only the owner may
  narrow it (remove a network, or start a list where there was none): admins get `403 owner_only`. Admins may still
  add networks or clear the list.
- If an owner still ends up outside, an operator can fix it in the database: remove `ipAllowlist` from
  `Organization.policies` (or set the column to `{}`, which resets every policy).

Stored policies that somehow fail validation are read field by field. An unreadable allowlist then fails closed (no
address allowed) rather than open.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/settings/policies` | `{ policies, changedAt, changedBy, yourIp }` (owners and admins) |
| PUT | `/admin/settings/policies` | The full policy object (unknown keys are refused). `403 owner_only`, `409 would_lock_out` |
