# Risk dashboard

**Admin → Risk dashboard** (`/o/<org>/admin/risk`) is the first page of an organisation's Admin area. Owners and
admins see it; members get the "No access" page and the API answers 403. It is modelled on Keeper's Risk Management
Dashboard, but it stays zero-knowledge: everything on it is computed on the server from the organisation's settings,
metadata (who is a member, when they were last seen, which folders they hold a key for) and the counts that members'
apps already report. No password, item title, key or ciphertext is read or returned.

The page has a score, utilisation tiles, security benchmarks, high-priority alerts, a password health summary and a
printable report.

## Score

A number from 0 to 100 (higher is better), computed by `computeScore` in `apps/api/src/lib/risk.ts`:

```
benchmarks = 100 × Σ weight(completed) / Σ weight(completed or critical)      weights: high 3, medium 2, low 1
health     = average password health score of the members' latest reports    (docs/password-health.md)
score      = round(0.7 × benchmarks + 0.3 × health)
           = round(benchmarks)                                                  while nobody has reported yet
```

Ignored, not-applicable and unknown benchmarks count neither way. So ignoring a benchmark takes it out of the score. The
page says how many benchmarks are ignored next to the score, and every ignore is logged. "How is this computed?" on the
page shows the same formula with the organisation's own numbers.

## Utilisation

These tiles count **active members** of the organisation. Each tile opens a per-member table (`?view=<tile>` in the
URL) with filters (all, with, without), a search box and a CSV export.

| Tile | Counts |
|---|---|
| Members with records | Members who can open at least one of the organisation's records: records in its team folders they hold a key for, plus records shared with them in it (and their own records shared there). The table also shows how many each member owns. |
| Signed in within 30 days | The latest `Session.lastSeen` (it updates on every token refresh) is within 30 days. |
| Invitations accepted | Accepted (joined) members against pending invitations. The table lists the pending ones, and **Resend all pending invites** calls People's `POST /admin/invites/resend-all` (`resendInvite` in `lib/invites.ts`): admin-only, rate-limited, each invitation at most every 5 minutes, within the daily invitation cap, and logged as `admin.invite_resend` and `admin.invite_resend_all`. A resent link gets a new token, so the old link stops working. |
| Two-step sign-in | Always 100%: every account sets up an authenticator before it can sign in. The tile also counts members whose current session skipped the code because the organisation trusts its identity provider's MFA (`Session.totpSkippedForOrg`). |
| Recovery kit saved | The member has a recovery kit (`User.recoveryWrap` is set). |
| Password health reported | The member's latest health report is less than 30 days old. |
| File storage | Ciphertext bytes of the files on records in the organisation's shared folders (uploads in progress included) against `ATTACHMENT_ORG_QUOTA_MB`, and the number of files (`docs/attachments.md`). The bar turns red over 90 %. Its table is storage by member (files on the records each member owns there) with a CSV export (`GET /admin/storage/members.csv`). Hidden when attachments are off on the server. |

## Security benchmarks

Each benchmark is **Critical** (needs action), **Completed** or **Ignored**. Each has a severity (its weight in the
score) and a button to the exact page that fixes it. **Ignore** keeps the benchmark key in the organisation's policies
JSON, under `riskIgnored`. That key sits beside the policies but outside the policy schema: the Policies form never
sends or replaces it, and saving the policies keeps it. Ignoring and restoring are logged as `risk.benchmark_ignored`
and `risk.benchmark_restored` with the key. An ignored benchmark still shows whether it would pass.

| Key | Benchmark | Severity | Passes when | Fix |
|---|---|---|---|---|
| `backup_admin` | At least two owners or admins | High | Two or more active owners or admins | People |
| `admin_recovery` | Admin account recovery is on | Medium | `adminRecoveryEnabled` (or ignore it on purpose) | Admin recovery |
| `auto_lock` | Auto-lock after 15 minutes or less | Medium | `autoLockMinutes` is set and is 15 or less (when unset, each member picks their own) | Policies |
| `master_password` | Minimum master password strength | High | `minPasswordScore` is 3 or more | Policies |
| `share_links` | One-time links are restricted | Medium | Links are off, need a password, or last at most 24 h. The policy already caps links at 7 days, so a 7-day limit alone would always pass. | Policies |
| `ip_allowlist` | IP allowlist (optional) | Low | At least one network is on the allowlist. Ignore it if members work from anywhere. | Policies |
| `sso` | Single sign-on with a verified domain | Medium | SSO is configured and at least one domain is verified. It doesn't apply when the organisation has no company domain, that is, no SSO domain added and no two members sharing a non-public email domain. | Single sign-on |
| `org_email` | Organisation email is set up | Medium | The organisation has its own email settings (the detail line also says whether the server's settings are in use) | Email |
| `backups` | Server backups ran in the last 48 hours | High | Instance backups are on and the last successful run finished within 48 h. Only instance admins see this; for everyone else it reads "ask your server admin" and doesn't count. | Server → Backups |
| `password_health` | No members with risky passwords | High | No reporting member has a breached password or a score under 60. It doesn't apply until someone reports. | Password health |
| `inactive_admins` | No admins inactive for 90 days | Medium | Every owner and admin was seen (last session, else when they joined) within 90 days | People |
| `storage` | File storage under 90 % of the quota | High | The organisation's files use at most 90 % of `ATTACHMENT_ORG_QUOTA_MB`. Doesn't apply while it has no files. | Organisation settings → Storage |

## High-priority alerts

These are counts of risky event actions in the **last 30 days** against the **30 days before**. The trend is
`(current − previous) / previous`, shown as "New" when there was nothing before. The table can be sorted by any column
and exported as CSV. **People** shows who did it ("by them") and who it was done to ("to them").

- **Organisation alerts** are entries in the organisation's own log: `sso.callback_failed`, `admin.reset_2fa`,
  `recovery.request_created`, `recovery.request_approved`, `auth.admin_recovery_used`, `admin.recovery_policy_disabled`,
  `admin.role_change`, `admin.remove_member`, `admin.disable`, `org.transfer`, `org.policies_update`,
  `policy.ip_bypass_owner`, `sso.bypass_owner`, `sso.settings_updated`, `sso.settings_removed`, `link.create`,
  `admin.events_export`, `risk.benchmark_ignored`, `attachment.quota_exceeded` (uploads refused: storage full),
  `link.attachment_download` (files downloaded through one-time links) and **files downloaded from widely shared
  records** (`attachment.download` events whose record ten or more people can open, `meta.wide`; its key is
  `attachment.download_wide`). Each label opens the event log filtered to that action
  (`/o/<org>/admin/events?action=…`).
- **Account alerts** are account-level events with no organisation: `auth.login_failed`, `auth.refresh_reuse`,
  `auth.step_up_failed`, `auth.recovery_failed`, `auth.reauth_failed`, `auth.recovery_kit_used`. They count only for
  the organisation's current members and only since they joined, plus the same action when it was logged in this
  organisation (a failed sign-in through its SSO, for example). They don't appear in the organisation's event log, so
  their details are on the dashboard.

There is no event for a request blocked by the IP allowlist (only the owner's break-glass is logged), so the dashboard
can't count blocks.

## Password health

The members' latest reports, summed: how many reported (and how many in the last 30 days), the average score, members
at risk (a breached password or a score under 60), and the total, weak, reused, old and breached passwords. "Breached"
covers only members who turned on the breach check. The per-member table stays on **Password health**.

## Report

**Download report** (or the browser's Print on this page) renders a plain report and prints it with a print stylesheet
(`risk-print.css`): the score and formula, utilisation, every benchmark, every alert and the health counts, in black on
white. Choose *Save as PDF* in the print dialog. There is no server-side PDF.

## API

Every endpoint is under `/admin/risk`, needs `X-Org-Id` and an owner or admin of that organisation (checked against
the database on every request), and is computed per request: one aggregate SQL query for the members and two grouped
queries for the alerts (no N+1, and no cache beyond the request).

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/risk` | `{ generatedAt, windowDays, instanceAdmin, score, utilisation, benchmarks, alerts, health }`; `utilisation.storage` is `{ used, quota, files, alertRatio, enabled }` |
| GET | `/admin/storage`, `/admin/storage/members.csv` | The File storage tile's data and CSV (also Organisation settings → Storage). |
| GET | `/admin/risk/members` | Per-member drill-down: `{ members: [{ id, name, email, role, joinedAt, records: { owned, canOpen }, lastSeen, active30d, idpMfa, recoveryKit, health }], invites: [{ email, role, createdAt, expiresAt }] }` |
| GET | `/admin/risk/members.csv` | `tile` = `records`, `active`, `invites`, `idp_mfa`, `recovery_kit` or `health`; `has` = `yes` or `no`. Rate-limited, logged as `admin.risk_export`. |
| GET | `/admin/risk/alerts.csv` | The alerts table. Rate-limited, logged as `admin.risk_export`. |
| GET | `/admin/risk/alerts/:action/members` | One alert's last 30 days per person: `{ people: [{ user, asActor, asTarget, lastAt }] }`. 404 for an action that isn't an alert. |
| POST / DELETE | `/admin/risk/benchmarks/:key/ignore` | Ignore or restore a benchmark (logged). POST returns the new overview. |

CSV cells are quoted, and cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`, as in
the event log export.
