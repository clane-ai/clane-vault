# Plans

Plans exist only on the hosted Clane Vault cloud. A self-hosted server is never limited.

## BILLING_MODE

| Value | What happens |
|---|---|
| `off` (default) | No plans, no limits. Every organisation behaves as it always has. `GET /api/v1/org/plan` answers `404`. |
| `hosted` | Every organisation has a plan (`team` or `business`) and the limits below apply. |

Set it in the server `.env`. The web app reads `GET /api/v1/org/plan` (owners and admins only). If that answers `404`, it shows no locks and no trial line.

## What each plan includes

This is what the server enforces today.

| | Personal | Team | Business |
|---|---|---|---|
| Seats | one person | 10 free, or the paid seat count | the paid seat count |
| Active one-time links | 5 | no limit | no limit |
| File storage | 1 GB per person | 2 GB per seat, pooled | 10 GB per seat, pooled |
| Event log | | last 30 days | last 365 days, with CSV export |
| Policies | | defaults only (read-only) | editable |
| Single sign-on | | no | yes |
| Verified domains and domain auto-join | | no | yes |
| Admin account recovery | | no | yes |
| Risk dashboard | | no | yes |
| Organisation logo | | no | yes |

Seats are active members plus pending invitations, counted once per email address. Disabled members don't count.

Reading, decrypting, exporting and deleting are never blocked. Going over a limit only blocks new invitations, new records in team folders and new file uploads.

## The 14-day trial

A new organisation gets 14 days of Business features, with no card. During the trial the seat allowance is 10. Owners and admins see "Business trial: n days left" in the Admin area.

When the trial ends, the organisation becomes Team. Nothing runs to make this happen: the plan is worked out from the trial end date.

## Errors

Refusals are `402` with these bodies.

| `error` | Extra fields | Shown to the person as |
|---|---|---|
| `plan_required` | `feature`, `requiredPlan` | Available on the Business plan. |
| `seat_limit` | `used`, `allowed` | All {allowed} seats are in use. An owner can add seats. |
| `link_limit` | `limit` | You can have 5 active one-time links. Revoke one to make another. |

A bulk invite reports `seat_limit` per row ("No seat left") and still invites the rows that fit. Storage refusals keep the existing `quota_exceeded` error.

## Setting a plan

Until billing is connected, an operator sets plans by hand:

    npm run set-plan -- --org <id> --plan team|business [--seats N]

Run it from `apps/api` (or `npm run set-plan -w @clane-vault/api -- ...` from the repo root). Business always needs `--seats`.

## Turning hosted mode on over existing organisations

Every organisation starts as Team. An organisation that already uses single sign-on, policies or admin recovery would lose those features.

Before you set `BILLING_MODE=hosted`, run `set-plan --plan business --seats N` for each existing organisation that needs them. Stored settings are never deleted. A stored "Require SSO" is not enforced on Team, so members can still sign in with their password and authenticator.
