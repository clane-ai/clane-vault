# Password health

**Password health** (in the sidebar) checks the passwords of every record you can open in the active organisation.
That includes your private records and the records shared with you or reached through team folders. The check runs
in the browser, after the vault is decrypted. Passwords are compared in memory and never leave the device.

## Checks

| Issue | Rule |
|---|---|
| Weak | zxcvbn score ≤ 2, or shorter than 10 characters, or a word followed by a few digits (same rule as *Needs attention*) |
| Reused | The same password in two or more live records you can see |
| Old | Not changed in more than 365 days: the record's `passwordChangedAt`, else its last update |
| Breached | Found in the Have I Been Pwned "Pwned Passwords" list (opt-in, see below) |

`passwordChangedAt` is an optional field of the encrypted record body (`RecordBody` in `packages/crypto/src/records.ts`):
- the record editor sets it when the password changes, and keeps it otherwise;
- it is kept only next to a password, and only when it is a real date;
- older records fall back to the record's `updatedAt`.

The **score** is the share of passwords without any issue, from 0 to 100 (100 when there are none). The page shows the
score and the counts, plus lists you can filter by issue. Each entry opens its record in the vault.

## Breach check (Have I Been Pwned)

The breach check is off until you turn it on. The setting is per user and kept on the device (`localStorage`). An
organisation can forbid it with the `breachCheckAllowed` policy (`docs/policies.md`).

When it is on, the app uses the k-anonymity range API:
1. It takes the SHA-1 hash of each password.
2. It sends only the first 5 hex characters of the hash to `https://api.pwnedpasswords.com/range/<prefix>`. The request
   has no cookies or referrer and asks for padded answers.
3. The app compares the rest of the hash on the device.

Ranges are cached in memory for an hour. `api.pwnedpasswords.com` is in the `connect-src` of the content security
policy: `apps/api/src/plugins/web.ts` and `apps/web/index.html`.

## What admins see

After each change, the app posts **counts and the score only** to `POST /me/health-report`, per user and organisation:
`{ score, total, weak, reused, old, breached }`, where `breached` is null when the check didn't run. Unknown fields are
dropped. No password, hash, title or record id is sent or stored.

The posted counts cover the organisation's records only: records in its team folders and records shared with you in
it. Your own private records appear in every organisation's view, but they are yours, so they stay out of what admins
see (an org record whose password you also use in a private record still counts as reused).

Owners and admins see a table on the same page (`GET /admin/health`). It lists every member with their last counts,
score and time, or "No report yet". A member's report is deleted when they leave or are removed from the
organisation.

## Event log

Admins also get an **Event log** page (Admin → Event log). It shows the active organisation's events, newest first,
with filters for the person, the action (exact, or a family such as `group.*`) and a date range.

**Export CSV** streams the filtered log from `GET /admin/events/export.csv`:
- owners and admins only, org-scoped, rate-limited;
- read in pages of 1,000, so memory use stays flat;
- every cell is quoted, and cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`
  so that spreadsheets don't run them as formulas;
- each export is logged as `admin.events_export`.

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/events` | `actor`, `action`, `from`, `to` (ISO), `before` (cursor), `limit` (≤ 200) → `{ events, nextBefore }` |
| GET | `/admin/events/actions` | Actions that occur in the organisation's log |
| GET | `/admin/events/export.csv` | Same filters, streamed CSV |
