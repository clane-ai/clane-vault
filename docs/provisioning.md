# User provisioning

How people get into an organisation, modelled on Keeper's provisioning options. Everything here is in the app
(**Admin → People**, and **Organisation settings → Single sign-on** for domains) and in the REST API, so admins can
script it.

| Keeper | Clane Vault |
|---|---|
| Manual invite / bulk upload in the Admin Console | **Invite people**: pasted addresses or a CSV, with a role and groups (below). The single-address form stays for quick invites. |
| Pending invitations, resend | **Invitations** on People: filter, Resend, Resend all pending, Revoke, expiry; CSV export. |
| Email auto-provisioning (reserved domain, default role) | **Email domain auto-join** for a domain the organisation verified by DNS. |
| SSO with just-in-time provisioning | [Single sign-on](sso.md) with **Auto-join verified domain users**. |
| Default teams for new users | Groups chosen at invite time (or for auto-join) apply when the person joins: **pending group memberships**. |
| AD bridge, SCIM | Not yet. Script the REST API below, or use SSO just-in-time joining. |

Zero knowledge doesn't change: nobody gets a folder key from being provisioned. Groups shared with team folders still
need a key holder (folder owner or editor) to **approve** each new member explicitly, exactly as when an admin adds
someone to a group ([groups](groups.md)).

## Invite people (bulk)

**Admin → People → Invite people**:

1. **Paste addresses** (separated by commas, semicolons, spaces or new lines; `Ann <ann@company.com>` works) or
   **Upload CSV**. CSV columns: `email`, `name`, `role` (`member` or `admin`), `groups` (group names, several separated
   by `;`). A header row is optional and may list the columns in any order; without one they are read in that order.
   Up to 500 rows at a time.
2. Choose the **role** for rows without their own, and **groups** everyone joins (on top of each row's groups).
3. **Preview**: the server checks every row and nothing is created or sent yet. Each row is *Ready*, *Invalid
   address*, *Invalid role*, *Unknown group*, *Duplicate* (same address earlier in the list), *Already a member*,
   *Already invited*, *Declined recently* (the address declined or an invitation was cancelled in the last 24 hours)
   or *Over today's limit*.
4. **Send**: one request; each row's result. Self-hosted, every new invite link is shown once to copy (each, or
   **Copy all links** as `email,link` lines); hosted, the links are only ever emailed.

What happens for each invited address is the same as for a single invite: an address without an account gets an
invite link (7 days) to create one; an existing account gets an invitation to accept in the app. The answer never says
whether an address has an account (only whether it is a member or invited *here*, which admins see on People anyway).

Limits: the organisation's daily cap (`INVITES_PER_ORG_PER_DAY`, default 50) counts every invitation sent in 24 hours,
new ones and resends alike, whichever way they were sent; rows beyond it are *Over today's limit*. `HOSTED_MODE`
refuses bulk invites without email set up (`409 email_required`), as for single invites. The endpoint is
rate-limited (10 requests a minute).

Events: one `admin.invite` per invitation (`meta.bulk: true`) and one `admin.invite_bulk` summary (`requested`,
`invited`, `emailed`, counts per outcome).

### Pending group memberships

Groups chosen for an invitee are stored against their address (`PendingGroupMember`) and become group memberships when
they **join**: at sign-up through the invite link, when an existing account accepts in the app, or at an SSO sign-up
with the invite. The membership counts as added by the admin who invited them (`group.member_add` with
`meta.via: "invite"`), so the folder owner's approval prompt shows who caused it. Revoking or declining the invitation,
removing the person, or deleting the group drops them.

## Invitations

**Admin → People → Invitations** lists open invitations (and those that expired in the last 30 days), with a filter by
address and status (Pending, Expired, All), the role, the groups waiting for them, when it was sent and by whom, and
when it expires. Invitations from email domain auto-join are marked **Domain auto-join**.

- **Resend**: a fresh 7 days and the email again. An invite link gets a **new token** (the old link stops working);
  self-hosted, the new link is shown to copy. Not more than once every 5 minutes per invitation (`429 too_soon`);
  counts toward the daily cap (`429 invite_limit`). Event `admin.invite_resend`.
- **Resend all pending**: every pending invitation, oldest first, until the cap is reached (the rest are reported
  as skipped). Event `admin.invite_resend_all`.
- **Revoke**: as before (the address cools down for 24 hours). Its pending group memberships go too.
- **Export CSV** (page header): **Members** (`name, email, role, status, two_factor, joined_at, groups`) or
  **Invitations** (`email, role, status, source, groups, invited_at, expires_at, last_sent_at, resend_count,
  invited_by`). Cells that start with `= + - @` are prefixed with `'` (spreadsheet formula injection). Event
  `admin.export`.

## Email domain auto-join

Keeper's "email auto-provisioning": anyone with an address in the organisation's domain may join it.

- **Owner only**, **off by default** (Organisation settings → Single sign-on → Email domain auto-join). Admins see it.
- Needs a domain **verified by this organisation**: the same DNS TXT check as for SSO (`clane-vault-verify=<token>` on
  the domain; SSO itself doesn't have to be set up). One organisation per domain: another organisation can't verify a
  domain already verified (`domain_taken`), and if two ever held the same verified domain, nobody joins through it.
  Public email providers (Gmail, Outlook, Yahoo, iCloud, Proton…) can never be added.
- Needs email delivery (the join link is always emailed): `409 email_required` otherwise.
- People join as **members** (never admins or owners), into the groups the owner picked.
- The join page is `${PUBLIC_URL}/join`, also linked from the sign-in page ("Join your organisation with your work
  email"). The person types their address; the answer is always the same ("if your organisation lets people with
  this domain join, we've emailed you a link"), so it reveals nothing about organisations, accounts or members.
- An eligible address gets an invitation (source `domain`) and an email:
  - no account: an invite link to create one: master password, **authenticator (2FA)** and recovery kit as usual
    (`HOSTED_MODE` also asks for the emailed sign-up code);
  - an existing account: a `/join/<token>` link. Signed in with **that** address, it becomes an invitation to accept
    from the organisation menu (where the organisation's master password rule is checked). Any other account gets the
    same 404 as for an unknown link.
- Nothing happens for addresses that are already members (or disabled, or invited by an admin: their invitation
  stands), that declined in the last 24 hours, or when the organisation reached its daily limit of auto-join emails
  (`INVITES_PER_ORG_PER_DAY`). A repeated request within 5 minutes sends nothing new; a later one sends a new link.
- At every request the domain must still be verified: its TXT record is looked up again when it wasn't seen in the
  last 24 hours, and a record that is gone un-verifies the domain and switches auto-join (and SSO's Require SSO and
  auto-join) off. Removing the last verified domain switches it off too, so while it's on only the owner can remove
  that domain (`403 owner_only_last_domain` for an admin). DNS failures refuse (fail closed).
- Owners and admins are emailed when it is turned on or off or its groups change. Events:
  `org.domain_join_enabled` / `_disabled` / `_updated`, `org.domain_join_request` (`meta.domain`), `org.domain_join`
  (`meta.via: "signup"`), `org.invite_claimed` (`meta.source`).

## Organisations for customers

On a hosted server the operator (an instance admin) sets up one organisation per customer without joining it:
**Server → Customer organisations**, with the organisation's name and its owner's email address.

- The organisation is created with **no members** and an **owner invitation** for that address. The instance admin
  never becomes a member and sees nothing inside it: the list shows only the name, the date, the owner's address as
  typed, and whether the invitation is **Pending**, **Expired** or **Accepted**.
- **Someone without an account** gets an invite link (HOSTED_MODE: only by email, and sign-up needs the emailed code;
  self-hosted, the link is also shown once to pass on). Signing up through it makes them the owner.
- **Someone with an account** gets an invitation to accept from the organisation menu (self-hosted, also a link). An
  invite link that meets an account made later (claimed at `/join/<token>`, or met when they sign up through another
  organisation's invitation) stays an owner invitation.
- Accepting makes them the organisation's only owner. It counts toward their `MAX_OWNED_ORGS` (`409 org_limit` when
  accepting, as for a transfer). Creating one isn't limited by `ALLOW_ORG_CREATION` or `MAX_OWNED_ORGS`. The instance
  admin can't invite their own address (`400 self`).
- **Keys**: nothing is made on the server. As in any organisation, the owner's browser creates their membership key
  pair the first time they unlock in it (`docs/design/2026-10-08-per-org-keypairs.md`, 6.1), and what they share there
  is sealed to it. Admin recovery starts off.
- **Resend invite**: a fresh 7 days and the email again (a link gets a new token), not more than every 5 minutes, and
  not within a day of a decline. **Cancel** deletes the organisation, which nobody has joined, and its invitation. An
  accepted one can't be cancelled here (`409 accepted`): its owner can delete it.
- Events: `org.create` (with `for: "customer"`), `admin.invite` and `admin.invite_resend` in the new organisation's
  log, so its owner sees who set it up; `instance.customer_org_create`, `instance.customer_org_resend` and
  `instance.customer_org_cancel` at instance level.

This replaces creating the organisation yourself, inviting the customer as an admin, transferring ownership and leaving.

| Method and path (instance admins; no `X-Org-Id`) | Body | Answer |
|---|---|---|
| `GET /admin/instance/orgs` | — | `{ orgs: [{ id, name, ownerEmail, createdAt, status, expiresAt }], hostedMode, emailConfigured }` |
| `POST /admin/instance/orgs` | `{ name, ownerEmail }` | `201 { org, emailed, inviteUrl? }`; `400 self`, `409 email_required` (10 a minute) |
| `POST /admin/instance/orgs/:orgId/resend` | — | `{ org, emailed, inviteUrl? }`; `404 not_found`, `409 accepted`, `409 invite_cooldown`, `409 email_required`, `429 too_soon` |
| `DELETE /admin/instance/orgs/:orgId` | — | `204`; `404 not_found`, `409 accepted` |

## Onboarding checklist

New organisations (their first 30 days) see **Set up your organisation** at the top of Admin → People: invite people,
create a group, set policies, turn on admin recovery, set up sign-in and email (SSO, email domain auto-join or the
organisation's own email). Each step is ticked from the real state (an open invitation or a second member, a group,
policies saved once, admin recovery on, SSO / auto-join / email settings present) and links to its page. Any owner or
admin can dismiss it for the organisation (`org.onboarding_dismissed`).

## REST API

All under `/api/v1`, with `Authorization: Bearer <access token>` and `X-Org-Id: <organisation id>`; the caller must be
an owner or admin of that organisation (checked on every request). Errors are `{ "error": "<code>" }`.

| Method and path | Body / query | Answer |
|---|---|---|
| `POST /admin/invites` | `{ email, role? }` | `201 { invited, email, role, emailed, inviteUrl? }` (single invite, unchanged) |
| `POST /admin/invites/bulk` | `{ rows: [{ email, name?, role?, groups? }], role?: "member"\|"admin", groupIds?: uuid[], dryRun?: boolean }` (`groups`: names or ids, a list or one `;`-separated string; max 500 rows) | `{ dryRun, counts, cap: { perDay, sentToday, remaining }, results: [{ row, email, name, role, groups, status, detail?, emailed?, inviteUrl? }] }`; `status` is `valid` (dry run), `invited`, `invalid_email`, `invalid_role`, `unknown_group`, `duplicate`, `member`, `already_invited`, `cooldown`, `over_cap` or `failed`. `400 group_not_found`, `409 email_required` |
| `GET /admin/invites` | `?status=pending\|expired\|all&q=<text>` | `{ invites: [{ id, email, role, source, groups, createdAt, expiresAt, expired, lastSentAt, resendCount, invitedBy }], cap, counts: { pending, expired }, emailConfigured, hostedMode }` |
| `POST /admin/invites/:id/resend` | — | `{ id, email, emailed, inviteUrl? }`; `404 not_found`, `409 email_required`, `429 too_soon`, `429 invite_limit` |
| `POST /admin/invites/resend-all` | `{ includeExpired?: boolean }` | `{ resent, skipped, results: [{ id, email, status, emailed?, inviteUrl? }], cap }` |
| `DELETE /admin/invites/:id` | — | `204` (revoke) |
| `GET /admin/people/export.csv` | — | `text/csv` |
| `GET /admin/invites/export.csv` | — | `text/csv` |
| `GET /admin/settings/domain-join` | — | `{ enabled, role, groups, domains: [{ domain, verified }], emailConfigured, joinUrl, canEdit, updatedAt, updatedBy }` |
| `PUT /admin/settings/domain-join` | `{ enabled, groupIds? }` | the same view; `403 owner_only`, `400 group_not_found`, `409 domain_not_verified`, `409 email_required` |
| `GET /admin/onboarding` | — | `{ show, dismissed, done, total, steps: [{ id, done }] }` (`invite`, `group`, `policies`, `recovery`, `sso`) |
| `PUT /admin/onboarding` | `{ dismissed: boolean }` | `{ dismissed }` |
| `POST /auth/domain-join` (no auth) | `{ email }` | always `202 { ok: true }` (5 a minute per client address) |
| `POST /me/join` (signed in, no `X-Org-Id`) | `{ token }` | `{ orgId, orgName, status: "invited"\|"member" }`; `404 not_found` |

Rate limits per client address: bulk 10/min, resend 30/min, resend all 5/min, exports 10/min, domain-join settings
20/min, `/me/join` 10/min.

Example: invite a CSV's people as members into "Engineering" (the group's id from `GET /admin/groups`), checking first:

```sh
API=https://vault.example.com/api/v1
H=(-H "Authorization: Bearer $TOKEN" -H "X-Org-Id: $ORG" -H "Content-Type: application/json")
BODY=$(jq -Rn --arg g "$GROUP_ID" '[inputs | split(",") | {email: .[0], name: .[1]}] | {rows: ., groupIds: [$g]}' < people.csv)
curl -s "${H[@]}" -d "$(jq '. + {dryRun: true}' <<<"$BODY")" "$API/admin/invites/bulk" | jq '.counts'
curl -s "${H[@]}" -d "$BODY" "$API/admin/invites/bulk" | jq -r '.results[] | [.email, .status, (.inviteUrl // "")] | @tsv'
```

`resendInvite(app, orgId, inviteId, actorId, log?)` in `apps/api/src/lib/invites.ts` is the server function behind
Resend; other features (the Risk dashboard's "Resend all pending invites") call it. Its signature is kept stable.
