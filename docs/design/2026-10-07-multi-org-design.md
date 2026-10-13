# Multiple organisations — design

Date: 2026-10-07 · Status: approved direction, implemented in 0.6.0 (unreleased), hardened after the security review
(section 10)

## 1. Goal

One hosted instance serves many organisations (tenants). A self-hosted install keeps working with exactly one
organisation and no visible change beyond an organisation name at the top of the sidebar.

- **Users are global.** One account = one email, one master password, one key pair, one authenticator, one recovery
  kit. A person who works with two organisations has one account and switches between them.
- **Everything shared is org-scoped.** Roles, admin status, disablement, invites, team folders (and their members and
  pending members), direct shares, one-time links on org records, admin-recovery policy, escrows, recovery requests and
  events belong to one organisation.
- **Private items belong to the user**, not to an organisation. Since section 11 (spaces) they live in the user's
  **Personal** space and never show inside an organisation (before: in every organisation as "Private").
- **Backups are instance-level** (one database), visible only to an *instance admin*.

## 2. Data model

```
Organization  id, name, slug (unique), createdAt,
              adminRecoveryEnabled, adminRecoveryChangedBy, adminRecoveryChangedAt   (was OrgSettings id=1)
Membership    orgId, userId (unique together), role owner|admin|member, status invited|active|disabled,
              adminSince, adminRecoveryAckAt, invitedById, createdAt (invited at), joinedAt
```

Changes to existing tables:

| Table | Change |
|---|---|
| `User` | `role`, `adminSince`, `adminRecoveryAckAt` move to `Membership` (dropped after copying). `status` stays global (`pending_2fa`, `active`, `disabled` — a globally disabled account can't sign in at all). |
| `Invite` | `orgId` (required). Invite links are for people without an account; existing users get an `invited` membership instead. |
| `Folder` | `orgId` (required for team folders, null for private folders; `ON DELETE SET NULL`). |
| `RecordAccess` | `orgId` on direct user shares (the org the share was made in). Owner rows and folder rows have none. `ON DELETE CASCADE`. |
| `ShareLink` | `orgId`: the org of the record (team record) or of the share the creator holds; null for links on the creator's own private records. |
| `Event` | `orgId` (nullable): the org the action happened in. |
| `AdminRecoveryEscrow` | `orgId`; unique `(orgId, userId, adminId)`. |
| `RecoveryRequest` | `orgId`: the org whose admins handle it. |
| `OrgSettings` | dropped (moved into `Organization`). |

A record's organisation is derived, never stored twice: `recordOrg(r) = r.folder.kind = team ? r.folder.orgId : null`.

The **default organisation** is the oldest one (`createdAt`, then `id`). It can't be deleted.

## 3. Migration of existing single-tenant data

One SQL migration (`20261007000000_organizations`), run by `prisma migrate deploy` on start:

1. Create `Organization` and `Membership`; insert one default organisation (name `''` = "not named yet", slug
   `default`), copying the admin-recovery policy from `OrgSettings` row 1.
2. Every user gets a membership in it: `role` from `User.role` (admin → admin, member → member), `adminSince` and
   `adminRecoveryAckAt` copied, `joinedAt = createdAt`, `status = active`, or `disabled` for disabled users (who also
   stay globally disabled, as before: they still can't sign in).
3. The oldest active admin (by `adminSince`, then `createdAt`) becomes the **owner**.
4. `orgId = default` on all invites, team folders, direct shares (non-owner user rows), links on team-folder records,
   events, escrows and recovery requests.
5. Drop `User.role`, `User.adminSince`, `User.adminRecoveryAckAt` and `OrgSettings`.

On start the API names an unnamed default organisation `DEFAULT_ORG_NAME`, or `"<PRODUCT_NAME> org"`, and creates a
default organisation if none exists (fresh install). Zero data loss is covered by `test/org-migration.test.ts`, which
migrates a database seeded at the previous schema.

## 4. Isolation rules (server)

**Active org.** Org-scoped routes read `X-Org-Id`. The value must be the id of an organisation in which the caller has
an **active** membership (checked in the database on every request, so a disable or removal applies at once). Anything
else — missing (where required), malformed, unknown org, invited/disabled membership, another user's org — is
`403 {error:"org_forbidden"}` (`org_required` when missing). The client can't widen access by spoofing the header: the
membership check is the authorisation.

When the org has single sign-on with "Require SSO for members" (`docs/sso.md`), a member whose address is in one of
its verified domains (not the owner) also needs a session established by that org's SSO, else
`403 {error:"sso_required", orgId}`.

| Route group | Header | Rule |
|---|---|---|
| `/auth/*`, `/auth/recovery/*`, `/public/links/*` | — | Global / public. |
| `/me`, `/me/orgs`, `/me/invitations/*`, `/orgs` (create), `/me/recovery-kit` | — | Global, about the caller. |
| `/me/security`, `/me/admin-recovery-ack`, `/me/escrows` | — | Per org inside the body/response (every org the caller is active in). |
| `/sync` | optional | Private items always; team folders, team records and direct shares only of the active org. No header → private only. |
| `/records/*`, `/folders/*`, `/records/batch`, `/links*` | optional, required for anything in an org | A record is reachable only when its org is null (private) or equals the active org. Direct shares count only when made in the active org. Team folders must belong to the active org. |
| `/users` (share/member picker) | required | Active members of the active org only. |
| `/pending-members`, `/folders/:id/pending-members*` | required | Folders of the active org; completion only for an active member of that org. |
| `/admin/*` (people, invites, members, recovery settings and requests) | required | Caller must be `owner` or `admin` **in that org**, read from the database. |
| `/admin/backups*` | — | Instance admin only. |
| `/org` (details, rename, transfer, delete, leave) | required | Rename/transfer/delete: owner. Leave: any member but the owner. |

**Sharing.** Direct record shares (`POST /records/:id/shares`) need an active org; the record must be private or in
that org and the recipient must be an active member of it. The share row carries the org. Folder members must be active
members of the folder's org.

**Admin power is per org.** Disable/enable/remove/role changes act on the membership in the active org only.
Resetting a member's 2FA changes the global account, so it is allowed only to an instance admin, or to an admin who
is an admin (or owner) of **every** organisation the member is active in, and never for someone who owns any
organisation (only an instance admin may reset an owner). Re-enabling a globally disabled (legacy) account follows the
same rule; an `invited` membership can never be "enabled" (only its invitee accepts it).

**Owner.** Exactly one per org. Owners can't be disabled or removed; they transfer ownership first. Admins can't act on
themselves (use Leave).

**Instance admin** = an active account with `User.instanceAdmin` set. It is bound to the account, never to an email
address: the bootstrap invite sets it, the multi-org migration sets it for the default organisation's owner, and the
operator changes it with `node dist/src/scripts/instance-admin.js --email … --grant|--revoke`. Only instance admins see
Backups and can start a backup. `node dist/src/scripts/org-owner.js --email … [--org slug]` sets an organisation's owner
(an org left without one, or a lost owner account).

**Offboarding** (removal by an admin, or leaving) runs in one transaction, per org:
- every live team folder of the org the user belongs to: the existing folder-member removal (their rows on the folder's
  records go, records they owned there pass to the folder owner, their links on them are revoked); folders they own pass
  to another member who already holds the folder key (an editor, org admins first, else a viewer; never a use-only
  member) and a folder with no such member is moved to the trash;
- direct shares made in the org, to or from them, are deleted and links of people who lost access are revoked;
- their live links with that org are revoked; their escrows in the org (as member and as admin) are deleted; their open
  recovery requests in the org and links they approved there end; pending folder-member rows for their email go.

Disable keeps folder memberships (enable restores them) but revokes the org's links they made, deletes their escrows in
the org (as member and as admin), and ends their recovery requests and approvals in the org. Enabling restarts an
admin's `adminSince`. Demoting an admin deletes the escrows they hold and ends the links they approved. The account and
private items are untouched in all cases.

## 5. Invites and membership lifecycle

- An org admin invites an email with a role (`admin`/`member`). The answer is always `201 {invited, email, role,
  emailed}` (plus a one-time `inviteUrl` when self-hosted) whether the address has an account, is already a member or is
  already invited: the endpoint is not an account oracle. People lists invitations by email only until accepted.
  - **No account** for that email: an invite link (token hash stored). Registering through it creates the account and an
    active membership. Other open invite links for the same email (other orgs) turn into `invited` memberships.
  - **Existing account**: an `invited` membership (no new account); they are emailed and see it in the org switcher with
    Accept / Decline. Self-hosted, a (useless for them) link is made too so the answer looks the same. Accepting makes it
    `active`; invitations last 7 days.
  - **`HOSTED_MODE=true`**: links are never shown to admins, only emailed (refused with `email_required` when email isn't
    set up), and registering also needs a 6-digit code emailed to the invited address (`POST /auth/register/code`;
    10 minutes, 5 wrong tries burn it). An admin can't create an account for somebody else's address.
  - Spam limits: `INVITES_PER_ORG_PER_DAY` (default 50) per org, and a 24-hour cooldown per address after a decline or a
    cancelled invitation. Organisation and display names are cleaned (control characters and newlines removed, spaces
    collapsed, at most 60 characters) and may not contain links or email addresses; emails are plain text.
- `ALLOW_ORG_CREATION` (default `false`; hosted operators set `true`): signed-in users can create organisations and own
  them, at most `MAX_OWNED_ORGS` (default 5) each.
- Owner: rename, transfer ownership to an active member (the old owner becomes admin), delete. Delete needs the org's
  name typed in; with team folders left it needs `trashTeamFolders: true`, which **deletes** its team folders, their
  records, members and pending members in one transaction and revokes their links. The default org can't be deleted.
- Members leave (owner must transfer first).

## 6. Account recovery per organisation

> **Superseded in 1.2** by per-org key pairs (`2026-10-08-per-org-keypairs.md`). Admin recovery now escrows a membership
> key per organisation, works for people in several organisations, and restores only that organisation. The
> single-org rule below no longer applies; it is kept for history.

- The admin-recovery policy (on/off, who/when) is a property of each organisation.
- **Only for accounts in exactly one organisation.** The escrow is of the global user key, so an org's admins holding it
  could open the whole account, including other organisations' records. Therefore escrows (`PUT /me/escrows`),
  acknowledgements and "Ask an admin to reset my password" only work while the account is an active member of exactly
  one organisation. When it becomes active in a second one (accepting an invitation, creating an org, being re-enabled),
  the same transaction deletes all its escrows, ends its open requests and clears its acknowledgements; the person and
  the admins of the org(s) that held escrows are emailed ("admin recovery turned off: X joined another organisation").
  The app asks for confirmation before accepting or creating. Back to one org, a fresh acknowledgement is needed.
- Escrows are `(org, user, admin)`; approval needs the escrow for that org and the approver's `adminSince` **in that
  org**. Recovery emails name the organisation whose admin opened the escrow or approved.

**Long-term fix: per-org key pairs.** Give each membership its own key pair and wrap every key the org may reach (team
folder keys, records shared in the org) to that membership key instead of the account key. Admin recovery would then
escrow only the membership key: an org's admins could restore access to that org's items and nothing else, and the
single-org restriction above could go. It needs a key migration for existing folders and shares and a re-share flow
when someone joins; it is out of scope for 0.6.0.
- `GET /auth/recovery/options` says whether any org has the policy on (it never says anything about an account).

## 7. API additions

```
GET    /me/orgs                      → { orgs:[{id,name,slug,role,isDefault}], invitations:[{orgId,orgName,role,invitedBy,invitedAt}], allowOrgCreation, instanceAdmin }
POST   /me/invitations/:orgId/accept | /decline
POST   /orgs {name}                  → 201 {id,...}   (403 org_creation_disabled)
GET    /org                          → {id,name,slug,createdAt,isDefault,myRole,memberCount,teamFolderCount}
PATCH  /org {name}                   owner
POST   /org/transfer {userId}        owner
DELETE /org {confirmName, trashTeamFolders?}   owner
POST   /org/leave                    any non-owner member
DELETE /admin/members/:userId        admin: remove (or cancel an invited membership)
PATCH  /admin/members/:userId {role} admin: admin ↔ member (not the owner)
POST   /admin/invites                → {kind:"link", inviteUrl, ...} | {kind:"existing", ...}
```

`login`, `refresh`, `totp/verify`, `recovery/finish` and `/me` also return `orgs` (active memberships) so the app can
pick an org before the first sync. The access token no longer carries a role.

## 8. Web

> **Superseded in part by section 11** (spaces in the URL): the switcher lists Personal and each org and navigates; the
> URL decides the active space; a new device opens Personal.

- Org switcher at the top of the sidebar: current org name and chevron; the menu lists orgs with the caller's role,
  pending invitations (badge on the trigger) with Accept / Decline, "Create organisation" and "Organisation settings".
- The last org is remembered per user in `localStorage` (`cv.org.<userId>`); unknown → default org → first org.
- `api.ts` sends `X-Org-Id` on every request; every org-scoped query key includes the org (`scope = userId:orgId`).
  Switching org wipes decrypted keys from the vault cache and removes every cached query except global ones, then the
  new org loads.
- `user.role` in the app is the caller's role in the active org (`owner` counts as admin for the UI).
- Settings → Organisation: name (rename for owner), member count, transfer ownership, delete (type the name), leave.
- People / Migrate / recovery requests use the active org; Backups is shown to instance admins only.

## 9. Threat model (see section 10 for the review fixes)

| Threat | Mitigation |
|---|---|
| Member of A reads B's data by sending B's id in `X-Org-Id` | Header is checked against an active membership in the DB on every request (403). |
| Member of A reaches B's records by id (records, links, activity, shares, moves) | `accessFor` returns nothing when the record's org isn't the active org; non-owner share rows count only in their org. Owner rows on team records of another org don't count either. |
| Admin of A uses admin power on B or on B's members | Admin checks read the role in the **active** org; every admin route resolves targets through memberships of that org. |
| Admin of A resets the 2FA of someone also in B to take over the global account | Only allowed to instance admins or to someone who is admin of every org the member is in. |
| Admin of A sees B's people via the share picker | `/users` lists active members of the active org only. |
| Disabled in A but active in B | The header check fails for A only; everything in B keeps working. |
| Org deletion leaves dangling access | Team folders are trashed, links revoked, memberships/escrows/requests/invites/org shares cascade. |
| Admin recovery in org B gives B's admins the whole account | Unavoidable with a global user key; disclosed per org, needs a per-org acknowledgement, and the existing two-person rule, approver age and waiting period apply per org. |
| Escrow uploaded for the wrong org | `PUT /me/escrows` checks per entry: policy on in that org (row locked), acknowledged, admin active in that org. |
| Cached data of org A shown after switching to B | Query keys include the org; switching removes org-scoped cache and wipes decrypted keys. Since section 11 the switch happens before the new space paints and the vault screen remounts per space. |

Residual risks: a person in several orgs with admin recovery on in each is recoverable by the admins of each (by design,
disclosed). Event rows are per org but the admin activity log UI doesn't exist yet. Private-record shares made in org A
are invisible while working in org B (by design: shares live in an org context).

## 10. Security review fixes (before release)

| Finding | Fix |
|---|---|
| C1 account squatting through copied invite links; instance admin by email | `HOSTED_MODE`: links only emailed, sign-up needs an emailed code. Instance admin is a `User.instanceAdmin` flag set by bootstrap/migration/CLI only. `ALLOW_ORG_CREATION` defaults to false. |
| C2 escrow of the global key gives one org's admins every org | Admin recovery only for single-org accounts; joining a second org ends escrows and requests with notice (section 6). |
| I1 invite endpoint as an account oracle | Identical answers; People shows invitations by email only; the Keeper migration only shows org members as "added now". |
| I2 invite spam and phishing names | Daily cap per org, 24-hour cooldown per address, name cleaning and link/email refusal. |
| I3 activity and links across orgs | Activity: active org's events plus the record's org-less events (all for its owner, the owner's own for others). Links: the owner sees the active org's and personal ones, others their own in the active org. Events are logged with the org the access came through. |
| I4 resetting an owner's 2FA; enabling an invitation | Owners only by an instance admin; invitations can't be enabled. |
| Minor | Migration owner fallback (longest-standing active member) and `org-owner` CLI; org delete purges team folders; moving a private record into a team folder ends shares made in other orgs; disable drops the member's escrows, enable restarts `adminSince`; demotion ends approved links; folder successors never use-only; per-user owned-org cap; the web pins `X-Org-Id` per operation (a mutation started in org A finishes in A). |

Re-review fixes:

- **Races.** Joining an org (accept, create, enable), escrow uploads and "ask an admin" requests take a row lock on the
  account (`SELECT … FROM "User" … FOR UPDATE`) first, so "exactly one org" is checked and acted on atomically. Escrow
  release, approval, link use and `/finish` re-check that the account is still in exactly one org (`409 multi_org`).
- **Sign-up codes.** Each try is counted atomically before the comparison (5 per code); 15 wrong tries per invite burn
  the invite; at most 5 codes per invite; `/auth/register` is limited to 10 per minute per address.
- **Org deletion** deletes the org's events as well (otherwise they'd become org-less and show as private context).
- **Instance admin** is revoked (event `instance.admin_revoked`) when the account stops being an active owner or admin
  of the main organisation (removed, left, disabled, demoted); a transfer keeps it (the old owner stays admin).
- **Invite dates.** An invite turned into an invitation at registration keeps the invite's date, so the inviting org
  can't tell when the account was created.
- **Record moves** drop shares from other orgs and revoke links inside the same transaction.
- Escrowed keys are never rotated (`docs/recovery.md`).

Residual: self-hosted mode keeps copyable invite links (the admin can register an account for an address they invited);
operators who don't trust their org admins should run with `HOSTED_MODE=true`.

## 11. Spaces: Personal and each organisation, in the URL (2026-10-10)

**Report.** "When I create a new org and switch org I still see passwords and folders from the previous org."

**Diagnosis** (isolated stack: user A in org X with a private folder, a private record, a team folder with a record;
creates org Y from the switcher; switches). Org Y showed the private folder and the private record, and nothing of X's
team folder or its record. `GET /sync` with `X-Org-Id: Y` returned only the private folder and record; with X it
returned those plus X's team folder and record; record and folder routes for X's items with `X-Org-Id: Y` (or none)
answered 404, `/links` with Y returned none. Client query keys were already `user:org` scoped and switching dropped them.
So no cross-org leak: what the user saw was the "private items in every org" rule of section 1, which read as data
from the previous org. Decision (product): a separate Personal space.

**Model.**
- **Personal** (no `X-Org-Id`): the user's private folders and records. Nothing shared by others (direct shares always
  belong to an org, `RecordAccess.orgId`), no team folders.
- **An organisation** (`X-Org-Id` + `GET /sync?space=org`): its team folders the user belongs to and their records,
  records shared with the user in that org, and the user's own private records that they shared in that org (so they
  can manage those shares there). No other private item, ever. `privateLocked` is never set there.
- A private folder inside an org does not exist in the data model: in an org, + New offers shared folders and records in
  them (Location lists its shared folders only; "No folder" is not offered; Import says it goes to Personal); in Personal,
  private folders and records (Shared Folder says it belongs to an organisation). A team record still can't move out to
  private (`409 org_record`); in an org, Move To lists its shared folders only.
- Sharing a private record from Personal: the share sheet asks which organisation to share it in, lists that org's
  people (`X-Org-Id` of that org, sealed to their membership key there) and posts the share with that org's header. The
  record then also shows in that org. Personal `GET /sync` lists `sharedIn: [orgId]` on owned records (ids only, orgs
  the user is still active in), and the sheet links to "Manage in <org>".
- `GET /links?space=org`: the org's links only; no header: personal links only. `/sync` and `/links` with `X-Org-Id`
  but without `space` keep the old behaviour (org + private) for browser extensions before this change.
- No crypto changes: per-org membership keys, folder keys and the zero-knowledge model are as before; the org space's
  sync still carries `membershipKeys`, bound by the client to the org it asked for.

**Routes** (`apps/web/src/lib/paths.ts`; the URL is the source of truth for the active space):

| Path | Page |
|---|---|
| `/p/vault`, `/p/vault/folder/:id`, `/p/vault/record/:id` | Personal vault, open folder, record |
| `/p/attention[/record/:id]`, `/p/links`, `/p/trash[/record/:id]` | Personal lists (no "Shared with me": `/p/shared` → `/p/vault`) |
| `/o/:org/vault[/folder/:id \| /record/:id]` | The org's vault |
| `/o/:org/shared[/record/:id]`, `/o/:org/attention[...]`, `/o/:org/links`, `/o/:org/trash[...]` | The org's lists |
| `/o/:org/admin` → first section; `/o/:org/admin/{people[/:userId], groups[/:groupId], events, health, migrate}` | Org admin (owners, admins) |
| `/o/:org/admin/org/{general, policies, sso, recovery, email}` | Org settings |
| `/server`, `/server/{branding, email, backups}` | The server's pages (instance admins), outside any org |
| `/settings`, `/settings/{account, security, device, extension, health}` | Personal settings (global; Password health shows the space in use) |
| `/`, `/vault/...`, `/shared`, `/attention`, `/links`, `/trash/...` | Redirect into the space used last |
| `/admin/...`, `/org/...`, `/settings/org/...`, `/migrate` | Redirect into the last org's admin pages (from Personal: an org the user administers); `/admin/server/*`, `/admin/backups` → `/server/*` |

`:org` is the organisation's slug (unique in the database), or its id. It is resolved against the user's own orgs only:
an org the user isn't an active member of — deleted, left, never joined, or not existing — shows the same "You can't open
this organisation" page with a link to Personal, so a URL never tells whether an org exists.

**Client isolation.**
- `SpaceGate` (`routes.tsx`): when the URL names another space than the session's, the session switches in a layout
  effect and nothing renders meanwhile, so the previous space's data never paints. The vault screen is keyed by the
  space: selections, open panels and searches reset. Switching (`activate`) wipes decrypted keys in the vault cache
  and drops every space-scoped query; every space-scoped query key carries `user:org` (`-` for Personal): vault, links,
  people, groups, activity, admin, policies, health, events, pending members.
- The switcher (Personal, each org, invitations) and accepting/creating an org navigate; leaving or deleting the active
  org goes to Personal. The space used last is remembered per device and user (`cv.org.<userId>`: an org id, or `-`); a
  device with none opens Personal. Old paths redirect into it.
- The offline copy is per space: Personal's sync under `-`, each org's `?space=org` sync under its id.
- An SSO sign-in lands in that org's vault; the "requires single sign-on" panel offers Personal.
- Browser extension: the space menu lists Personal and each org (`?space=org` for an org, no header for Personal; new
  device: Personal); a saved new login always goes to Personal.

**Tests.** API: `test/orgs.test.ts` (spaces: org-only sync and links, Personal with `sharedIn`, refusals). Web:
`lib/paths.test.ts`, `features/orgs/Orgs.test.tsx` (Personal on a new device; switching navigates and never shows another
space's data, checked on every DOM change; back/forward; links into an org; unknown org; old paths; invitations),
`Sharing.test.tsx` (sharing from Personal inside an org). Extension: `test/core.test.ts`. E2E: `multi-org.spec.ts`
(each space shows only its own folders and records through switching, reload and back/forward; outsider and unknown org
pages), `sharing.spec.ts`, `migrate.spec.ts`, `sso.spec.ts`, `org-policy/admin-recovery.spec.ts`.

**Not done (follow-ups).** Moving an existing private record into an org's shared folder needs it to be visible in the
org first (share it there, or recreate it); a "Move to organisation" action would close that gap.
