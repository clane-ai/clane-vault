# Groups

Groups let an organisation share a team folder with a set of people at once. Owners and admins create the groups
and choose who is in them. Folder owners share their team folders with groups. Everything stays zero-knowledge: the
server never holds a folder key.

## Who does what

| Action | Who |
|---|---|
| Create, rename or delete a group; add or remove members | Owners and admins of the organisation (`/admin/groups`) |
| See the organisation's groups and their members' public keys | Any member (`GET /groups`): sharing a folder seals the key to them |
| Share a team folder with a group | The folder owner, who holds the folder key |
| Change a group's permission on a folder, or stop sharing | The folder owner. An org admin may downgrade or remove, never upgrade |
| Seal the folder key to group members who are still waiting | The folder owner or any editor of the folder (both hold the key) |

Groups belong to one organisation. A group can only hold people who are members of that organisation, and it can only
be shared with team folders of that organisation. Group names follow the same rules as organisation names: no links
and no email addresses.

Invitations can name groups too (bulk invites and email domain auto-join, [provisioning](provisioning.md)): those are
**pending group memberships**, kept against the invited address, that become ordinary group memberships when the person
joins the organisation (added by the admin who invited them). Joining gives no folder key: the approval below applies
as for anyone added to a group.

## Keys and pending access

When the owner shares a folder with a group, their client seals the folder key to every current member of the group,
the same way as for a single folder member: to the person's membership key in this organisation (`s1.`, AAD
`org-folder-key:<orgId>:<folderId>`), or to their account key (AAD `folder-key:<folderId>`) while they don't have
one yet (see `docs/design/2026-10-08-per-org-keypairs.md`). Each wrap says which key it is sealed to
(`sealedTo`), and the server refuses a wrap sealed to anything but the person's current key. The client sends those
wraps with `POST /folders/:id/groups`. Sharing with a group is itself an explicit choice of the owner, who sees the
group's members.

The server can't seal the key itself. So group members who have no wrap yet are *pending*:
- people added to the group later;
- people the client couldn't seal to at the time.

The server works this out from the group grants and doesn't store it. `GET /group-access/pending` lists, for the
caller, the people waiting for folders the caller can seal (as owner or editor): name, email, the key to seal to,
the permission the groups give them, and for each group who added them to it (`via`).

**Nothing is sealed automatically.** The web app shows "N people are waiting for access" while the vault is open.
**Review** lists, per folder, each person's name and email, the group and who added them to it, and the fingerprint
of the key the folder key would be sealed to. It also warns when that key changed since this device last sealed to
them. The owner or an editor then chooses:
- **Approve**: their client seals the key and posts the wraps to `POST /folders/:id/group-access`.
- **Decline**: `POST /folders/:id/group-access/decline`. The person stays out, and the request is hidden until they
  are added to a group again.

The server decides the permission and checks each person again under the folder's row lock:
- they are in a group shared with the folder;
- they are an active member of the organisation;
- they don't already have access;
- the wrap is sealed to their current key.

Disabled members aren't offered for approval. Bulk-migration pending members (`PendingFolderMember`) are unchanged,
apart from sealing to membership keys as well.

## Permissions

`FolderMember.permission` is the effective permission: the highest of the direct grant and every group grant.
`FolderMember.directPermission` keeps the direct grant on its own, and is null when the access comes only through
groups. The folder owner's is `owner`. Group grants are `edit`, `view` or `use`.

- A direct grant on top of group access (`POST /folders/:id/members`) needs no new key. It just sets the direct grant.
- Changing a direct grant (`PATCH /folders/:id/members/:userId`) changes `directPermission`. The effective permission
  is then worked out again. Someone with access only through a group gets `409 group_access`: manage the group instead.
- Removing the direct grant (`DELETE /folders/:id/members/:userId`) keeps any group access. Someone with group-only
  access can't be removed here (`409 group_access`), and can't leave the folder themselves either.

## Removing access

The following remove the access that came only through the group. Direct grants and other groups stay:
- removing someone from a group;
- stopping sharing a folder with a group;
- deleting a group.

When someone loses all access to a folder this way, the normal offboarding runs:
- their rows on the folder's records go;
- the records they owned there pass to the folder owner;
- their live one-time links on those records are revoked.

When the effective permission only drops below `edit`, their one-time links on the folder's records are revoked.

Leaving or being removed from the organisation deletes the person's group memberships there.

## Races

Every change to who can open a folder takes a row lock on the folder (`SELECT … FOR UPDATE`). Group changes lock the
group first, then the affected folders, in a fixed (sorted) order. Sharing a folder with a group locks the group, then
the folder. A seal that arrives as someone is removed from the group either finds no grant (and does nothing) or is
undone when the removal takes the folder lock.

## Trust

As with direct sharing (see `docs/sharing.md`, *Trust limits*), public keys come from the server. Admins decide who
joins a group, so whoever manages groups could add themselves (or someone else) to a group that a sensitive folder
is shared with. A server operator could also make up such a group change. That is why the folder key never goes to
a waiting group member automatically. Someone who holds the key (the folder's owner or an editor) approves each
person, seeing who it is, through which group and who added them. The key's fingerprint is shown, and a warning
appears when it changed since this device last sealed to them. Share sensitive folders with groups only if you trust
the people who manage them, and check the prompt before approving. The people sheet shows who has access through
which group. Group changes, approvals and declines are in the event log.

## Events

- `group.create`, `group.rename` and `group.delete`, with `meta.groupId`.
- `group.member_add` and `group.member_remove`, with `targetUserId` and `meta.groupId`.
- `folder.group_add`, `folder.group_update` and `folder.group_remove`, with `meta.groupId` and `permission`.
- `folder.member_add` and `folder.member_remove`, with `meta.via = "group"` when the access came through a group.
- `folder.group_access_declined`, with `targetUserId`: a key holder declined a waiting group member.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/groups` | Groups with members and how many live folders each is shared with |
| POST | `/admin/groups` | `{ name }` → `201 { id, name }`, `409 exists` |
| PATCH | `/admin/groups/:id` | `{ name }` |
| DELETE | `/admin/groups/:id` | Ends group-only folder access |
| POST | `/admin/groups/:id/members` | `{ userIds }` (people of the org) → `201 { added }`, `400 user_not_member` |
| DELETE | `/admin/groups/:id/members/:userId` | Ends group-only folder access |
| GET | `/groups` | Any member: groups with active members' public keys and `membershipKey` |
| POST | `/folders/:id/groups` | Owner: `{ groupId, permission, wraps: [{ userId, wrappedFolderKey, sealedTo }] }` → `201 { added, pending }` |
| PATCH | `/folders/:id/groups/:groupId` | `{ permission }` |
| DELETE | `/folders/:id/groups/:groupId` | |
| GET | `/group-access/pending` | People waiting for folders the caller can seal, with `membershipKey`, `via` (group, added by) and `declined` |
| POST | `/folders/:id/group-access` | Owner or editor approves: `{ wraps: [{ userId, wrappedFolderKey, sealedTo }] }` → `{ added: [userId], skipped }` |
| POST | `/folders/:id/group-access/decline` | Owner or editor: `{ userIds }` → `{ declined }` |

`GET /sync` returns, for each team folder:
- `groups`: id, name, permission and member ids;
- `directPermission` for each member.
