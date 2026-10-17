# Team sharing (phase 2) and one-time links (phase 3)

How records and folders are shared, and what is deliberately left for later.

## Keys

| Thing | Key | Stored as | AAD |
|---|---|---|---|
| Team folder key | random 32 bytes | sealed box (`s1.`) to each member's membership key in the folder's organisation (`FolderMember.sealedTo`), in `FolderMember.wrappedFolderKey`; before the member had one, to their account key | `org-folder-key:<orgId>:<folderId>` (account key: `folder-key:<folderId>`) |
| Team folder name | folder key | `v1.` AES-GCM | `folder-name:<folderId>` |
| Record in a team folder | record key | `v1.` under the folder key, in a `RecordAccess` row with `holderType=folder` | `record-key:<recordId>` |
| Record owner's own copy | record key | `v1.` under the owner's user key (`holderType=user`, `permission=owner`) | `record-key:<recordId>` |
| Direct share | record key | sealed box (`s1.`) to the recipient's membership key in the organisation the share is made in (`RecordAccess.sealedTo`), opened on every sync | `org-record-share:<orgId>:<recordId>` (account key: `record-share:<recordId>`) |
| File on a record (1.6, `docs/attachments.md`) | file key, random per file | `v1.` under the record key (`Attachment.wrappedFileKey`); chunks AES-GCM under the file key | `attachment-key:<recordId>:<fileId>`; chunks `attachment-chunk:<fileId>:<index>:<chunkCount>` |

Membership keys (one X25519 pair per person and organisation, `docs/design/2026-10-08-per-org-keypairs.md`)
scope admin recovery to one organisation. The server refuses a wrap that isn't sealed to the recipient's current key,
and each client moves its older rows from the account key to its membership key on unlock.

`openRecordKey` in `packages/crypto/src/sharing.ts` picks the key by `holderType` and the envelope prefix. A folder row is only ever opened with a folder key, and a sealed box is only accepted for a user row. The AAD binds every wrapped key to its folder or record id, so the server can't move a wrapped key to a different record.

## Permissions

`owner > edit > view > use`. Your effective permission on a record is the highest of your direct share and your team folder membership. A team folder membership counts at most as `edit`.

Owner-only actions are trash, restore, purge, share and move. These people can take them:
- the holder of the record's owner row;
- the owner of the live team folder the record is in (they reach the key through the folder row).

Moving such a record out takes ownership: the folder owner supplies their own wrap, and the previous owner keeps `edit`.

Only the folder owner (who holds the folder key) can add members. An admin can downgrade and remove members, but can't add anyone (themselves included) or upgrade anyone.

`use` hides the password in the app but still lets the person copy it. It is a soft limit (spec §5.6). For **files** it
is a hard limit: the server refuses `use` holders the chunks (`403 use_only`), because a file can't be used without
opening it. They still see the file names (under the record key they hold, like the title).

**Files follow the record** (`docs/attachments.md`). A file's key is wrapped under the record key, so every share and
folder membership that hands over the record key hands over its files, with nothing re-encrypted. Removing access
stops the server serving the chunks at once; someone who already downloaded a file keeps it, as with any secret.

**Offboarding.** When a member is removed from a team folder or leaves it, one transaction:
- deletes every row of theirs on records in that folder, direct shares included;
- hands the records they owned there to the folder owner;
- revokes the live one-time links they created on those records.

**Deleting a team folder.** This is refused (`409 folder_has_others_records`) while the folder holds live records owned by other people. Membership of a deleted folder grants nothing.

## One-time links and import (phase 3) meet sharing

**Who can make a link.** `POST /links` uses the same effective permission (`accessFor`): the record owner, the folder owner, and anyone with `edit` (direct share or team folder membership). `view` and `use` can't, because a link hands the secret out in full. Record owners make links from the Share sheet's "One-time link" tab. Editors who aren't the owner can't share with people, so they get a "One-time link" button in the record panel instead.

**A link lives only as long as its creator's right to make it.** In the same transaction as the change, the server revokes (and burns) the live links a person created on the affected records once they no longer hold `edit` there:
- a direct share is removed, or downgraded to `view` or `use`;
- a team folder member is removed, leaves, or is downgraded to `view` or `use`.

A link stays live if the person still has `edit` some other way, for example a direct share plus a team folder membership. Disabling an account revokes every live link it created. Trashing a record, or deleting its folder, revokes every link on it, whoever made it. The record owner (or folder owner) sees all links on a record and can revoke any of them.

**Import and bulk migration.** `POST /records/batch` creates up to 25 records owned by the caller, all or nothing. Into no folder or the caller's own live private folders, each record is wrapped under the caller's user key. Into a live team folder where the caller is owner or editor, each record carries two wraps like `POST /records`: the folder-key wrap (`wrappedRecordKey`) and the caller's own (`ownerWrappedRecordKey`, required); view/use members get `403`, anyone else `404 folder_not_found`. The member import sheet still only offers private folders; the admin bulk migration from Keeper (`docs/migrate-from-keeper.md`) writes straight into the team folders it creates. People who aren't active yet are kept as *pending folder members* (`PendingFolderMember`: folder, email, permission; no keys) that only the folder owner can complete, by sealing the folder key to the person once they are active.

**Needs attention.** Weak, reused and old checks run in the browser over every record you can open, including records shared with you directly or through a team folder. So a password you reuse in a shared record counts. "Generate new password" is shown only to people who can edit the record (owner or `edit`).

## Trust limits (spec §5.6)

The server can't read any secret. But because public keys and sealed boxes are not authenticated, a malicious or compromised server **can**:

- **Swap public keys.** It can hand out its own public key in place of a colleague's, so a share or a member's folder key gets sealed to the server. Mitigations:
  - *Pinning (trust on first use).* Each browser remembers, per organisation, the key it last sealed to for each person (the membership key, or the account key while they have none). Sealing to a different key is refused: the person picker shows the old and new fingerprints and *Add*/*Share* stays disabled until the user clicks *I've checked it with them*. Adding a group skips members whose key changed; they wait in the approval queue, which shows the same warning. *Give access again* (after an account reset) and approving a group request seal to the new key after showing its fingerprint. A swap is still possible on the **first** share to someone from a browser, and pins are per browser (a new device, a cleared profile or private mode starts over).
  - *Fingerprints.* The share and member pickers, the People page and the folder people sheet show the fingerprint of the key sealing uses. Compare it out of band before the first share of anything sensitive. Shares that already exist are not affected.
- **Plant fake team folders and fake shared records.** Anyone can seal a key to your public key, so the server can add a team folder or a "shared with you" record whose contents it chose. Sealed boxes are not signed, so you can't prove who sealed them. Mitigation: the folder sheet shows the folder owner's name and key fingerprint. The client also refuses a sealed (`s1.`) key on a record that claims you as its owner, because your own records are always wrapped under your user key. Treat unexpected shared folders or records with suspicion: don't type secrets into a folder whose owner fingerprint you haven't checked.
- **Withhold or roll back data.** The server decides which rows to return, so it can hide records or serve an older revision.

## Follow-ups (not in phase 2)

- **Key rotation on removal.** (Access rows are removed at once; see Offboarding.) When someone is removed from a team folder or a direct share, their row is deleted right away and the server stops serving the ciphertext to them. The folder key and the record keys are **not** rotated, so anyone who kept a copy of a key from before can still decrypt ciphertext they already have. The fix is to rotate the folder key, re-wrap the record keys and re-encrypt the records. The UI currently suggests changing important passwords after a removal.
- Pending shares for invited people who haven't registered yet (spec §5.2). For now, shares can only target active users (ruling R1).

## Organisations (0.6.0)

Team folders, direct shares and one-time links on team records belong to the organisation they were made in and are
only visible while that organisation is active (the org switcher at the top of the sidebar). Records can be shared
only with members of the active organisation. Private records belong to you and show in every organisation; a direct
share of a private record lives in the organisation it was made in. Leaving or being removed from an organisation ends
your team-folder memberships, shares and links there (records you created in its team folders pass to the folder
owner). See `docs/design/2026-10-07-multi-org-design.md`.
