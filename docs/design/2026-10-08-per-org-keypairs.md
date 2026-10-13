# Per-organisation key pairs — design (workstream D)

Date: 2026-10-08 · Status: implemented (crypto, API, web, extension, migration `20261014000000_membership_keys`, e2e)
· Target: 1.2.0

**Decisions taken** (open questions of section 11):
1. One scoped mechanism for everyone. There is no "full account" option; the old whole-account escrows are deleted by
   the migration rather than kept for a transition.
2. `AccountKeyArchive` lives until the user deletes it.
3. The "restore later" banner is skipped when the reset lost nothing.
4. Folder-key rotation on member removal stays out of scope.
5. Members see which admins hold their escrow (Settings → Security).

**Differences from the plan below, as built:**
- Legacy escrows aren't kept for a transition: `AdminRecoveryEscrow` is dropped and open requests end in the migration
  (upgrade note in `docs/recovery.md`).
- Escrows go in `MembershipEscrow`. `RecoveryRequest.wrappedUserKey` became `wrappedMembershipKey` (+ `memberPublicKey`).
  Requests are per (user, org) through a partial unique index.
- The endpoints are org-scoped by `X-Org-Id`: `/membership-key`, `/membership-key/{rotate,pending,rows,escrows,owner-repair,repaired}`.
  The account-wide ones are `/me/key-archive{,/open,/:id/memberships,/:id/restored}`, `/me/owner-rows` and `/me/private-folders`.
- Sync carries the caller's membership key material (`membershipKeys`), so the offline copy and the browser extension
  open membership-sealed rows with no extra request. Clients bind them to the org they asked for, never the server's word.
- The client job runs for the active organisation only: other organisations migrate when the user switches to them.
  This avoids SSO or IP-policy prompts from organisations the user isn't looking at.
- Group access is never sealed automatically (an explicit approve/decline prompt with person, group, who added them,
  and key fingerprint), and `GroupAccessDecline` records declines.
- Clients pin (trust on first use, per device) the membership key they sealed to for each person, and show a warning
  in the approval prompt when it changed.
- Security review (2026-10-08): the key archive opens only with proof of the old password or kit (archived auth hashes,
  migration `20261015000000_key_archive_auth`); admin links never return the wrapped user key (restore mode fetches it
  after a password check); migration batches name the key they are sealed to (`to`) and are refused after a concurrent
  rotation; my own copy of a new folder key goes only to a membership key this device can open; pins cover account keys
  too (a dropped membership key warns); escrows of retiring keys aren't released.
- Records in an organisation's team folder can't be moved out to private (`409 org_record`), so they stay under the
  organisation's link policy and event log. Private folder renames are logged without an organisation.

Related: `docs/recovery.md`, `2026-10-04-clane-vault-design.md`, `2026-10-07-multi-org-design.md` (sections 6 and 10),
`2026-10-08-close-the-gap.md` (section D).

## 1. Problem

Admin recovery escrows the account's single `userKey`, sealed to each admin. That key opens everything the account can
open: private items, every organisation's team folders and shares. So since 0.6.0 admin recovery is allowed only for
accounts that are active in **exactly one** organisation. Joining a second organisation deletes the escrows. Admins of
org A must never be able to restore (or read) what the person holds in org B or in their private vault.

Goal: admin recovery for people in several organisations. An admin of org A can restore access only to what the
person holds **in org A**.

## 2. Decision summary

1. Every membership (user × organisation) gets its own X25519 **membership key pair**. The private key is wrapped
   under the account `userKey`. Everything org A gives the member is sealed to the membership public key: team
   folder keys (`FolderMember.wrappedFolderKey`) and direct shares made in A (`RecordAccess` user rows with `orgId = A`).
2. Admin recovery escrows only the **membership private key**. It is sealed to each other admin's **membership**
   public key in the same org. The existing rules stay as they are: the two-person rule, the approver's minimum admin
   age, the 24 h delay after a 2FA reset, single-use 24 h links, five strikes and emails.
3. Admin recovery becomes a **scoped reset**. The member gets a new master password **and new account keys** (new
   `userKey` and account key pair). Org A's membership key is restored under the new `userKey`. Nothing else is: no
   private items and no other organisation. The old account material is **archived**, and the old recovery kit or
   the old master password can still restore everything later (section 6.4).
4. **Decision on the single-org semantics.** Today a single-org member's admin recovery also restores private items,
   by design: the policy warning says admins "can access their private records". We **retire that** and use scoped
   recovery for everyone. Reasons:
   - It is strictly safer. An opened escrow no longer gives an admin the member's private vault, and a membership key
     can be rotated after use (section 6.3). The account `userKey` can never be rotated.
   - One mechanism is simpler than two that depend on how many orgs someone is in. Joining a second org would also
     silently change what an admin can do.
   - The recovery kit remains the way to restore private items. It is always available and needs no admin.

   The legacy whole-account escrows keep working for single-org members **only until** that member's membership
   escrows are complete. After that, the legacy escrows are deleted (section 7). A release after 1.2 drops them
   entirely. This is open question Q1 if product wants a "full account" option kept.
5. Migration is **client-driven on unlock**. It is online, idempotent and resumable: each row moves on its own, and
   the server records which key each row is sealed to (`sealedTo`).

### Alternatives considered

| Option | Why not |
|---|---|
| Keep the single-org rule (status quo) | Doesn't meet the goal. |
| Escrow each team folder key and share key directly to admins | O(folders × admins) escrows to keep in sync. Every new folder or share needs uploads. Admins would hold keys to folders independently of any request. Hard to reason about. |
| One shared org key pair (all members hold the org private key) | Any member could open every escrow or folder key in the org. Removing a member would need a full re-key. |
| Shamir / threshold split of the `userKey` among admins | Still the whole account, so the scope problem stays. Also much more machinery. |
| Per-membership symmetric key + key pair derived from a seed | Workable, but nothing in the org needs a symmetric membership key: owner rows stay under the `userKey` and are repaired after a reset. A plain key pair mirrors the account structure. |
| **Per-membership key pair (chosen)** | One small key per membership, scoped escrow, rotatable, reuses the existing seal and recovery flows. |

## 3. Threat model (deltas from `docs/recovery.md`)

| Who | Today (single-org only) | With membership keys |
|---|---|---|
| Rogue admin of org A, policy on | Opens the member's whole account: private items, and every org if the account were multi-org (hence the single-org rule). | Opens the member's **A membership key**. That gives every A team folder the member is in and every A share to them. No private items, nothing from other orgs. The member rotates the key after a recovery, so future A shares aren't readable with the old key. Folder keys the admin saw stay known (folder keys aren't rotated; same as any ex-member). |
| Admin of org A against a member of A and B | Not possible (no escrow). | Same scope as above. Org B's escrows are sealed to B admins' B membership keys, which A admins don't have. |
| Admin of A completing a reset | Can't without the member's 2FA. A 2FA reset needs a second, long-standing admin plus a 24 h delay. | Unchanged. A scoped reset changes the account password, so the 2FA-reset rule (needs an instance admin, or an admin of **every** org the person is in) stays. |
| Server operator (active) | Could list its own key as an "admin" (no worse than malicious JS). | Same. It could also claim that a member re-keyed so that folder holders re-seal to an attacker key. That is why **re-granting access after a key change needs an explicit click** by a folder manager (section 8), never auto-sealing. |
| Database writer (no code change) | Could replace a user's `publicKey`: future shares are sealed to the attacker. | Same for membership public keys. Clients check `assertKeyPair` for every membership key they unwrap, and refuse rows whose `sealedTo` is a key of another org. |
| Database thief | Nothing usable. | Same. Membership private keys are wrapped under `userKey`; escrows are sealed boxes. |
| Org B learning about the reset | — | Org B admins see that the person's B access needs to be restored (they must re-grant), so they learn that a reset happened. Accepted. |

Out of scope, unchanged: malicious JavaScript, a compromised member device, folder key rotation on member removal.

## 4. Key hierarchy

```
master password ──Argon2id+HKDF──► wrapKey
                                     │ AES-GCM, AAD "user-key"
                                     ▼
                                  userKey (32 B, per account; replaced by a scoped reset)
             ┌───────────────────────┼─────────────────────────────────────────┐
             │ AAD private-key:<pub> │ AAD membership-private-key:<org>:<user>:<mpub>
             ▼                       ▼                                         ▼ AAD record-key:<rid> / folder-name:<fid>
   account key pair (X25519)   membership key pair, one per active org     owner rows of my records,
   - legacy rows (sealedTo null)  │                                        private folder names
   - one-time links, nothing new   │ sealed (s1.) to mpub_A:
                                   │  org-folder-key:<orgA>:<folderId>  ──► team folder key ──► record-key:<rid> (folder rows)
                                   │  org-record-share:<orgA>:<rid>     ──► record key (direct share in org A)
                                   ▼
             escrow: mpriv_A sealed to admin's mpub_A
               AAD escrow-membership-key:<orgA>:<userId>:<adminId>:<mpub_A>
             recovery link: mpriv_A under HKDF(R, "clane-vault/admin-recovery-membership")
               AAD admin-recovery-membership:<requestId>:<orgA>:<userId>:<mpub_A>
               proof HKDF(R, "clane-vault/admin-recovery-proof")   (same as account links)

recovery kit: recoveryKey ──HKDF "clane-vault/recovery"──► wraps userKey (AAD recovery-user-key:<userId>)   (unchanged)
```

### Exactly which key seals what

| Item | Sealed / wrapped under | Envelope | AAD | Function |
|---|---|---|---|---|
| Membership private key (PKCS#8) | `userKey` | `v1.` | `membership-private-key:<orgId>:<userId>:<mpubB64>` | `createMembershipKeys`, `wrapMembershipKeys`, `unlockMembershipKeys` (checks the pair) |
| Team folder key, member copy (new) | recipient's membership public key | `s1.` | `org-folder-key:<orgId>:<folderId>` | `sealOrgFolderKey`, `openOrgFolderKey` |
| Team folder key, member copy (legacy) | recipient's account public key | `s1.` | `folder-key:<folderId>` | `sealFolderKeyFor` (only until the recipient has membership keys) |
| Direct share in an org (new) | recipient's membership public key | `s1.` | `org-record-share:<orgId>:<recordId>` | `sealOrgRecordShare`, `openOrgRecordShare` |
| Direct share (legacy) | recipient's account public key | `s1.` | `record-share:<recordId>` | `shareRecordKey` |
| Owner row of my record (private or in a team folder) | my `userKey` | `v1.` | `record-key:<recordId>` | unchanged |
| Folder row of a record in a team folder | folder key | `v1.` | `record-key:<recordId>` | unchanged |
| Private folder name | my `userKey` | `v1.` | `folder-name:<folderId>` | unchanged |
| Membership escrow | each other admin's **membership** public key in the same org | `s1.` | `escrow-membership-key:<orgId>:<userId>:<adminId>:<memberPubB64>` | `sealMembershipEscrow`, `openMembershipEscrow` (checks the pair) |
| Membership recovery link | `HKDF(R, "clane-vault/admin-recovery-membership")` | `v1.` | `admin-recovery-membership:<requestId>:<orgId>:<userId>:<memberPubB64>` | `createMembershipRecoveryGrant`, `openMembershipRecoveryGrant` |
| Legacy escrow (retired) | admin's account public key | `s1.` | `escrow-user-key:<userId>:<adminId>` | `sealEscrow` (no new uploads once a member has membership keys) |

The rules behind this table:

- Every new label binds the **organisation id**. A client also refuses a membership key whose `orgId` differs from
  the row's org (`bad_key`) before it decrypts anything. A box from org A can't be presented in org B's context.
- Escrow and link labels also bind the **member's public key**. After opening, the client checks that the private key
  matches the public key the server lists (`assertKeyPair`, X25519 with the base point). A server can't swap in a key
  pair of its own.
- Owner rows stay under `userKey` on purpose. Ownership is an account concept, and the membership key must never
  open private items. After a scoped reset, owner rows of team-folder records are rebuilt from the folder row
  (`ownerRecordKeyFromFolder`).
- One-time links keep their own keys (unchanged).

## 5. Data model changes (not applied yet; schema is busy with workstream C)

```prisma
/// A membership key pair (docs/design/2026-10-08-per-org-keypairs.md). Several rows per membership only
/// during a rotation, or when keys from before a scoped reset are archived.
model MembershipKey {
  id                String   @id @default(uuid()) @db.Uuid
  orgId             String   @db.Uuid
  userId            String   @db.Uuid
  publicKey         String   @unique
  /// v1. under the account user key of generation `userKeyGen` (AAD membership-private-key:<org>:<user>:<pub>).
  wrappedPrivateKey String
  userKeyGen        Int
  /// current: the one to seal to; retiring: still referenced by rows during a rotation; archived: wrapped under an
  /// old user key after a scoped reset (restorable with the old password / kit, or an admin link of that org).
  state             MembershipKeyState @default(current)
  createdAt         DateTime @default(now())
  retiredAt         DateTime?
  @@index([orgId, userId])
  // partial unique (raw SQL in the migration): one `current` row per (orgId, userId)
}
enum MembershipKeyState { current retiring archived }

model MembershipEscrow {          // replaces AdminRecoveryEscrow once legacy escrows are gone
  id              String @id @default(uuid()) @db.Uuid
  orgId           String @db.Uuid
  userId          String @db.Uuid
  adminId         String @db.Uuid
  memberPublicKey String          // the MembershipKey sealed (must be the member's current key)
  adminPublicKey  String          // the admin's membership key it is sealed to
  sealedKey       String          // s1. (AAD escrow-membership-key:...)
  createdAt       DateTime @default(now())
  @@unique([orgId, userId, adminId])
  @@index([adminId]) @@index([userId])
}

/// Account material replaced by a scoped reset; lets the old password or old kit restore everything later.
model AccountKeyArchive {
  id                String   @id @default(uuid()) @db.Uuid
  userId            String   @db.Uuid
  userKeyGen        Int
  kdfSalt           String
  kdfParams         Json
  wrappedUserKey    String
  publicKey         String
  wrappedPrivateKey String
  recoveryWrap      String?   // the kit as it was (still opens this generation's userKey)
  recoveryAuthHash  String?
  archivedAt        DateTime @default(now())
  restoredAt        DateTime?
  @@index([userId])
}
```

Column changes:

| Table | Change |
|---|---|
| `User` | `userKeyGen Int @default(1)` (bumped by a scoped reset). |
| `FolderMember` | `sealedTo String?`: the membership public key `wrappedFolderKey` is sealed to (null = account key, legacy). |
| `RecordAccess` | `sealedTo String?` (user share rows only). |
| `RecoveryRequest` | `scope` (`account` \| `membership`, default `account` for old rows), `memberPublicKey String?`, `wrappedMembershipKey String?` (burned like `wrappedUserKey`). Drop the "one open request per person" rule in favour of one open request per (person, org). |
| `Membership` | none (keys live in `MembershipKey`). The `adminRecoveryAckAt` semantics stay per org. |

Server-side invariants:

- **Sealing to the right key.** A write that seals to a member (add folder member, group sync, pending-member
  completion, direct share) names `sealedTo`. The server accepts it only if `sealedTo` is that member's `current`
  membership key in the folder's or share's org, or `null` while the member has no membership key yet. Otherwise it
  answers `409 stale_recipient_key`, and the client refetches the key and seals again.
- **A membership is recoverable** when every one of its live rows (`FolderMember` in the org's team folders,
  `RecordAccess` user rows with that `orgId`) has `sealedTo` = the current key, and a `MembershipEscrow` exists for
  that key. Only recoverable memberships get recovery requests.

## 6. Flows

### 6.1 Membership keys and migration (every unlock, background, idempotent)

Runs per active membership, after unlock. The session's org confinement applies (section 9), so a confined session
does only that org.

1. **Ensure a key.** `GET /me/membership-keys` returns my rows: current, retiring, and archived with gen. If the org
   has no `current` key, call `createMembershipKeys(userKey, {orgId, userId})` and then
   `POST /me/membership-keys {orgId, publicKey, wrappedPrivateKey}`. The server inserts only if no current key exists
   (`ON CONFLICT DO NOTHING`) and returns the winner. A second device that loses the race discards its key and uses
   the winner's.
2. **Unlock keys.** `unlockMembershipKeys` runs for every current and retiring row of my generation. A row that fails
   (`bad_key` / `decrypt_failed`) is reported once (`membership.key_invalid` event) and skipped. It is never trusted.
3. **Move legacy rows.** `GET /me/membership-keys/:orgId/pending` returns pages of my rows in that org whose
   `sealedTo` is not the current key: folder copies and shares. For each row:
   - if `sealedTo` is null, call `resealFolderKeyToMembership` / `resealRecordShareToMembership` with my account keys;
   - if it is a retiring key, call `rotateFolderKeySeal` / `rotateRecordShareSeal`.

   Batches go up with `PUT /me/membership-keys/:orgId/rows`
   `{folders:[{folderId, from, wrappedFolderKey}], shares:[{recordId, from, wrappedRecordKey}]}` (max 200). The
   server updates each row with compare-and-set on `(sealedTo = from, wrapped = the value it served)`. A row changed
   in between is skipped and comes back in the next page. A row that fails to open on the client is left alone and
   reported as unreadable. The job resumes from wherever it stopped.
4. **Retire.** When no row references a retiring key, the server deletes that `MembershipKey` row (on the batch that
   empties it).
5. **Escrow.** When the org's policy is on, the member has acknowledged, and the membership is recoverable, the
   client seals the current membership private key to each other active admin's current membership key
   (`sealMembershipEscrow`) and calls `PUT /me/membership-escrows`. `GET /me/security` lists `escrowNeeded`: admins
   with no escrow, or one whose `memberPublicKey` / `adminPublicKey` is no longer current. Admins without a
   membership key yet are skipped until they unlock.
6. **Retire legacy escrows.** Once membership escrows exist for every admin that has a legacy escrow for me in that
   org, the server deletes my `AdminRecoveryEscrow` rows there (in the same transaction as the escrow upload).

New sealing by others: clients use the recipient's current membership key from the API (`members[].membershipKey`
or the share-recipient lookup) when there is one, otherwise the account key with `sealedTo: null`. Either way the
recipient's own migration later converges the row.

### 6.2 Admin recovery (scoped reset)

1. **Request.** Sign in → Need help? → *Ask an admin to reset my password* → email. The answer is always the same.
   The server creates one pending request (`scope: membership`) **per org** where the account is active, the policy
   is on and the membership is recoverable. During the transition there is also the legacy case: a single-org account
   with only a legacy escrow gets a `scope: account` request exactly as today. Each org's admins and the member are
   emailed with the org's name.
2. **Escrow release.** `POST /admin/recovery-requests/:id/escrow` is unchanged: fresh admin TOTP; not self; not the
   admin who reset the member's 2FA; approver old enough when 2FA was reset. It returns this admin's
   `MembershipEscrow` plus `{memberPublicKey, orgId}` and the 5-minute approval token. The `multi_org` check is
   removed for `scope: membership`.
3. **Approve.** The admin's client unlocks its own membership key for the org and runs `openMembershipEscrow`
   (which checks the pair against `memberPublicKey`), then `createMembershipRecoveryGrant(requestId, {orgId, userId},
   key)`. It uploads `{approvalToken, wrappedMembershipKey, proof}` and gets the link `PUBLIC_URL/recover/<id>#<R>`.
   TTL, emails and events are as today.
4. **Link.** `POST /auth/recovery/admin/:id` with proof and TOTP. The two-person rule, approver age and reset delay
   apply exactly as today. It returns
   `{scope: "membership", orgId, orgName, memberPublicKey, wrappedMembershipKey, material, recoveryToken}`.
5. **Choose new password.** The client runs `openMembershipRecoveryGrant(...)` (pair check) and tells the user
   plainly: *"This restores what you have in {org}. Your private items and other organisations need your recovery kit
   or your old master password; you can restore them later."* It then runs `createAccount(newPassword)`, which makes
   a new `userKey` and a new account key pair, and `wrapMembershipKeys(newUserKey, {orgId, userId}, key)`.
6. **Finish.** `POST /auth/recovery/finish` with
   `{authKey, material (new keys), scope: "membership", membership: {orgId, publicKey, wrappedPrivateKey}}`.
   `membership.publicKey` must equal the request's `memberPublicKey`. In one transaction, under the user row lock:
   - Archive the old account material and kit into `AccountKeyArchive`, then set the new material and bump
     `userKeyGen`.
   - Re-wrap membership A under the new generation.
   - Mark every other `MembershipKey` of the user `archived`.
   - Delete legacy `AdminRecoveryEscrow` rows (they hold the old `userKey`).
   - Keep `MembershipEscrow` rows: those keys are unchanged, so other orgs can still restore them.
   - Mark the request used and burn the link material.
   - Revoke all sessions and start a new one, then send the email and events (`auth.admin_recovery_used` with
     `scope`, `orgId`). Other open requests stay open, because another org may still restore its membership
     (section 6.4).
7. **First unlock afterwards.** The client:
   - **rotates** membership A, because an admin has seen that key. It creates a new current key, marks the old one
     retiring and runs steps 3 to 5 of 6.1, which re-seal every A folder copy and share to the new key and re-escrow.
     The old key is deleted when it is no longer referenced.
   - **rebuilds owner rows** of its own records in A team folders from the folder rows (`ownerRecordKeyFromFolder`,
     `PUT /me/owner-rows`).
   - shows a banner: *"N private items and your access in {other orgs} are locked from before your reset. Restore
     with your recovery kit or old master password."*
   - prompts for a new recovery kit, as today.

### 6.3 Rotation (also usable without recovery)

Rotation re-uses the migration. The client creates a new `current` key and the previous one becomes `retiring`. Its
own rows are re-sealed from the retiring key to the new one, the escrows are redone, and the retiring key is deleted
when it is no longer referenced. Triggers:
- automatic after a scoped recovery of that org (6.2 step 7);
- automatic when the server reports `escrowOpenedAt` newer than the current key (an admin opened an escrow, even
  if the request was then denied);
- manual "Rotate my organisation key" in Settings → Security (later).

### 6.4 Restoring the rest after a scoped reset

- **Old recovery kit or old master password** (`Settings → Security → Restore items from before your reset`;
  needs an unconfined session and fresh TOTP). The client:
  1. Fetches the archive.
  2. Unwraps the old `userKey` with `openRecoveryWrap` (kit) or `unlockAccount` (old password).
  3. Re-wraps the owner rows and private folder names under the new `userKey` with `rewrapOwnerRecordKey` and
     `reencryptPrivateFolderName` (`PUT /me/owner-rows`, `PUT /me/private-folders`, batched with compare-and-set).
  4. Re-wraps every archived membership key under the new `userKey` with `unlockMembershipKeys` (old) and then
     `wrapMembershipKeys` (new) (`PUT /me/membership-keys/restore`), and legacy rows sealed to the old account key
     to the new membership keys (open with old account keys, seal to the membership).

  The archive is marked `restoredAt`. The old kit stays a valid way to read the archive until the user deletes the
  archive. We recommend deleting it once restored, and the UI offers that.
- **Another org's admin link** (org B approves an open request after the reset). The link page does proof + TOTP as
  usual. The server sees that B's key is `archived`, so it answers `scope: membership, mode: "restore"`. The page
  asks for the **current** master password (auth key checked server-side like a login and counted toward the
  lockout), opens the grant, and wraps B's key under the current `userKey`. It sends
  `POST /auth/recovery/restore-membership {recoveryToken, authKey, publicKey, wrappedPrivateKey}`. The server
  checks that the public key equals the archived one and makes it `current` again. The request becomes used. No
  password change, no session revocation (event `recovery.membership_restored`). Then B rotates as in 6.2 step 7.
- **Nobody can restore B.** B's folder managers see "Ana needs access again (reset on <date>)" and click *Restore
  access*, which re-seals each folder key to Ana's new B key (section 8). Shares made to Ana in B: the record's
  owner sees "Re-share". The owner's own items in B team folders are back as soon as any folder key is.

### 6.5 Recovery kit (unchanged)

The kit restores the account `userKey`, and with it everything: membership keys and private items. Kit use keeps the
account keys, so nothing is archived and no rotation is needed. The kit is still the way to recover everything.

## 7. Interaction with the existing rules

- **Two-person rule, approver age, 24 h delay, link TTL, five strikes, emails, events.** Unchanged and evaluated per
  request org, exactly as now. `linkIsOnlyFactor`, `twoPersonOk` and `approverOldEnough` apply to both scopes.
- **2FA reset.** It is still account-wide: an instance admin or an admin of every org, and never an org owner. A
  scoped reset doesn't change who may reset 2FA.
- **Joining a second org.** It no longer suspends admin recovery. Legacy (account) escrows are still deleted at that
  moment, as today, because they hold the whole account. Membership escrows of the first org stay. The new org's
  membership key is created on next unlock.
- **Leaving or removal from an org.** Delete that membership's keys and escrows (cascade by `(orgId, userId)`, done in
  the leave/remove transaction), and expire open requests for that org.
- **Admin disabled or demoted.** Delete `MembershipEscrow` rows held by that admin in that org (as now for legacy).
  Approved links by them are burned (as now).
- **Admin's own key rotates.** Escrows sealed to their old `adminPublicKey` show up in `escrowNeeded` for each member
  and are redone on the members' next unlock. The admin keeps the retiring key until the server reports no escrow
  or row references it.
- **Policy off.** Deletes the org's `MembershipEscrow` and `AdminRecoveryEscrow` rows and ends requests (as now).
- **Acknowledgement.** Per org, as now. The warning text changes to: *"{Org}'s admins will be able to restore your
  access to {Org}'s shared folders and items if you forget your master password. They can't open your private items
  or other organisations' items."*

## 8. Groups, pending members, re-granting access

- **Groups (workstream C).** When a client syncs group members into a folder, it seals to each member's current
  membership key (`sealedTo`) or, if there is none, to the account key. Removing a user from a group removes the
  `FolderMember` row as now.
- **Pending folder members.** Completion is unchanged except that it seals to the recipient's membership key when the
  recipient has one.
- **Re-grant after a key change.** A `FolderMember` row whose `sealedTo` is neither the member's current/retiring key
  nor (for null) a still-valid account key appears to the folder's owners and managers as "needs access again". The
  server computes this from `MembershipKey.state = archived` or the account generation. *Restore access* is an
  **explicit** action. The client fetches the member's current key, shows its fingerprint (`keyFingerprint`) next to
  the member's name, and seals. It is never automatic (see the threat model). Event: `folder.access_regranted`.

## 9. SSO users and the private-items lock

- SSO accounts still have a master password and a `userKey`. Everything above applies, including JIT-provisioned
  members (membership key on first unlock).
- A **confined session** (trusted IdP MFA, no TOTP yet; `totpSkippedForOrg`) may create, migrate, rotate and escrow
  the keys of **that org only**. The endpoints are org-scoped and go through the existing org check. Restoring
  private items from the archive needs an unconfined session (TOTP step-up). A recovery link for another org needs
  the link's own TOTP check anyway.
- A scoped reset changes the master password. SSO sign-ins then use the new password as usual.

## 10. Endpoints (to add or change)

| Method + path | Purpose |
|---|---|
| `GET /me/membership-keys` | My membership keys (all orgs I'm active in plus archived), with `userKeyGen`. |
| `POST /me/membership-keys` | Create the current key for an org if there is none (idempotent, returns the winner). Org-scoped. |
| `POST /me/membership-keys/:orgId/rotate` | Add a new current key; the old one becomes retiring. |
| `GET /me/membership-keys/:orgId/pending?cursor=` | My rows in that org not sealed to the current key (paged). |
| `PUT /me/membership-keys/:orgId/rows` | Batch compare-and-set re-seal of folder copies and shares. |
| `PUT /me/membership-keys/restore` | Re-wrap archived keys under the current `userKey` (after a kit/old-password restore). |
| `PUT /me/owner-rows`, `PUT /me/private-folders` | Batch compare-and-set re-wrap of owner rows and private folder names (restore / repair). |
| `GET /me/key-archive` | Archived account material (ciphertext only) and the kit wrap, for restore. Unconfined session + fresh TOTP. |
| `DELETE /me/key-archive/:id` | Forget an archive. |
| `GET /me/security` | Adds per-org `membershipKey`, `recoverable`, `escrowNeeded` (membership escrows, admin membership keys), `rotateNeeded`, `archive`; drops `adminRecoverySuspended`. |
| `PUT /me/membership-escrows` | Upload membership escrows. Same checks as `/me/escrows`, minus `multi_org`, plus "member key is current" and "admin key is the admin's current key in that org". |
| `POST /auth/recovery/admin/request` | One request per eligible org (scope membership), or legacy (single-org, legacy escrow only). |
| `POST /admin/recovery-requests/:id/escrow`, `/approve` | Scope-aware: membership escrow and `wrappedMembershipKey`. |
| `POST /auth/recovery/admin/:id` | Returns scope, `mode: reset \| restore` and membership fields. |
| `POST /auth/recovery/finish` | `scope: membership`: new account keys allowed, archive, re-wrap the restored membership. |
| `POST /auth/recovery/restore-membership` | Restore an archived membership with an admin link plus the current master password. |
| Folder/share/group/pending writes | Accept `sealedTo`; refuse a stale recipient key (`409 stale_recipient_key`). Sync and member lists return `membershipKey` per member and `sealedTo` per row. |
| `GET /folders/:id/regrant` (or in sync) | Members needing access again, with their current key. |

## 11. Open questions

- **Q1.** Should orgs keep a "full account" option (legacy escrow of `userKey`, private items included) for
  single-org members? Recommendation: no. The kit covers it, and it reintroduces the multi-org cliff.
- **Q2.** Archive lifetime: keep `AccountKeyArchive` until the user deletes it (recommended), or expire it after N
  days? It holds only ciphertext, but it keeps the old kit meaningful.
- **Q3.** A scoped reset for someone in a single org who has **no** private items and no other orgs loses nothing.
  Should the UI skip the "restore later" banner in that case? (Cosmetic.)
- **Q4.** Folder key rotation on member removal is still out of scope. An admin who opened an escrow keeps knowing the
  folder keys of that moment, as any ex-member does.
- **Q5.** Should a member be able to see (and approve) which admins hold an escrow of their membership key?
  Today it's only a count.

## 12. Implementation plan (API + web + migration): done, see "Differences from the plan" at the top

Phase 0 is done: crypto in `packages/crypto/src/orgKeys.ts` and `rekey.ts`, with tests in `test/orgKeys.test.ts` and
`test/rekey.test.ts`.

**Phase 1: schema (after workstream C releases `schema.prisma`)**
- [x] Migration `2026xxxx_membership_keys`: `MembershipKey` (+ state enum, partial unique index on current),
      `MembershipEscrow`, `AccountKeyArchive`, `User.userKeyGen`, `FolderMember.sealedTo`, `RecordAccess.sealedTo`,
      `RecoveryRequest.scope/memberPublicKey/wrappedMembershipKey`; replace the one-open-request index with per (user, org).
- [x] Cascades: leaving or removal from an org deletes `MembershipKey` + `MembershipEscrow` for `(orgId, userId)`.

**Phase 2: API**
- [x] `lib/membershipKeys.ts`: current key lookup, `recoverable(orgId, userId)`, `sealedTo` validation helper.
- [x] `routes/membershipKeys.ts`: the `/me/membership-keys*`, `/me/owner-rows`, `/me/private-folders` and
      `/me/key-archive` endpoints. Compare-and-set batches, max 200 rows. Org check and private-lock rules as in section 9.
- [x] Folder member add, group sync, pending completion and share create accept `sealedTo` and refuse stale keys
      (`routes/folders.ts`, `routes/groups.ts`, `routes/pendingMembers.ts`, `routes/records.ts`). Coordinate with C.
- [x] Sync and member lists: `sealedTo` per row, `membershipKey` per member, a needs-regrant flag.
- [x] `routes/recovery.ts`: per-org requests; scope-aware link; `/finish` scope membership (archive + generation bump +
      legacy-escrow delete, all under the user lock); `/restore-membership`; `/me/security` and `/me/membership-escrows`.
- [x] `routes/adminRecovery.ts`: scope-aware escrow release and approve; `multi_org` only for the legacy scope;
      escrow counts from both tables during the transition.
- [x] `lib/orgs.ts` join path: delete only legacy escrows. Leave/remove/disable/demote: membership escrows.
- [x] Events: `membership.key_created`, `membership.key_rotated`, `membership.rows_migrated` (counts),
      `membership.key_invalid`, `recovery.membership_restored`, `folder.access_regranted`, `auth.key_archive_restored`.
- [x] Tests (`apps/api/test/membership-keys.test.ts`, `recovery-scoped.test.ts`):
  - idempotent create race;
  - compare-and-set skip;
  - cross-org row refusal;
  - confined session limits;
  - per-org request;
  - two-person and delay rules under scope membership;
  - finish archives and keeps other orgs' escrows;
  - restore-membership needs the current auth key and a matching public key;
  - stale recipient key refusal.

**Phase 3: web**
- [x] `lib/session.tsx`: keep a membership keyring (by public key) next to `keys`; zero it on lock.
- [x] `features/vault/decrypt.ts`: `openTeamFolderKey` / `openSharedRecordKeyInOrg` with `sealedTo`; never trust a
      membership key whose org doesn't match.
- [x] `features/orgKeys/useMembershipSync.ts`: on unlock, ensure key → migrate pages → rotate if needed → escrow
      (replaces `useEscrowSync`). Backoff on failure; progress is invisible unless something is unreadable.
- [x] Sealing call sites (`FolderPeopleSheet`, groups, pending members, share dialog, `RecordEditor`) seal to the
      membership key when present and send `sealedTo`.
- [x] Recovery pages: scoped reset copy, `mode: restore` path (current password), post-reset banner, and "Restore
      items from before your reset" (kit or old password) in Settings → Security.
- [x] Folder people sheet: "needs access again" with fingerprint and *Restore access*.
- [x] Admin approve flow: unlock own membership key, `openMembershipEscrow`, `createMembershipRecoveryGrant`.
- [x] Policy warning, acknowledgement and `docs/recovery.md` texts per section 7.
- [x] Offline copy (workstream B): store wrapped membership keys with the wrapped account keys (ciphertext only).
- [x] Browser extension: load the membership keyring at unlock (read-only use).

**Phase 4: e2e and docs**
- [x] e2e: a two-org user. A-admin recovery restores A only, B shows locked, the kit restores the rest, and a B link
      restores B without a password change.
- [x] Update `docs/recovery.md` (organisations section, threat model) and the multi-org design section 6.
- [x] Release 1.2.0. In the release after that, drop `AdminRecoveryEscrow` and `scope: account`.
