# Master-password recovery

Clane Vault is zero-knowledge: the server never sees a master password or a key that can decrypt a vault. A
forgotten master password used to mean a lost vault. Two opt-in mechanisms change that without giving the server
the keys:

1. **Recovery kit** (every user, always available). A random code the user saves offline.
2. **Admin account recovery** (organisation policy, **off by default**). An organisation's admins can approve a reset
   that restores what the member holds **in that organisation** only.

With the kit the user keeps their whole vault: the user key (which wraps their private key, records and membership
keys) is recovered on the user's device and re-wrapped under a new master password. Nothing is re-encrypted.

An admin recovery is a **scoped reset**: new account keys, and only that organisation's membership key comes back.
The rest (private items, other organisations) stays locked until the old kit or old master password restores it.

**The kit never rotates the user key.** Whoever has held it (a kit holder) can still decrypt that user's vault
afterwards, also after a password change. An admin who opened an escrow saw a **membership key** of one organisation.
The member's client replaces that key on its next unlock, so it doesn't open anything shared later. Folder keys the
admin could reach at that moment stay known to them, as with any former member.

## Keys involved (recap)

- `userKey` (32 bytes) is wrapped under `wrapKey = HKDF(Argon2id(password))` as `wrappedUserKey` (AAD `user-key`).
- The X25519 private key is wrapped under `userKey` (AAD `private-key:<publicKey>`).
- One membership key pair per organisation, its private key wrapped under `userKey`
  (AAD `membership-private-key:<orgId>:<userId>:<publicKey>`); team folder keys and direct shares of that
  organisation are sealed to it.
- Kit recovery replaces only the password-derived parts: `kdfSalt`, `kdfParams`, `authHash`, `wrappedUserKey`.
  The server refuses a kit finish that changes `publicKey` or `wrappedPrivateKey`. An admin (scoped) reset must
  change them, and must restore exactly the membership key the admin's escrow held.

## Recovery kit

**Creation.** The client generates `recoveryKey` = 32 random bytes and shows it once as a Crockford base32 code:
14 groups of 4 (`XXXX-…-XXXX`), the last group a 20-bit checksum (SHA-256 of a label and the key), so a typo is
caught on the device before anything is sent. It stores on the server:

- `recoveryWrap = AES-GCM(HKDF(recoveryKey, "clane-vault/recovery"), userKey, AAD "recovery-user-key:<userId>")`
- `recoveryAuthHash = SHA-256(HKDF(recoveryKey, "clane-vault/recovery-auth"))`

The auth value lets the server check possession of the kit; it is a different HKDF output from the wrap key, so
the server (or a database thief) can't unwrap anything with it, and the code itself is never sent. Creating or
replacing a kit needs the master password's auth key (checked like a login and counted toward the lockout), so a
stolen access token can't swap the kit for one the attacker knows.

The kit is created right after sign-up (after 2FA), with a "type the last group" or "I saved it" confirmation and a
**Download recovery kit** text file (Blob download; nothing leaves the browser). Existing users see a persistent
"Create your recovery kit" prompt (dismissable until the next unlock) and can **Regenerate** it in
Settings → Security (master password required; the old kit stops working immediately).

**Use.** Sign in → Need help? → *Forgot master password? Use your recovery kit*:

1. Email + recovery code. The client parses the code (checksum) and sends only the auth value.
2. The server answers `invalid_recovery` for an unknown email, an account without a kit and a wrong code alike.
   Wrong codes count toward the account's sign-in lockout (10 failures → 15 minutes, shared with passwords and 2FA),
   and the endpoint is rate limited per client.
3. A fresh TOTP code is required (`totp_required` / `totp_invalid`, also counted).
4. The server returns the `recoveryWrap`, the account material and a 10-minute recovery token pinned to the kit.
5. The client unwraps `userKey`, proves it by opening the private key, and the user picks a new master password.
   `changeMasterPassword` produces new material; `POST /auth/recovery/finish` stores it.
6. Finish is atomic: credentials replaced, **the kit is consumed** (deleted), every session revoked, failed-login
   counter reset, open admin-recovery requests ended, event `auth.recovery_kit_used`, email to the user if Resend is
   configured. The user is signed in on this device and must save a **new kit** before the vault opens.

## Admin account recovery (policy)

Off by default, and a setting of each organisation. Since 1.2 it is **scoped to one organisation** (per-org key pairs,
`docs/design/2026-10-08-per-org-keypairs.md`). An admin of an organisation can help a member set a new
master password and restore what the member holds **in that organisation**: its team folders and the records shared
with them there. Admins can never restore or open the member's private items or anything in another organisation.
The recovery kit is the way to bring those back.

An admin turns the policy on in Organisation settings, after a warning: *"Admins will be able to help any member
reset their master password and restore what they hold in this organisation. Never their private items or other
organisations' items."* Turning it **on** needs the admin's master password (auth key, checked like a login) **and**
a fresh 2FA code, so a stolen access token can't switch it on; both count toward the lockout. Turning it off needs
only the admin session. The change (and who made it, when) is logged (`admin.recovery_policy_enabled` /
`admin.recovery_policy_disabled`), and every member is emailed when it turns on (if Resend is configured).

**Disclosure.** While it is on, members see "Your organisation's admins can restore your access to it" on the
sign-up screen. Settings → Security shows, per organisation, which admins hold an escrow of their key there.

**Acknowledgement.** Before a member's client escrows anything for an organisation, the app shows a one-time blocking
notice: *"{Org} turned on admin recovery … its admins can help you reset your master password and restore your access
to {Org}'s shared folders and items. They can't open your private items or other organisations' items"*, with
Continue (or Sign out). The acknowledgement is recorded per organisation (`recovery.policy_acknowledged`). The server
refuses escrows without one newer than the latest switch-on. The admin who switches it on acknowledges by doing so.

**Membership keys.** Each member has one X25519 key pair per organisation. Its private key is wrapped under the user
key. Team folder keys and direct shares made in that organisation are sealed to it. The client creates the key on
the first unlock in that organisation and moves older copies (sealed to the account key) to it, one row at a time;
interrupted moves resume.

**Escrow.** While the policy is on, each client, when it unlocks in that organisation (after the acknowledgement and
once every row there is on the membership key), seals its **membership private key** to every other admin's
membership public key in the same organisation. The seal uses `sealTo` with AAD
`escrow-membership-key:<orgId>:<userId>:<adminId>:<memberPublicKey>`. The client uploads the escrows
(`PUT /membership-key/escrows`, `recovery.escrow_created`, with a count); an upload replaces an existing escrow for
the same admin. Admins don't escrow to themselves.

- A new admin receives escrows as each member next unlocks there, once the new admin has unlocked once (they need a
  membership key). Until then, the new admin can't approve that member's request; another admin can.
- Disabling or demoting an admin deletes the escrows they hold.
- **Turning the policy off deletes every escrow of that organisation and ends every open request** (wrapped keys
  burned).

**Flow.**

1. Member: Sign in → Need help? → *Ask an admin to reset my password* → email. The answer is the same whether or
   not the account exists. A request is recorded for **each organisation** where the member is active, the policy is
   on and their membership key is escrowed (one open request per person and organisation). The member gets an email
   per organisation if Resend is configured (`recovery.request_created`).
2. Admin: People shows the request (badge on People). **Approve** needs the admin's unlocked vault and a fresh TOTP
   code. The server releases only *this admin's* escrow plus a 5-minute approval token for that request
   (`recovery.escrow_opened`), and marks the member's key as seen (the member's client replaces it on the next
   unlock). An admin can't approve their own request, nor one for a member whose 2FA they reset (see below). The
   member is emailed when their escrow is opened and when the request is approved.
3. The admin's browser opens the escrow with its own membership key. It checks that the result is the private key of
   the member's listed membership key, generates a random 32-byte secret `R`, and uploads two things:
   - `AES-GCM(HKDF(R, "clane-vault/admin-recovery-membership"), membershipPrivateKey, AAD "admin-recovery-membership:<requestId>:<orgId>:<userId>:<memberPublicKey>")`;
   - a proof `HKDF(R, "clane-vault/admin-recovery-proof")`, of which the server stores only a SHA-256
     (`recovery.request_approved`).

   The admin gets the link `PUBLIC_URL/recover/<requestId>#<R>` once and sends it to the member by a channel they
   trust, telling them to open it in a private window on their own device. The fragment never reaches the server.
4. Member opens the link. The page drops the fragment from the address bar, sends the proof, then a fresh TOTP code,
   receives the blob and opens the membership key (checked against its public key). The link never returns the
   account's wrapped user key: whoever holds the link (its approver knows `R`) must not be able to guess the master
   password offline and reach private items or other organisations. The page says what this
   restores: *"what you have in {Org}. Your private items and other organisations stay locked."* The member picks a
   new master password.

   This is a **scoped reset**: the client makes a new user key and a new account key pair, and wraps the membership
   key under the new user key. `POST /auth/recovery/finish` then does all of this at once:
   - stores the new material;
   - moves the old account material and the old recovery kit into an **archive**;
   - marks the member's other organisations' keys as archived, and their rows sealed to the old account key;
   - revokes every session;
   - emails the member and logs `auth.admin_recovery_used` with the organisation and approving admin.

   The member then saves a **new recovery kit** before the vault opens. On the next unlock in that organisation, the
   client rebuilds the member's own records there from the folder rows, replaces the membership key (an admin has
   seen it) and escrows the new one.
5. The link works **once** and for **24 hours** (longer only for a member whose 2FA was reset, see below). Five wrong
   attempts (wrong proofs or wrong 2FA codes) burn it. Pending requests lapse after 7 days. Expiry is swept every few
   minutes (`recovery.request_expired`). Admins can deny a request or cancel a sent link; disabling an admin burns
   the links they approved.

**What the reset left behind.** A banner says how many private items and other organisations stayed locked; it doesn't
show when nothing did. The old recovery kit, or the old master password, restores everything in Settings → Security →
*From before your password reset*:
- the archive is opened on the device. The server hands out the old key material only for a fresh 2FA code **and**
  proof of the old secret: the old master password's auth key (checked against the archived auth hash) or the old
  kit's auth value. Wrong ones count toward the sign-in lockout. A session and a 2FA code alone are never enough: whoever
  completed the reset (in the 2FA-reset path, two of the organisation's admins) could otherwise guess the old master
  password offline. A session confined to one organisation needs a step-up first;
- private items and other organisations' keys are re-wrapped under the new user key;
- rows sealed to the old account key move to the membership keys.

The archive stays until the member deletes it (*Forget it*).

**Another organisation's admin link after a reset.** If another organisation approves its (still open) request, its
link sees that the account was reset since. It then asks for the member's **current** master password instead of a
new one (the wrapped user key comes only after the server checks it: `POST /auth/recovery/restore-membership/material`),
and restores that organisation (`recovery.membership_restored`), without a reset and without signing out.

**Nobody restores an organisation.** Its folder owners and editors see "Needs access again" next to the member and give
the folder key again with one click (`folder.access_regranted`). The member's new key fingerprint is shown. The
owners of records shared directly see "Share again".

**The admin never sets or sees the new password**, and can't complete the reset without the member's 2FA.

## If the authenticator is lost too

Recovery keeps the account's 2FA, and every 2FA code is accepted **once** (the last used 30-second step is stored per
account and checked by sign-in, 2FA setup, recovery, approvals and the policy switch). If someone has lost both their
master password and their authenticator:

1. An admin uses **Reset 2FA** on People (signs them out everywhere; the server records which admin did it and when).
   For an organisation owner, an instance admin does it in **Server → Accounts** (see "Organisations" below).
   **Verify the person's identity out-of-band before resetting 2FA** (a call to a known number, in person): a 2FA
   reset is what turns a stolen kit into a takeover (see the threat model).
2. **With a recovery kit:** the member uses it; because the account has no authenticator, the flow asks them to scan
   a new QR code, then to enter the next code it shows.
3. **With admin recovery:** the member asks for a reset and an admin approves it. While the member's authenticator
   is missing (and again when the new password is set, if the authenticator was set up through the link) the server
   guarantees exactly this:
   - **two distinct admin accounts**: the admin who reset 2FA can't be the approver, in either order;
   - **the approver was already an admin at least `ADMIN_RECOVERY_APPROVER_MIN_AGE_DAYS` (default 7) before the
     reset** (admin accounts record when they became admin), so an admin can't invite a second admin account of
     their own for the occasion; refused with `approver_too_new`;
   - **a waiting period**: the link only lets the member set up a new authenticator once
     `ADMIN_RECOVERY_RESET_DELAY_HOURS` (default 24) have passed since the reset; before that it answers "try again
     in N hours". Such a link stays valid until 24 hours after the delay ends
     (`max(approval + 24 h, reset + delay + 24 h)`), so an approval made right after the reset isn't wasted;
   - **notifications**: the member is emailed when their 2FA is reset, when their escrow is opened, when a reset is
     approved and when it is used; every admin is emailed when a new admin account becomes active (`admin.added`).

**Residual risks.** (A) A stolen kit plus a socially engineered 2FA reset is a takeover (see the threat model).
(B) An honest 2FA reset plus one rogue, long-standing admin who approves can still take over the account once the
delay has passed, if the member doesn't react to the emails. The rules count actions by distinct accounts, not
intent. Verify the person's identity out-of-band before both the reset and the approval, and check the event log
(`admin.reset_2fa`, `recovery.request_approved`, `recovery.escrow_opened`, `auth.admin_recovery_used`).

## Threat model

| Who | Kit | Admin recovery off | Admin recovery on |
|---|---|---|---|
| Database thief | Sees `recoveryWrap` + a hash of the auth value: can't unwrap or brute-force a 256-bit key. | Nothing new. | Escrows are sealed to admins' X25519 keys; approved blobs need `R` (only in the link). |
| Server operator (passive) | Same as a database thief. | Same. | Same. Can't open escrows (no admin private key). |
| Server operator (active / malicious) | Could serve malicious JavaScript, which defeats any web-based E2E design anyway. | Same. | Could also claim the policy is on and list its own key as an "admin"; clients would escrow to it. This is no worse than serving malicious JavaScript, but it is a concrete reason to run the image you were given and protect the host. |
| Someone with the kit code only | Needs the account's TOTP too. | — | — |
| Someone with the kit and the authenticator | Can reset the master password (that's the purpose). Store them apart. | — | — |
| A rogue admin | Can't use a member's kit. | Can reset 2FA (existing) but can't decrypt or take over a vault. | **Can open an escrowed member's membership key of that organisation**: their team folders and shares there, on their own device (the member is emailed, and their client replaces the key). Never their private items or other organisations. Can approve a reset but can't complete it without the member's 2FA. Resetting that 2FA as well is refused (two distinct admins), a freshly invited second admin account can't approve either (approver must have been admin ≥ 7 days before the reset), and there is a 24 h delay with emails to the member and admins. Remaining: an honest reset plus one rogue long-standing approver (residual risk B). Everything is logged. |
| Stolen access token | Can't create/replace a kit (needs master-password auth key). | — | Can't switch the policy on (needs the admin's master password and fresh TOTP) and can't approve (needs fresh TOTP and the admin's unlocked private key). |
| Intercepted recovery link | — | — | Needs the member's TOTP; single-use, 24 h, five wrong attempts burn it. If the member's 2FA was reset, the link alone is enough to set up a new authenticator, which is why that needs a second admin and a waiting period, and the member is emailed. |
| Stolen kit + a socially engineered 2FA reset | **Takeover**: the kit then sets up a new authenticator. Admins must verify identity out-of-band before resetting 2FA. | Same. | Same. |
| A captured 2FA code | Can't be replayed: each code is accepted once per account. | | |

## Operational guidance

- Ask everyone to save their recovery kit offline (printed, sealed envelope, or a separate password manager), and
  never in the same place as their authenticator.
- Turn on admin recovery only if your organisation accepts that admins can restore (and so read) what members hold in it. Keep the
  number of admins small (at least two long-standing admins, for the two-person rule) and make sure every admin uses
  2FA on a separate device. Watch for "new admin" emails.
- Never reset someone's 2FA on a chat message alone: confirm it's them out-of-band first.
- Before approving, confirm out-of-band that the person asking is really the member (a call, in person). Send the
  link through a different channel from the one the request may have come from.
- After turning the policy on, escrows appear as members unlock; the Settings page shows how many people are
  escrowed. A member who never unlocks again can't be recovered by an admin.
- Watch the event log for `auth.recovery_kit_used`, `auth.admin_recovery_used`, `recovery.request_*`,
  `recovery.escrow_opened` and `admin.recovery_policy_*`.
- Configure Resend (`RESEND_API_KEY`, `EMAIL_FROM`) so people are told when a reset is requested or used.

## Organisations

Admin recovery is a setting of each organisation, and since 1.2 it works for people in several organisations: each
organisation's admins hold escrows of that organisation's membership key only, and can restore only that. Joining or
leaving another organisation changes nothing in this one. Leaving an organisation deletes that membership's keys and
escrows. Resetting someone's 2FA changes their whole account, so on People it needs an admin of every organisation
they belong to (or an instance admin who is an admin there), and it never applies to an organisation owner. See
`docs/design/2026-10-08-per-org-keypairs.md`.

**Resetting an owner's 2FA.** No organisation's admin can reset its owner's authenticator. An instance admin can, by
email address, without being a member of the owner's organisations: **Server → Accounts → Reset someone's
authenticator** (a confirmation step first), or `POST /admin/instance/users/reset-2fa` with `{ "email": "…" }` (10 a
minute; `404 not_found`, `409 disabled`). It works for any account, owners included, and does what **Reset 2FA** does:
the account goes back to authenticator setup, every session is signed out, the person is emailed (through the server's
email settings) and the instance admin is recorded as the resetter for admin recovery. The event is
`instance.reset_2fa`, logged at instance level (no organisation). Like **Reset 2FA** on People, it asks for no
re-authentication. An instance admin can never reset their own account this way (`400 self`): a signed-in session
shouldn't be able to drop its own second factor.

**The server operator's command.** When the instance admin is the one locked out, or on a self-hosted server without
one to hand, whoever runs the server resets an account from the command line:

    docker compose exec clane-vault node dist/src/scripts/reset-2fa.js --email someone@company.com

It has the same effect and logs `instance.reset_2fa` with `via: "cli"`. No resetter is recorded, so while the person
sets up a new authenticator no admin can be the second admin of an admin recovery: a recovery link waits until they
have set it up. Confirm who is asking out-of-band first, as for any reset.

**Upgrading to 1.2.** The migration deletes the old whole-account escrows and ends open requests. Members escrow their
membership keys again when they next unlock in each organisation. Until then an admin can't help them: they use their
recovery kit.
