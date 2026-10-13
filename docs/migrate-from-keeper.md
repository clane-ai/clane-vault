# Migrate from Keeper (bulk migration)

Admins can move a whole Keeper vault into Clane Vault in one go: **Admin → Migrate from Keeper** in the sidebar
(also **+ New → Import → Bulk migration (admins)**). Shared folders become team folders with their people,
personal folders become the admin's private folders. Members who use the normal **Import** only bring their own
records into private folders (`docs/import.md` lists every source it reads: Keeper, Bitwarden, 1Password, LastPass,
Dashlane, Zoho Vault, Chrome / Edge and any CSV).

Everything happens in the admin's browser: the export file is read and encrypted there and is never uploaded.
The server only ever receives ciphertext, as with any other record.

## 1. Export from Keeper

### Keeper Commander (recommended: includes shared folders and their people)

Commander is Keeper's command-line tool. Sign in as a Keeper admin (or a user) who can see every shared folder
you want to move; only what that account can see is exported.

    pip install keepercommander
    keeper shell
    My Vault> export --format json keeper-export.json

The same in one line: `keeper export --format json keeper-export.json`.

The file has two parts:

- `shared_folders`: each shared folder's path and its people and teams (`permissions`), with their
  `manage_records` / `manage_users` rights;
- `records`: every record with its fields, custom fields and the folders it is in.

If Keeper asks for a confirmation for shared-folder data, accept it: without it there is no membership data and
team folders are created with only you in them.

### Keeper web vault (records only)

Settings → Export → JSON. This file has records and their folders but **no sharing data**: team folders are
created with only you in them, and you add people afterwards (folder → People).

## 2. Review the plan

Choose the file on **Migrate from Keeper**. The format is detected automatically. Before anything is written you see:

- **Folders.** Each Keeper shared folder → a team folder that you own. Nested paths are flattened
  (`Clients\Acme` → `Clients / Acme`); records in subfolders of a shared folder go into that team folder.
  Personal folders → your private folders. A folder of yours with the same name is reused (team folders only if
  you own them). Untick a folder to leave it out.
- **People** per team folder, matched by email:
  - an active Clane user is **added now**: Keeper `manage_records` (or `can_edit`) → **Can edit**, otherwise
    **Can view**;
  - an unknown email **will be invited** (tick box, on by default) and is added to the folder once they have
    registered (see step 4);
  - someone with a pending invite or who hasn't finished 2FA setup is added once they are active;
  - a disabled account is not added;
  - Keeper **teams** (names that aren't emails) are listed as *not mapped*: Clane has no teams, add those people
    by hand;
  - Keeper `manage_users` is noted as "folder manager" in the report: in Clane only the folder's owner manages
    its people.
- **Duplicates**: a record with the same title, username and URL already in the target folder (or twice in the
  export); for typed records also the same type and identifying field (host, SSID, last four card digits…). Choose **Skip them** (default) or **Import anyway**.
- **Good to know**: attachments (not migrated, listed in the report), records that are in several Keeper folders
  (a copy goes into each), records that can't be read.

### How records are converted

Keeper record types become the matching Clane record types (`docs/record-types.md`):

| Keeper `$type` | Clane type | Fields |
|---|---|---|
| `login`, `general` | Login | `login`, `password`, first URL, first one-time code |
| `bankCard` | Payment card | `paymentCard` (number, expiry `MM/YYYY` → `MM/YY`, security code), cardholder name, PIN, address → billing address |
| `bankAccount` | Bank account | `bankAccount` (account number, routing), name → account name, login, password |
| `serverCredentials` | Server credentials | `host` (host name, port), login, password |
| `databaseCredentials` | Database credentials | type, `host` (host, port), login, password |
| `sshKeys` | SSH key | `keyPair` (private, public key), host, login; the record password → passphrase |
| `wifiCredentials` | Wi-Fi | SSID, password, security |
| `softwareLicense` | Software licence | licence number, expiration date, date |
| `passport`, `driverLicense`, `ssnCard`, `birthCertificate` | Identity document | document type, name, number, issue and expiry dates |
| `address` | Address | street, city, state, postcode, country |
| `contact` | Contact | name, company, email, phone |
| `membership` | Membership | account number → member ID, organisation, password, expiration date |
| anything else (`encryptedNotes`, …) | Secure note | |

- Keeper dates (epoch milliseconds) become ISO dates.
- More URLs, more one-time codes, security questions and every custom field a type has no slot for become **custom
  fields** (hidden for secrets, website, email, phone, date, one-time code, multi-line) — not lines in the notes.
- A login with no username, password, URL or one-time code becomes a secure note (its fields kept as custom fields).
- The plan and the report show how many records of each type are migrated (counts only).
- Attachments are **not** migrated yet: download them from Keeper and attach them to the migrated records (Clane Vault
  has encrypted file attachments since 1.6, `docs/attachments.md`: drop the files on the record). Importing Keeper
  Commander's `export --format json --zip` (the JSON plus the files) is planned for a later release.

## 3. Run it

**Start migration** creates, in order: the team folders (you are the owner), their existing members (the folder
key is sealed to each person's public key in your browser), pending entries for people who can't be added yet,
the private folders, then the records in batches of 25 (each batch is retried once), and finally the invites.

Keep the page open until it finishes. If something fails (a lost connection, the vault locked) run it again from
the same page with the same file: what was already created in this session is skipped.

## 4. The report

At the end you get a report per folder (created / skipped / failed), the **invite links** to send (each is shown
once and works for 7 days), the people to add after they register, folder-manager notes, unmapped teams and the
attachments to move by hand. Download it as **CSV** or **JSON**; the files are made in your browser.

The report contains invite links: treat it as sensitive and delete it once the invites are sent.

### Complete pending members

Shares only work with active accounts (the folder key is sealed to the person's public key, which exists only
once they have registered and set up 2FA). People who weren't active during the migration are stored as
*pending members* of their folders (email and permission only, no keys). When they have registered, the
**Migrate from Keeper** and **People** pages show a badge; press **Complete pending members** and your browser
adds each of them to their folders. Only the folder's owner (the admin who migrated it) can complete them.
Pending entries disappear when completed, when the person is added another way, or when the folder is deleted.

## Privacy and clean-up

- The export file holds **every password in plain text**. Keep it on an encrypted disk, never email it or put it
  in a shared drive, and **delete it as soon as the migration is done** (and empty the trash / recycle bin).
- Nothing in the file is uploaded as is; only encrypted records leave the browser.
- Delete the downloaded report once the invites are sent: it contains invite links.
- After checking the result, turn off or delete the Keeper vault so nobody keeps using the old copies.
