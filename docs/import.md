# Import from another password manager

**+ New → Import** reads an export file in the browser, shows a preview (folders, a count per record type, the first
records with their type, skipped rows), then
encrypts every record on the device and uploads it in batches of 25 into your private vault. The file itself is never
uploaded. Delete the export when you're done: it holds every password in plain text.

For a whole Keeper vault with shared folders and their people, admins use the bulk migration instead
(`docs/migrate-from-keeper.md`).

## Sources

The format is detected from the file. Folders (or vaults, groups, categories) become private folders with the same
names, merged case-insensitively with folders you already have; or choose **Put them all in one folder**. A 2FA secret
(`otpauth://` URI or a base32 key) becomes the record's authenticator code; one that can't be read is kept in the notes.

Items keep their kind: cards, bank accounts, servers, databases, SSH keys, Wi-Fi, software licences, identity
documents, contacts, addresses and memberships become records of that type (see `docs/record-types.md`), with each
value in its template field. Anything a type has no field for becomes a **custom field** with a sensible kind (hidden
for passwords, PINs and other secrets, website, email, phone, date, one-time code, multi-line); past 64 custom fields
the rest go into the notes. Items with no matching type (documents, medical records…) are skipped and listed with a
reason.

| Source | How to export | File |
|---|---|---|
| Keeper | Web vault: **Settings → Export → JSON** (or CSV). Commander: `export --format json`. | `.json`, `.csv` |
| Bitwarden | **Tools → Export vault**, format **.json** or **.csv** (not the encrypted JSON). | `.json`, `.csv` |
| 1Password 8 | Desktop app: **File → Export →** your account, format **1PUX** (or CSV). | `.1pux` (a zip with `export.data`), `.csv` |
| LastPass | Web vault: **Advanced options → Export** (or the extension: **Account → Fix a problem yourself → Export vault items → Export data**). Save the CSV. | `.csv` with `url,username,password,totp,extra,name,grouping,fav` |
| Dashlane | Web app: **My account → Settings → Export data → CSV** (unzip it). Import `credentials.csv`, `securenotes.csv` for notes, `payments.csv` for cards and bank accounts, `ids.csv` for passports, licences and ID cards. | `.csv` |
| Zoho Vault | **Tools → Export Secrets**, format **CSV**. Username and password come from the `SecretData` lines; `Folder Name` becomes the folder. | `.csv` |
| Chrome / Edge | `chrome://password-manager/settings` (or `edge://wallet/passwords`) **→ Export passwords**. | `.csv` with `name,url,username,password,note` |
| Any other CSV | Any CSV with a header row. | `.csv` |

Mapping details:

- **Keeper** (JSON and CSV): record types map as in the bulk migration (`docs/migrate-from-keeper.md`); in a CSV a
  `$type` custom field pair names the type.
- **Bitwarden JSON**: cards → payment card (expiry month/year → `MM/YY`); identities → identity document when they
  hold a passport, licence or SSN number, else a contact, else an address; SSH keys → SSH key. Custom fields: text,
  hidden (→ hidden field) and boolean; linked fields are dropped. Bitwarden's **CSV** has no columns for cards,
  identities or SSH keys: those rows are skipped with "export as JSON to import them".
- **1PUX**: each vault becomes a folder. Logins (`001`), Secure Notes (`003`) and Passwords (`005`) as before; Credit
  Card, Bank Account, Server, Database, Wireless Router, Software License, Passport, Driver License, API Credential,
  SSH Key, Membership and Identity (→ contact) map to their types by 1Password's field ids (`ccnum`, `cvv`, `expiry`,
  `hostname`, `database_type`, `network_name`, `reg_code`, `private_key`, `membership_no`…). Other section fields become
  custom fields. Archived items are skipped.
- **LastPass**: the `grouping` path (`Work\Dev`) becomes `Work / Dev`; rows with the URL `http://sn` are secure notes.
  A secure note of type Credit Card, Bank Account, Server, Database, Wi-Fi Password, Software License, Passport,
  Driver's License, SSH Key, Membership or Address (`NoteType:` line) becomes that record type from its `Key:Value`
  lines (`Notes:` and what follows stays the note); other note types stay plain notes.
- **Dashlane**: `category` becomes the folder; `otpUrl` or `otpSecret` the authenticator; `username2`/`username3`
  become custom fields. `payments.csv`: cards → payment card, bank rows → bank account. `ids.csv`: passport, driving
  licence, ID card (other kinds → identity document "Other").
- **Zoho Vault**: `Password Name` (or `Secret Name`) is the title, `Password URL` the website, `TOTP` the
  authenticator, `Description` and `Notes` the notes, other `SecretData`/`CustomData` lines custom fields.

## Any other CSV: match the columns

If the header isn't one of the formats above, the import asks which column holds what: **Title, Username, Password,
Website, 2FA secret, Notes, Folder**. It guesses from the column names (`account`, `user`, `pass`, `site`,
`comment`, `group`...) and shows the first rows as mapped (passwords and 2FA secrets are left out of that preview).
At least the title, password or website column is needed; a missing title is taken from the website's host name.

## Limits

- Files up to 20 MB. Records over about 40 KB of text are skipped ("Too large to import").
- Attachments, password history, favourites, tags and sharing are not imported.
- A batch that fails is retried once; records that still fail are counted as "couldn't be uploaded" and can be
  imported again from the same file (duplicates are not detected).
