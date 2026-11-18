# Record types and custom fields

Clane Vault records come in fifteen types (Keeper parity, chosen for IT teams), each with a field template, and any
record can carry custom fields. Everything about a record's type and fields lives inside the encrypted record body: the
server never learns that a record is a payment card or an SSH key.

## Types

The New record dialog groups them; each has a lucide icon used in the picker, the list, the record panel and the type
filter. Every type keeps its Notes field.

| Group | Type (`type`) | Template fields (`*` core field, stored at the top of the body) | List subtitle |
|---|---|---|---|
| Logins & access | Login (`login`) | Username\*, Password\*, Website\*, 2FA secret\* | username, else website |
| | Server credentials (`server`) | Hostname or IP, Port, Protocol (SSH, RDP, VNC, HTTPS, Telnet, Other), Username\*, Password\* | `user@host:port` |
| | Database credentials (`database`) | Type (PostgreSQL, MySQL / MariaDB, SQL Server, Oracle, MongoDB, Redis, Other), Host, Port, Database, Username\*, Password\*, Connection string (secret) | `PostgreSQL · host:port/db` |
| | SSH key (`sshKey`) | Username\*, Host, Private key (hidden multi-line), Public key (multi-line), Passphrase (secret) | `user@host` |
| | API key / secret (`apiKey`) | Service, Key ID, Secret (secret), Endpoint (URL) | service, else endpoint |
| | .env file (`envFile`) | Project, Environment, File name, Contents (hidden multi-line) | `project · environment`, else file name |
| | Wi-Fi (`wifi`) | Network name (SSID), Password\*, Security (WPA3, WPA2, WPA, WPA2/3 Enterprise, WEP, Open) | SSID |
| Payments & finance | Payment card (`card`) | Cardholder, Card number (secret; groups of four, Luhn hint), Expiry (MM/YY), Security code (secret), PIN (secret), Billing address (multi-line) | `•••• 4242 · Cardholder` |
| | Bank account (`bankAccount`) | Account name, Bank, IBAN / account number, BIC / sort code / routing, Online banking login\*, Password\* | `Bank · •••• 5678` |
| Identity | Identity document (`identity`) | Document type (Passport, Driving licence, ID card, Other), Full name, Document number (secret), Nationality, Issue date, Expiry date, Issuing authority | `Passport · Full name` |
| | Contact (`contact`) | Name, Company, Email, Phone | `Name · Company` |
| | Address (`address`) | Street, Street line 2, City, County / state, Postcode, Country | `Street · City · Country` |
| | Membership (`membership`) | Organisation, Member ID, Password\*, Expiry date | `Organisation · Member ID` |
| Other | Secure note (`note`) | (notes only) | "Secure note" |
| | Software licence (`softwareLicence`) | Product, Licence key (secret), Licensed to, Version, Purchase date, Expiry date | `Product · Version` |

The templates are code (`packages/crypto/src/recordTypes.ts`), shared by the web app, the extension and the validator.
A subtitle never shows a secret; a card shows only its last four digits.

## .env files

A *.env file* item keeps a project's `.env` as a backup, with every value a secret of its own. **New → .env file**
opens the New record dialog with the type chosen; it can go in any folder, private or shared. There is no special
folder: if you want one, make a folder such as *Env backups*. It is an ordinary folder.

**The stored text is the file.** `data.content` holds the file's text exactly as it was read, and nothing else is
stored: the entries you see are parsed from it each time (`parseEnv`, `packages/crypto/src/envFile.ts`, used by the web
app and the agent gateway alike). **Download** saves exactly that text, so the file you get back is byte-identical to the
one you dropped in: CRLF line endings, a byte-order mark, comments, spacing and lines the parser doesn't understand
included. The download is named after *File name* when that is a plain name such as `prod.env`. Chrome and Edge drop the leading
dot of a downloaded file's name (`.env` would arrive as `env`), so a name that starts with a dot, or no name, follows the
item's title: *Billing API* with `.env` downloads as `billing-api.env`, with `.env.production` as
`billing-api.env.production`. Rename it to `.env` after the download.

**In the editor**, drop a file on the drop zone or use **Choose file**. The file is read as strict UTF-8. Dropping it
fills *File name* and, from `.env.<name>` or `<name>.env`, *Environment*, when those are empty. Below it each entry is
a masked input (changing one rewrites only that entry's value) and **Add entry** appends one. **Edit as text** shows the
whole file in a masked text area, for comments or removing or renaming a key. A browser text area turns `\r\n` into
`\n`; the editor converts only the text you changed there, to the line ending most of the file uses, and the text
before and after your change keeps its stored bytes (a bare `\n` inside a quoted multi-line value and a lone `\r`
among them). Text you don't touch is saved byte for byte.

**In the record panel** each entry is a row: the key, the value masked, **Show** and **Copy**. **Copy all** copies the
whole file and **Download** saves it. A person with *Use only* gets Copy and Copy all, but no Show and no Download.

| Line | Read as |
|---|---|
| `KEY=value`, `KEY = value`, leading spaces | an entry; an unquoted value is trimmed |
| `export KEY=value` | the entry `KEY`; the prefix stays in the file |
| Key | `[A-Za-z0-9_.-]`, 1 to 128 characters |
| `KEY=` | an entry with an empty value (it can't be given to an agent) |
| `KEY=abc # note` | `abc`: in an unquoted value, a `#` after whitespace starts a comment |
| `KEY=abc#123` | `abc#123` (no whitespace before `#`). Node's dotenv would read `abc`; passwords with `#` are why |
| `KEY="a\nb"` | double quotes: `\n`, `\r`, `\t`, `\"` and `\\` are decoded, any other backslash pair is kept; may span lines |
| `KEY='a\nb'`, a value in backticks | literal, no escapes; may span lines |
| After a closing quote | only spaces and an optional `# comment`; anything else makes the line invalid |
| `${OTHER}`, `$OTHER` | kept literally. Nothing is expanded |
| `# comment`, a blank line | kept, not an entry |
| Anything else (`KEY`, `=x`, `KEY: value`, an unterminated quote) | kept verbatim as an invalid line and counted: *"2 lines aren't KEY=value. They are kept as they are."* |
| The same key twice | both kept; the last one is the value, as loaders do. The earlier one is marked *Overridden below* |
| `\n`, `\r\n`, a UTF-8 byte-order mark | kept exactly |

**Limits.** The contents are at most 32 768 bytes of UTF-8 and at most 500 entries, with no NUL character; the whole
record's 49 000-byte limit applies on top. A larger file is refused with *"This file is too large for a .env item
(32 KB). Attach it to a Secure note instead."* and one that isn't UTF-8 text with *"This file isn't UTF-8 text. Attach it
to a Secure note instead."* Attachments take much larger files, but then no single value can be shown or used on its own.

**Search** finds a .env file by its title, project, environment, file name and key names, never by a value.
Password health ignores the type. A one-time link shows the contents as one hidden text field. Agents use one entry of
the file (`docs/agents.md`, *.env files*).

**Older clients.** A web app or extension from before this type shows a .env file item as *Can't open this record*
and can't save it, so it can't damage it. Update the web app and the extension together.

## Custom fields

Any record can have up to 64 custom fields, added, renamed, retyped, reordered (up/down) and removed in the editor
(**Add field**). Each has a label (1–100 characters) and a kind:

| Kind (`kind`) | Editor | Panel |
|---|---|---|
| `text` | input | shown, Copy |
| `secret` | masked input with Show | masked, Show, Copy |
| `multiline` | text area | shown as typed, Copy |
| `url`, `email`, `phone` | input of that type | shown, Copy |
| `date` | date picker (`YYYY-MM-DD`) | localised date, Copy |
| `totp` | 2FA setup key (checked as base32) | live code with seconds left, Copy code |
| `hiddenMultiline` | masked text area with Show (keys, certificates) | masked, Show, Copy |

Secret kinds are `secret`, `totp` and `hiddenMultiline`; template fields use the same kinds (a card number is a
`secret`, an SSH private key a `hiddenMultiline`).

## Data model (record body v2)

```ts
interface RecordBody {
  v?: 2;                       // absent: a v1 body
  type: RecordType;            // one of the fifteen types
  title: string;
  username?: string; password?: string; url?: string; totpSecret?: string;   // core fields, only where the template has them
  notes?: string; passwordChangedAt?: string;
  data?: Record<string, string>;                                              // the template's other fields, by key
  fields?: { id: string; label: string; kind: FieldKind; value: string }[];   // custom fields
}
```

One representation, chosen so v1 logins are already valid v2 bodies and every existing reader of `username` /
`password` / `url` keeps working: the four core fields stay at the top of the body (for any type whose template has
them), every other template field goes in `data` keyed by the template's key (`data.number`, `data.hostname`), and
custom fields are an ordered list with stable ids.

- **Versioning.** Every encrypt writes `v: 2`. A body without `v` is a v1 body and is read exactly as before (type
  `login` or `note`, the five v1 fields). Unknown versions are refused (the record shows as "Can't open").
- **Validation** (`validate()` in `packages/crypto/src/records.ts`, on encrypt and decrypt): a known type and a title;
  core and `data` keys must belong to the type's template (anything else is refused, not silently dropped); values are
  text up to 64 KiB each; custom fields at most 64, unique ids (`[A-Za-z0-9_-]{1,64}`), labels 1–100 characters,
  allowed kinds only; blank values are dropped; the whole body at most 49 000 bytes of JSON, which keeps the
  ciphertext inside the API's 64 KiB envelope.
- **Older clients.** A client from before this change opens v2 logins and notes but ignores `data` and `fields`; if it
  saves such a record, those are lost. It refuses the other types (shown as "Can't open this record"). Update the web
  app and the extension together.

## What the server sees

`Record.type` is coarse metadata, not the real type: `login` (a login the extension may fill) or `item` (everything
else, secure notes included). The real type is encrypted. The API accepts `login`, `item` and, from older clients,
`note` (stored as `item`). Database migration `20261020000000_record_item_type` turns every existing non-`login` row (`note`) into `item`
and adds a check constraint so the column only holds `login` or `item`. Existing records keep working: their bodies are
unchanged v1 bodies until they're next saved.

## Permissions and secrets

- **Use only** holders never see any secret-kind field (password, card number, security code, PIN, custom secrets,
  private keys, passphrases, connection strings): no Show button, a "Use only: you can copy it, not view it." line, and
  Copy still works, exactly as the password always did (spec §5.6; a soft limit, not a cryptographic one). The list's
  hover copy-password shortcut stays hidden for them.
- **Search** covers titles and non-secret fields (usernames, websites, hosts, SSIDs, cardholders, option labels such as
  "WPA3", custom text fields); never a secret, never notes.
- **Type filter** in the list header ("All types" or one type) shows the matching records as a flat list.

## Password health and Needs attention

Only password-like credentials count: the core `password` of a login, bank account, server, database, Wi-Fi or
membership. Card numbers, security codes, PINs, licence keys, SSH private keys and passphrases, API secrets and custom
secret fields are never scored, never reported as weak, reused or old, and never sent to the breach check.

## One-time links and the offline copy

A one-time link snapshots the record's type, core fields (never the 2FA secret), `data` and custom fields (never `totp`
ones) — `linkSnapshot()` in `packages/crypto/src/links.ts`. The link page shows every field read-only, secrets hidden
until **Show**, Copy on each. Links made before record types have no `type` and show as a login.

The offline copy stores the sync response's ciphertext as before and opens every type.

## Importers

See `docs/import.md` and `docs/migrate-from-keeper.md`. Keeper (JSON and CSV, including the bulk migration), Bitwarden
(cards, identities, SSH keys, custom fields), 1Password (`.1pux` categories), LastPass (secure note types) and Dashlane
map into these types instead of flattening them into notes; fields with no template slot become custom fields.

## Browser extension

The extension fills logins only. Other types never appear in its list and are never filled (no card autofill in this
release). Saving a changed password from a page keeps a login's custom fields.
