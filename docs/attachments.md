# File attachments

Since 1.6. Attach files (scans, contracts, keys, certificates, licence files…) to any record, of any type, private or
in a shared folder. Files are encrypted in your browser before they leave it and decrypted in the browser of whoever
opens them; the server stores ciphertext only. Design: `docs/design/2026-10-12-attachments.md`.

## Using files

- **Add.** Open a record and press **Attach file** in its **Files** section, or drop files anywhere on the open record
  (the panel says "Drop to attach to …"). In the editor there is an **Attach files** drop target at the bottom: for an
  existing record files upload at once ("Files are saved as they upload", independent of Save); for a new record they
  wait in a queue and upload right after the first save, and the record's panel shows their progress. Cancelling a new
  record discards the queue. Several files at once are fine; each is its own upload.
- **Progress.** Each upload shows a bar with the bytes sent, **Cancel**, and **Retry** after a failure. Retry keeps
  what the server already has. Leaving the page while files upload asks first. Nothing about an upload survives a page
  reload: add the file again (it starts over under a new key).
- **Open.** **Preview** (eye) shows images (PNG, JPEG, GIF, WebP), PDFs and plain text in a sheet; **Download** saves
  the file. In Chrome and Edge you choose where to save first and the file streams to disk; elsewhere it is assembled in
  memory and saved with the browser's download. Any other type (Office files, archives, HTML, SVG, executables…) is
  download-only. Programs (`.exe`, `.ps1`, `.sh`, `.jar`, …) ask before they download and say who added them.
- **Remove.** Removes the file for everyone at once. There is no file trash: the record's own trash covers the record
  with all its files.
- **List.** The record list shows a paperclip with the number of files. Each file shows its size, who added it and when.

## Who can do what

Access follows the record. Sharing a record (directly or through a shared folder or group) shares its files; removing
someone's access stops their downloads at once. Nothing is re-encrypted on share.

| | Owner | Can edit | Can view | Use only |
|---|---|---|---|---|
| See the files (names, sizes, who added them) | yes | yes | yes | yes |
| Download, preview | yes | yes | yes | **no** |
| Add, remove, cancel an upload | yes | yes | no | no |
| Include a file in a one-time link | yes | yes | no | no |

**Use only** can copy a password without seeing it, but a file can't be used without opening it, so use-only holders
can't download. This is enforced by the server (it never sends them the bytes), so for files it is a hard limit. They
see the file names with a lock and "Ask the owner for Can view to download". In the trash, files stay listed but can't
be opened, added or removed until the record is restored.

## One-time links

A one-time link can carry files, chosen per link: the link sheet lists the record's files with a checkbox each, all off,
with the total size and a warning that the link carries the keys to these files. At most 25 files and 100 MB per link.
The recipient's page lists the files with **Download** (never a preview on that page). Opening the link gives the
recipient 30 minutes to download, even after the last allowed open. Revoking the link, the creator losing edit, trashing
the record or removing the file stops the downloads at once; removing a file revokes any live link that carries it.
Organisations can keep files out of links by policy.

## Offline copy and the browser extension

The offline copy lists files under their records with their size and "Available online"; it never stores their content,
so opening a file needs a connection. The browser extension doesn't show files.

## Limits

| Limit | Default | Setting |
|---|---|---|
| File size | 100 MB | `ATTACHMENT_MAX_FILE_MB` (1–100); an organisation may set a lower one by policy |
| Files per record | 25 | `ATTACHMENT_MAX_PER_RECORD` |
| All files of one record | 250 MB | `ATTACHMENT_MAX_RECORD_MB` |
| Per organisation (files on records in its shared folders) | 2 GB | `ATTACHMENT_ORG_QUOTA_MB` |
| Per person (files on their private records) | 512 MB | `ATTACHMENT_USER_QUOTA_MB` |
| The whole server | 10 GB | `ATTACHMENT_INSTANCE_QUOTA_MB` |
| Uploads per person per 24 hours | 2 GB | `ATTACHMENT_DAILY_UPLOAD_MB` |

The app refuses a file that can't fit before it sends anything and says which limit it hit. A private record shared
with someone in an organisation is still charged to its owner. Moving a record into a shared folder moves its files'
usage to the organisation; the move is refused when the organisation's quota can't take them. Uploads in progress
count against the quota until they finish or are abandoned (an upload must finish within 24 hours; after that it takes
no more chunks and is removed).

## What the server sees

| The server knows | The server never knows |
|---|---|
| that a record has N files, each one's id, ciphertext size (the file size plus 16 bytes per MiB), who added it and when | file names, types, content, the hash of the content |
| who downloaded which file and when (the event log) | whether two files are the same (each has its own key) |
| usage per organisation, person and server | anything in the record itself |

How it works: each file gets its own random 256-bit key. The file is cut into 1 MiB chunks, each encrypted with
AES-256-GCM under that key with a nonce made of 8 random bytes and the chunk's position, and with the file id, the
position and the number of chunks bound into every chunk (so chunks can't be swapped, reordered, dropped or replayed).
The file key and the metadata (name, type, size, SHA-256 of the content) are encrypted under the record's key. After
downloading, the app checks every chunk and the SHA-256 of the whole file; a file that fails any check is discarded
("This file is damaged"). A chunk is never encrypted twice under the same key: a retry resends the same ciphertext, and a
fresh start uses a new key.

Previews are safe by construction: the app never renders a file as HTML or SVG, never opens it in a frame or a new tab,
checks an image's or PDF's real format (its first bytes) before showing it, renders PDFs itself on a canvas with scripts
off (pdf.js), and shows text as text. Downloads are always handed to the browser as `application/octet-stream`.

The server can't scan files for malware (it only has ciphertext). Every file shows who added it, the event log records
it (`attachment.add`), and organisations that want to can turn previews or uploads off.

## Event log

| Action | When |
|---|---|
| `attachment.add` | an upload completed (`meta.size`, `meta.chunkCount`) |
| `attachment.remove` | a file was removed (`meta.size`) |
| `attachment.download` | someone opened a file (logged once per person and file per 10 minutes; `meta.wide` when ten or more people can open the record) |
| `attachment.upload_abandoned` | an upload was left unfinished for 24 hours and removed |
| `attachment.quota_exceeded` | an upload (or a move) was refused for quota (`meta.scope`, `used`, `quota`) |
| `link.attachment_download` | a one-time link's recipient downloaded a file |
| `link.create` / `link.revoke` | `meta.attachments` (files carried) / `meta.reason: "attachment_removed"` |

Never in an event: a file name, type or hash. A record's Activity lists added, downloaded and removed files.

## For administrators

- **Organisation settings → Storage**: usage against the quota, the largest 20 records (titles you can open), the limits
  and the policy, and storage by member (CSV).
- **Risk dashboard**: a **File storage** tile (used / quota, by member, CSV); the benchmark "File storage under 90 % of
  the quota" goes critical above 90 %; alerts count refused uploads, downloads through one-time links and downloads from
  widely shared records.
- **Policies** (`docs/policies.md`): **File attachments** (off: no new uploads, existing files stay downloadable),
  **Largest file** (can only lower the server's limit), **File previews** (off: download only), and in one-time links
  **Allow files in links** (off: links can't carry files and live links that carry files are revoked).
- **Server → Storage** (instance admins): the backend, usage against the server quota, per organisation, the clean-up
  (abandoned uploads, removed files, purged files in S3 and, once a day, S3 orphans) with **Run now**, and the backup
  note. Instance admins see a banner when the server passes 80 % of `ATTACHMENT_INSTANCE_QUOTA_MB`; with database
  storage the server also logs a warning at start.

## Storage, backups and Supabase (operators)

Files live **in Postgres by default** (`ATTACHMENT_STORAGE=db`): one container, and the scheduled `pg_dump` backup and a
restore cover everything. The chunk column is stored out of line without compression (ciphertext doesn't compress), and
backups now dump at compression level 1 (about the same size, a fraction of the CPU). A backup grows by roughly the
attachment volume (5 GB of files ≈ a 5.5 GB encrypted dump, taking minutes rather than seconds), and so does a restore.

**Managed Postgres (Supabase and others).** Database storage is the expensive part of those plans, and every download
also leaves through the API (egress). Rough guidance:

| Plan | Suggestion |
|---|---|
| Supabase Free (500 MB database) | `ATTACHMENT_INSTANCE_QUOTA_MB=200`, or `ATTACHMENTS_ENABLED=false` |
| Supabase Pro (8 GB included, then per GB-month) with real use | `ATTACHMENT_STORAGE=s3` with Supabase Storage's S3 endpoint (below) |
| Small VPS with the bundled Postgres | the defaults (10 GB on the server, 2 GB per organisation), watching disk and backup size |

Lower the quotas to fit your plan, and move to S3 before raising them.

**S3-compatible storage** (`ATTACHMENT_STORAGE=s3`): chunks go to `<ATTACHMENT_S3_PREFIX><file id>/<index>` in a bucket
of their own. The API proxies every byte (no pre-signed URLs), so access control and the event log stay in one place.
Use a different bucket and credentials from the backups (`BACKUP_S3_*`): attachment credentials need read, write, list
and delete; backup credentials ideally only write.

    ATTACHMENT_STORAGE=s3
    ATTACHMENT_S3_ENDPOINT=https://<project-ref>.supabase.co/storage/v1/s3   # Supabase Storage; empty for AWS S3
    ATTACHMENT_S3_REGION=eu-central-1
    ATTACHMENT_S3_BUCKET=vault-files                                         # a private bucket
    ATTACHMENT_S3_PREFIX=attachments/
    ATTACHMENT_S3_ACCESS_KEY_ID=…
    ATTACHMENT_S3_SECRET_ACCESS_KEY=…
    ATTACHMENT_S3_FORCE_PATH_STYLE=true

With S3 storage the database backup leaves the chunk data out (`--exclude-table-data`), so **back the bucket up
yourself**: turn on object versioning (and a lifecycle rule for old versions) or replicate it to another bucket. As long
as any file still has its chunks in the database (a half-moved instance), backups keep including chunk data.

**Switching storage.** Each file records where its chunks are, so an instance keeps working while it moves. Set the
`ATTACHMENT_S3_*` variables and `ATTACHMENT_STORAGE=s3` (new uploads go to the bucket), restart, then copy the existing
files over (safe to stop and run again; each file flips only after all its chunks were copied):

    docker compose exec clane-vault node dist/src/scripts/attachments-move.js --to s3
    # back to the database: --to db (with ATTACHMENT_STORAGE=db)

**Proxies need no change.** Chunks are 1 MiB, so every request stays under the API's 2 MB limit and the 5 MB the
install guide asks proxies for. A 100 MB file is about 100 requests; attachment traffic has its own per-person rate
limits (600 chunk requests a minute each way, 60 new files a minute) outside the per-address limit, and the public link
download route has 300 a minute per address.

## Not in this release

- **Keeper import with files.** Keeper Commander's `export --format json --zip` (the JSON plus the files records
  reference) isn't imported yet: the Migrate from Keeper report still lists attachments to move by hand
  (`docs/migrate-from-keeper.md`). Planned for a later release, with the zip read entry by entry and size guards.
- Thumbnails in the file list, file versions, a file trash, folder-level files and files in the browser extension.
