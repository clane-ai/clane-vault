# Clane Vault: self-hosted install

Clane Vault is a zero-knowledge team password manager. This bundle runs it as a single container (API plus web app). You supply Postgres, either your own or the optional bundled one.

> **Security status: pre-audit, use for evaluation.** No external security audit has been done. Don't store
> production secrets in it or roll it out across a company until one has. See [SECURITY.md](../../SECURITY.md#status).

## Requirements

- Docker with Compose v2 (Linux, macOS or Windows).
- Internet access to pull the public image `ghcr.io/clane-ai/clane-vault` (no login needed).
- A Postgres 14+ database, or choose the bundled one during install.
- An HTTPS reverse proxy (nginx, Caddy, Traefik, a cloud load balancer) with a certificate for your hostname.

## Install

Linux/macOS:

    ./install.sh

Windows (PowerShell):

    .\install.ps1

The installer (logging in to a registry only if you set `REGISTRY_USERNAME` / `REGISTRY_TOKEN` for a private mirror) creates `.env` with random secrets if it does not exist (it never overwrites one), asks whether to use the bundled Postgres, then pulls the image, starts it and waits for `/api/v1/health`.

Using your own Postgres: answer `n` and enter its `DATABASE_URL` (`postgresql://user:password@host:5432/dbname`). The database user needs to create tables (migrations run automatically on every start). The bundled database is enabled by `COMPOSE_PROFILES=bundled-db` in `.env`.

Review `.env` afterwards, especially `PUBLIC_URL` (the https address users open) and `TRUST_PROXY` (number of reverse proxies in front of the container, normally 1).

## First admin

    docker compose exec clane-vault node dist/src/scripts/bootstrap.js --email you@yourcompany.com

This prints a one-time invite link (valid 48 hours). Open it, set a password and enrol TOTP. That account owns the main organisation and is the instance admin (Backups). It refuses to run if an admin already exists; invite everyone else from the app.

Instance admins are accounts, never emails in configuration. To add or remove one, or to give an organisation a new owner:

    docker compose exec clane-vault node dist/src/scripts/instance-admin.js --email you@yourcompany.com --grant   # or --revoke
    docker compose exec clane-vault node dist/src/scripts/org-owner.js --email you@yourcompany.com [--org <slug>]

To reset someone's authenticator (two-step sign-in) when nobody can in the app: the instance admin's own, or an organisation owner's on a server without an instance admin to hand. Instance admins reset anyone else's, owners included, in **Server → Accounts**.

    docker compose exec clane-vault node dist/src/scripts/reset-2fa.js --email someone@yourcompany.com

They are signed out everywhere, set up a new authenticator at their next sign-in, and are emailed if email is set up. Confirm who is asking out-of-band first (`docs/recovery.md`).

## TLS

The container speaks plain HTTP on `127.0.0.1:8080` (`HTTP_BIND` / `HTTP_PORT`). Put your own HTTPS reverse proxy in front and forward to it, passing `X-Forwarded-For` and `X-Forwarded-Proto`. Never expose the plain HTTP port publicly. Keep `COOKIE_SECURE=true`.

### Reverse proxies and `TRUST_PROXY`

Set `TRUST_PROXY` to the **number of proxies** between the internet and the container (one proxy → `1`; e.g. Nginx Proxy Manager → Traefik → container → `2`). Never set it to `true`. Every proxy in the chain must **append** to `X-Forwarded-For` rather than overwrite it — Traefik, for example, only keeps an upstream proxy's header when that proxy's IP is listed in the entrypoint's `forwardedHeaders.trustedIPs`.

Check it after your first sign-in: `SELECT ip, action, at FROM "Event" ORDER BY id DESC LIMIT 5;` (prefix the schema if you use one). The `ip` must be the user's real public address. If it shows a private proxy address, every user shares one rate-limit bucket and a few failed sign-ins will lock everybody out for a minute.

The app sends `Strict-Transport-Security` only when it sees `X-Forwarded-Proto: https` through the trusted chain; verify with `curl -sI https://your-host/ | grep -i strict`.

## Running under a path (e.g. /vault)

One image runs at the root of a host or under a path such as `https://northwind.example.com/vault`; the path is chosen at
runtime, no rebuild:

1. In `.env` set `PUBLIC_URL` to the full address including the path: `PUBLIC_URL=https://northwind.example.com/vault`
   (no trailing slash). The path is taken from it. You may also set `BASE_PATH=/vault`, but it must then equal
   `PUBLIC_URL`'s path or the server refuses to start. Path segments may only use `A-Z a-z 0-9 . _ ~ -`.
2. `docker compose up -d`. The container now serves **only** under the path: the web app at `/vault/`, the API at
   `/vault/api/v1` (health: `curl http://127.0.0.1:8080/vault/api/v1/health`), and `/vault` redirects to `/vault/`.
   Requests outside `/vault` get 404.
3. Point the reverse proxy at the container **without stripping the prefix**: the app expects to see `/vault/...`.

Nginx Proxy Manager, on the proxy host for `northwind.example.com` → **Custom locations** → **Add location**:

| Field | Value |
| --- | --- |
| Define location | `/vault` |
| Scheme | `http` |
| Forward Hostname / IP | the Docker host (or the container name if NPM shares its Docker network) |
| Forward Port | `8080` (`HTTP_PORT`) |

Leave the gear (advanced) box empty: NPM's custom location becomes `location /vault { proxy_pass http://host:8080; }`,
which passes `/vault/...` through unchanged. Do **not** add a trailing slash or a path to the forward address (that
would strip `/vault`). NPM already sends `X-Forwarded-For` and `X-Forwarded-Proto`; keep `TRUST_PROXY=1`. SSL is
configured on the proxy host as usual (Force SSL on). The site's own root (`/`) can keep serving something else.

Plain nginx equivalent:

```nginx
location /vault {
    proxy_pass http://127.0.0.1:8080;   # no URI part: the /vault prefix is passed through
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

What follows the path: invite, join, recovery and one-time-link URLs and emails (from `PUBLIC_URL`), the SSO redirect
URI (`https://northwind.example.com/vault/api/v1/auth/sso/callback`: register that one at your identity provider), the
session cookie (scoped to `/vault/api/v1/auth`), the installable app (service worker and manifest scoped to `/vault/`)
and the browser extension (connect it to `https://northwind.example.com/vault`). Several instances can share one host under
different paths; their browser storage and offline copies are kept apart.

Moving an existing install to a path: change `PUBLIC_URL`, restart, update the SSO redirect URI at the identity
provider and reconnect browser extensions to the new address. Links already sent (invites, one-time links) point at
the old address and must be sent again.

## Running in production

- **One replica only.** Rate limits and the expired-link cleanup run in the app's memory; more replicas multiply the limits.
- **Request size:** imports upload batches of up to ~2 MB. Allow at least 5 MB on your proxy (nginx: `client_max_body_size 5m;`). File attachments need nothing more: they travel in 1 MiB chunks (see "Attachments and storage").
- **Clock:** keep the host on NTP — authenticator (2FA) codes fail if the clock drifts by more than ~30 seconds.
- **Health check:** `GET /api/v1/health` (under `BASE_PATH` when set) returns `{"ok":true,"db":true}`; it also checks the database, so use a few retries before restarting. From 1.6.2 the image has a built-in Docker health check (`node dist/src/scripts/healthcheck.js`, which follows `PORT` and `BASE_PATH`), so `docker compose ps` shows `healthy`. If you write your own, use the exec form, e.g. `test: ["CMD", "node", "dist/src/scripts/healthcheck.js"]`: the image has no shell, so `CMD-SHELL`, `curl` and `wget` checks don't work.
- The container is stateless: no volume is needed (unless you use `BACKUP_LOCAL_DIR`). Pin `CLANE_VAULT_VERSION`.

### Using a managed Postgres (Supabase, Azure, RDS…)

- Use a dedicated role and schema, e.g. `DATABASE_URL=postgresql://clane_vault_app:…@host:5432/postgres?schema=clane_vault&sslmode=require&connection_limit=5`. Avoid the schema name `vault` on Supabase (used by Supabase Vault).
- Use a **session-mode** connection (port 5432 / direct). Transaction-mode poolers (e.g. Supabase port 6543) need `&pgbouncer=true` and are not recommended.
- Give the role a connection limit of at least 2 × `connection_limit` + 5 so upgrades (old and new container plus migrations) don't run out of connections.
- On Supabase, do not add the schema to the Data API's exposed schemas, and grant the role nothing outside its schema.

## Attachments and storage

Since 1.6 people can attach files to records (`docs/attachments.md`). Files are encrypted in the browser; the server
stores ciphertext only. **No proxy change is needed:** uploads and downloads go in 1 MiB chunks, well under the 5 MB
above, with their own per-person rate limits.

By default files are stored **in Postgres** (`ATTACHMENT_STORAGE=db`): nothing else to set up, and the scheduled backup
covers them. The database (and every backup and restore) grows by the attachment volume; backups dump at compression
level 1, so 5 GB of files make roughly a 5.5 GB encrypted dump. Instance admins see **Server → Storage** and a banner
past 80 % of the server quota.

| Variable | Default | |
|---|---|---|
| `ATTACHMENTS_ENABLED` | `true` | `false` hides the feature and every attachment route answers `404 attachments_disabled`. |
| `ATTACHMENT_STORAGE` | `db` | `db` (Postgres) or `s3` (an S3-compatible bucket, below). |
| `ATTACHMENT_MAX_FILE_MB` | `100` | Largest file, 1–100. Organisations may lower it by policy. |
| `ATTACHMENT_MAX_PER_RECORD` | `25` | Files per record. |
| `ATTACHMENT_MAX_RECORD_MB` | `250` | All files of one record together. |
| `ATTACHMENT_ORG_QUOTA_MB` | `2048` | Per organisation (files on records in its shared folders). |
| `ATTACHMENT_USER_QUOTA_MB` | `512` | Per person (files on their private records). |
| `ATTACHMENT_INSTANCE_QUOTA_MB` | `10240` | The whole server. |
| `ATTACHMENT_DAILY_UPLOAD_MB` | `2048` | Uploads per person per 24 hours. |
| `ATTACHMENT_S3_ENDPOINT`, `_REGION` (`us-east-1`), `_BUCKET`, `_PREFIX` (`attachments/`), `_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY`, `_FORCE_PATH_STYLE` (`true`) | | Required with `ATTACHMENT_STORAGE=s3`. Use a bucket and key of their own, not the backup ones: this key needs read, write, list and delete. |

**Managed Postgres (Supabase, …).** Database storage is the expensive part of those plans and every download is egress
through the API. On Supabase Free (500 MB) set `ATTACHMENT_INSTANCE_QUOTA_MB=200` or `ATTACHMENTS_ENABLED=false`; on Pro
with real use, store files in Supabase Storage's S3 endpoint:

    ATTACHMENT_STORAGE=s3
    ATTACHMENT_S3_ENDPOINT=https://<project-ref>.supabase.co/storage/v1/s3
    ATTACHMENT_S3_REGION=<project region, e.g. eu-central-1>
    ATTACHMENT_S3_BUCKET=vault-files
    ATTACHMENT_S3_ACCESS_KEY_ID=…
    ATTACHMENT_S3_SECRET_ACCESS_KEY=…
    ATTACHMENT_S3_FORCE_PATH_STYLE=true

**With S3 storage, back the bucket up yourself** (object versioning with a lifecycle rule, or replication to another
bucket): the database backup then leaves the chunk data out (`--exclude-table-data`). To move existing files from the
database to the bucket after switching, run (safe to stop and run again):

    docker compose exec clane-vault node dist/src/scripts/attachments-move.js --to s3

Until every file is moved, backups keep including chunk data. See `docs/attachments.md` for the details.

## Backups

The database holds only ciphertext (the server never sees your master passwords or vault keys), but losing it loses everything, so back it up. **Back up `.env` separately (in your secrets manager), not just the database.** `SERVER_SECRET` encrypts every user's 2FA secret: if it is lost or changed, nobody can sign in with their authenticator code again. Changing `JWT_SECRET` only signs everyone out.

From 1.6.1 the server checks `SERVER_SECRET` at startup and refuses to start if it differs from the one the database was set up with, logging `server_secret_mismatch` with what to do. Put back the original `SERVER_SECRET` from your saved `.env`. If it is lost for good, start once with `ACCEPT_NEW_SERVER_SECRET=true`, then remove it: every account that set up an authenticator then needs **Admin → People → Reset 2FA** (owners: **Server → Accounts**, or `reset-2fa.js` above), and email and SSO secrets must be entered again. Vault data is not affected (it is encrypted with each person's master password). When some accounts' authenticators were set up under an older secret, the server still starts and logs how many can't sign in.

### Scheduled backups (built in)

The app can back itself up on a schedule. Each run dumps **only the app's schema** (`?schema=` in `DATABASE_URL`, default `public`) with `pg_dump --format=custom`, encrypts it with [age](https://age-encryption.org) to your public key **before it leaves the container**, uploads it to S3-compatible storage and/or a mounted folder, and then deletes this schema's backups older than `BACKUP_RETENTION_DAYS`. It runs as the app's own database role, so a role that only owns its schema (Supabase, shared Postgres) is enough. Admins see the status, run history and a **Back up now** button under **Admin → Backups**; every admin gets a banner if the last backup failed or the last good one is more than 26 hours old.

1. **Make an age key pair** on a trusted machine. Keep the private key (identity file) offline or in your secrets manager, never next to the backups or on the vault server:

        docker compose run --rm --no-deps clane-vault node dist/src/scripts/age-keygen.js > backup-key.txt
        # or, with age installed: age-keygen -o backup-key.txt

   The public key (`age1…`) is printed and is also on the `# public key:` line of the file.

2. **Set the backup variables** in `.env` and run `docker compose up -d`:

   | Variable | Default | |
   |---|---|---|
   | `BACKUP_ENABLED` | `false` | `true` turns scheduled backups on. The app refuses to start if it is on without a recipient and a destination. |
   | `BACKUP_AGE_RECIPIENT` | | age public key (`age1…`). Required: backups are never written unencrypted. |
   | `BACKUP_SCHEDULE` | `30 2 * * *` | 5-field cron, **UTC**. |
   | `BACKUP_RETENTION_DAYS` | `14` | Older backups of this schema are deleted after each successful run. Other files in the bucket or folder are never touched. |
   | `BACKUP_S3_BUCKET` | | Bucket name; setting it enables the S3 destination. |
   | `BACKUP_S3_ENDPOINT` | | S3 API URL. Leave empty for AWS S3. |
   | `BACKUP_S3_REGION` | `us-east-1` | |
   | `BACKUP_S3_PREFIX` | `clane-vault/` | Key prefix ("folder") inside the bucket. |
   | `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY` | | Credentials. The key needs list, read, write and delete on the prefix. |
   | `BACKUP_S3_FORCE_PATH_STYLE` | `true` | Path-style URLs (needed by MinIO and Supabase). |
   | `BACKUP_LOCAL_DIR` | | A folder inside the container, e.g. `/backups` (mount a volume there, see below). |

   Objects are named `clane-vault-<schema>-<yyyyMMdd-HHmmss>.dump.age` (UTC). Use storage in a different account or provider from the database if you can, and turn on object versioning or object lock there so a compromised server can't erase the history.

   **Supabase Storage** (Storage → S3 Connection: enable it, create an access key, and create a private bucket):

        BACKUP_S3_ENDPOINT=https://<project-ref>.supabase.co/storage/v1/s3
        BACKUP_S3_REGION=<project region, e.g. eu-central-1>
        BACKUP_S3_BUCKET=vault-backups
        BACKUP_S3_FORCE_PATH_STYLE=true

   **Cloudflare R2** (R2 → Manage API tokens, Object Read & Write on the bucket):

        BACKUP_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
        BACKUP_S3_REGION=auto
        BACKUP_S3_BUCKET=vault-backups

   **MinIO** (or any other S3-compatible server):

        BACKUP_S3_ENDPOINT=https://minio.internal:9000
        BACKUP_S3_BUCKET=vault-backups
        BACKUP_S3_FORCE_PATH_STYLE=true

   **Local folder**: add a `docker-compose.override.yml` next to `docker-compose.yml` (the container runs as uid 1000, which must be able to write there), set `BACKUP_LOCAL_DIR=/backups`, and copy the folder off the host regularly:

        services:
          clane-vault:
            volumes: ["/srv/clane-vault-backups:/backups"]

3. **Check it**: open **Admin → Backups** and press **Back up now**. The container log has one JSON line per run step (`backup.start`, then `backup.success` with duration, size and object name, or `backup.failure` with the error); credentials and keys are never logged. Only one backup runs at a time, even with several containers on the same database (a Postgres advisory lock).

The image ships `pg_dump` 17, which can back up Postgres 14 to 17.

### Restore

Restores go into an **empty schema** (the restore refuses a schema that already has tables unless you add `--force`), so you can restore next to the live data and switch over when you are happy:

    docker compose exec clane-vault node dist/src/scripts/restore.js --list
    docker compose exec -T clane-vault node dist/src/scripts/restore.js \
        --from clane-vault/clane-vault-public-20261006-023000.dump.age \
        --identity - --target-schema vault_restored < backup-key.txt

`--identity -` reads the private key from standard input (`-T` passes it through), so it is never written inside the container. A key file inside the container (`--identity /path/to/key`) also works. The image has no shell, so commands inside it are `node …` scripts: there is no `sh`, `rm` or `cat`.

`--from` is an S3 object key (or bare object name) in the configured bucket, or a file path inside the container (e.g. under `BACKUP_LOCAL_DIR`). `--target-schema` defaults to the schema in `DATABASE_URL`, which suits a fresh, empty database. The database role needs permission to create the target schema (or create it, empty, beforehand). Then:

1. Point `DATABASE_URL` at the restored schema (`?schema=vault_restored`), or rename schemas in Postgres.
2. Use the **same `.env`** as when the backup was taken: without the same `SERVER_SECRET` nobody can use their 2FA codes.
3. `docker compose up -d`. Any newer migrations run on start. Sign in and open a few records to check.

Test a restore into a scratch schema now and then; a backup you have never restored is a hope, not a backup. With file
attachments in the database, the dump and the restore grow with the files stored (every chunk streams through age and
psql): time your own drill and note how long it takes per GB. With `ATTACHMENT_STORAGE=s3` restore the bucket from its
versioning or replica as well: the database dump has the files' metadata, the bucket their content.

### Manual backups

Without the built-in schedule, `pg_dump` works too (remove `schema=`, `connection_limit=` and other Prisma parameters from the URL and pass `--schema=<schema>`):

    pg_dump "postgresql://user:password@host:5432/db" --schema=public | gzip > clane-vault-$(date +%F).sql.gz

For the bundled database: `docker compose exec -T postgres pg_dump -U vault vault | gzip > backup.sql.gz`. Keep copies off the host, encrypted, and test restores.

## Updates

    ./update.sh 0.2.0        # or .\update.ps1 0.2.0

This sets `CLANE_VAULT_VERSION`, pulls the image and restarts. Database migrations run automatically on start. Take a backup first.

## Security notes

- Never commit or share `.env`; it holds the signing secrets.
- Keep `HTTP_BIND=127.0.0.1` unless the proxy runs on another host and the network path is private.
- Restrict access to the registry token; Clane can revoke and reissue it.
- Restrict network access to Postgres to the container host.
- The database contains encrypted data only, but treat dumps as sensitive.
- Email (invites, sign-up codes, security notices): set it up in the app under **Settings → Email** (instance admins; Resend or any SMTP server, with a "Send test email" button), or with `RESEND_API_KEY` and `EMAIL_FROM` in `.env` (used when the app has no settings). Organisation admins can give their organisation its own email settings. Passwords and API keys are encrypted with a key derived from `SERVER_SECRET` and never shown again; changing `SERVER_SECRET` means entering them again. Without any email, admins copy invite links and nobody is emailed. Details: `docs/email.md`.
- Single sign-on (OpenID Connect, e.g. Microsoft Entra ID or Google Workspace): organisation owners and admins set it up under **Settings → Single sign-on** (redirect URI `https://<your host>/api/v1/auth/sso/callback`, so `PUBLIC_URL` must be the public address). People still unlock with their master password after SSO: the identity provider never gets vault keys. Verify your email domain with the DNS TXT record the app shows before using "Require SSO" or auto-join. The issuer must use https. Setup guides: `docs/sso.md`.
- Master-password recovery (full details: `docs/recovery.md` in the source repository):
  - **Recovery kit**: every user saves a one-time recovery code after sign-up (and can regenerate it in Settings → Security). With the code *and* their authenticator they can set a new master password without losing their vault. The server stores only a wrapped key and a hash; it can't use the kit. A used kit is replaced straight away.
  - **Admin account recovery** is **off by default**. When an admin turns it on (Settings → Organisation), every member's vault key is also sealed to each admin as members unlock, so **admins can reset any member's master password and read their private records**. Members are told on sign-up and in Settings. Approving a reset needs the admin's fresh 2FA code; the member finishes it with a one-time link (24 hours, single use) plus their own 2FA, and the admin never sees the new password. Turning it off deletes every escrowed key.
  - Turning admin recovery on needs the admin's master password and a fresh 2FA code; members are emailed and must confirm an in-app notice before their key is escrowed.
  - Recovery keeps 2FA, and 2FA codes are single-use. If someone lost their authenticator too, an admin resets 2FA first (an organisation owner's: an instance admin in **Server → Accounts**, or the `reset-2fa.js` command; verify who you're talking to out-of-band before you do); the member then sets up a new authenticator during recovery. With admin recovery, a *different* admin who has been an admin for at least `ADMIN_RECOVERY_APPROVER_MIN_AGE_DAYS` (default 7) before the reset must approve, and the link waits `ADMIN_RECOVERY_RESET_DELAY_HOURS` (default 24) after the reset. Members are emailed when their 2FA is reset; admins are emailed when a new admin appears.
  - Recovery never changes a user's vault key: turning admin recovery off deletes the escrows but can't undo keys an admin already opened.
  - Recovery events (`auth.recovery_kit_used`, `auth.admin_recovery_used`, `recovery.*`, `admin.recovery_policy_*`) are in the event log.
