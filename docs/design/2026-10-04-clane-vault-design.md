# Clane Vault — design

Date: 2026-10-04 · Status: draft for review

## 1. Purpose

A web-based, zero-knowledge password manager for the Clane team: a few hundred
shared and private logins, shared with teammates through team folders or one
record at a time, and occasionally sent to customers as one-time links. It
should feel as simple as Keeper. It is internal first; it may become a product,
so all code is ours (no GPL dependencies in the server or the app).

**Success looks like:** the team moves its passwords out of Keeper into Clane
Vault, finds and copies any password in a few seconds, and shares one without
asking how.

### Decisions already made

| Decision | Choice |
|---|---|
| Build or adopt | Build from zero (own server and app). Vaultwarden dropped. |
| Platform | Web app only. No browser extension, no autofill, no desktop/mobile apps (phase 2 at the earliest). |
| Look | Clane Design System, constellation logo mark. Layout from mockup v2 (Keeper-style). |
| Hosting | Docker Compose. Local first, then a server behind Nginx Proxy Manager at `vault.example.com`. |
| Email | Resend (invites, verification, new-device notices). |
| Customers | One-time links only. No customer accounts in v1. |
| Key service (KMS) | None in v1; server secrets in a locked-down `.env`. |

## 2. Scope of v1

In:
- Sign up by invite, sign in with master password + authenticator-app 2FA (required), auto-lock after idle.
- Vault: folder tree in the main list, flat list, search, sort, Show filter, slide-in record panel.
- Record types: Login (title, username, password, website, 2FA secret, notes), Secure note.
- Password generator and strength meter.
- Private folders and team folders (name, members, permission per member).
- Share one record with one person directly.
- Permissions: Can view, Can edit, Use only (copy without seeing; UI-level, see §5.6), Owner.
- One-time links with expiry, max opens, optional password, revoke; public "open link" page.
- Needs attention: weak and reused passwords (computed in the browser).
- Activity per record and an admin activity log.
- Trash with 30-day restore.
- Import from Keeper export (JSON/CSV) and generic CSV (Bitwarden, Chrome/Edge).
- Admin: invite and remove people, see who is pending, reset a member's 2FA.
- Light and dark theme, phone layout.

Out of v1: SSO, browser extension, mobile apps, customer accounts, breach
checks against external services, file attachments, account recovery for a
forgotten master password (see §5.7), multiple organisations.

## 3. Architecture

```
Browser (React app) ── all encryption and decryption happens here
      │ HTTPS (vault.example.com, TLS at Nginx Proxy Manager)
┌─────▼──────────────────────────── docker compose ───────────────────┐
│  web   : Caddy serving the built app + /api reverse proxy             │
│  api   : Node 22 + Fastify (TypeScript), stores only ciphertext        │
│  db    : Postgres 16 (internal network only)                         │
│  backup: nightly pg_dump → age-encrypted file, 14 daily + 8 weekly    │
└──────────────────────────────────────────────────────────────────────┘
      │ outbound: Resend API (email)
```

Stack is TypeScript end to end, matching Clane Analytics:

| Part | Choice |
|---|---|
| App | React 19, Vite, TypeScript (static single-page app, no server rendering), React Router, TanStack Query. |
| Styling | Tailwind CSS 4 with the Clane Design System tokens mapped into `@theme` (light and dark). |
| Components | shadcn/ui (Radix based), restyled to the Clane look; Lucide icons. Next.js was considered and rejected: server rendering cannot be used with zero-knowledge data, and static output keeps the CSP strict and the attack surface small. |
| Crypto | Web Crypto API (AES-256-GCM, HKDF-SHA256, X25519) + `hash-wasm` (Argon2id, MIT). Shared package `@clane-vault/crypto`, used by app and tests. |
| API | Fastify, Zod validation, Prisma ORM, Postgres 16. |
| Auth | Argon2id-hashed auth key, TOTP (`otplib`), short-lived access token + httpOnly refresh cookie. |
| Tests | Vitest (crypto, app units), Vitest + Testcontainers Postgres (API), Playwright (end to end). |

Repository layout:

```
clane-keeper/
  packages/crypto/     key derivation, wrap/unwrap, record and link encryption + known-answer tests
  apps/api/            Fastify server, Prisma schema and migrations
  apps/web/            React app, design-system port, Clane logo assets
  deploy/              docker-compose.yml, Caddyfile, backup job, .env.example
  docs/                specs, plans, operations runbook
```

## 4. Look and feel

- Tokens copied from the design system (`tokens/colors.css`, `typography.css`,
  `spacing.css`); dark mode by token remap via `data-theme`.
- Type: Space Grotesk 600 for headings and the wordmark, IBM Plex Sans for UI,
  IBM Plex Mono for usernames, passwords, codes and metadata.
- Colour roles: navy ink base; blue `#3E7BFA` for selection and links; orange
  `#FF6A3D` scarce, for the one primary action per view and "needs attention";
  green / amber / red for strength and status.
- Borders over shadows, 14px card radius, hairlines `#E4EAF3`.
- Logo: `assets/logo-mark.svg` and `logo-mark-on-tile.svg`; wordmark "Clane"
  plus "Vault" in Space Grotesk.
- Layout (from mockup v2): collapsible sidebar (248px ↔ 64px rail) with
  + New menu, Vault, Shared with me, Needs attention, Share links, Trash;
  main list full width with folders as expandable rows; record panel slides in
  from the right on selection; Share replaces the record panel (People /
  One-time link tabs); status bar "End-to-end encrypted · Synced".
- Copy follows the design-system voice: sentence case, terse, no emoji.

## 5. Security design

### 5.1 Keys per user

1. `masterKey = Argon2id(masterPassword, salt, m=64 MiB, t=3, p=1)`, 32 bytes.
   The salt is random per user and stored on the server.
2. `authKey = HKDF(masterKey, "clane-vault/auth")` is sent to the server at
   sign-in; the server stores `Argon2id(authKey)` and never sees `masterKey`.
3. `wrapKey = HKDF(masterKey, "clane-vault/wrap")` never leaves the browser.
4. `userKey` (random 32 bytes, AES-256-GCM) is stored encrypted under `wrapKey`.
5. An X25519 key pair; the public key is stored in clear, the private key
   encrypted under `userKey`.

Changing the master password re-encrypts only `userKey` (step 4).

### 5.2 Records, folders and sharing

- Every record has its own random `recordKey`. The record body (all fields as
  JSON) is encrypted with AES-256-GCM under `recordKey`. Titles are encrypted too;
  the server sees only IDs, timestamps and folder membership.
- **Private record:** `recordKey` wrapped with the owner's `userKey`.
- **Team folder:** has a random `folderKey`, wrapped to each member's public key
  (X25519 + HKDF + AES-GCM sealed box). Records in it have `recordKey` wrapped
  with `folderKey`.
- **Direct share of one record:** `recordKey` sealed to the recipient's public
  key. On first open the recipient's app re-wraps it with their `userKey`.
- **Adding a member** (to a folder or a record) is done by a sharer's browser,
  because only it can unwrap the key. If the invitee has not finished sign-up
  yet, the share stays "pending" and is completed automatically the next time
  any owner of that folder or record opens the app.
- **Removing a member** deletes their wrapped key on the server immediately. For
  team folders the app offers "rotate folder key" (new `folderKey`, re-wrap all
  record keys), recommended after someone leaves the company, and the Needs
  attention view lists passwords that person could see so they can be changed.

### 5.3 One-time links

- The browser creates a random `linkKey`, encrypts a snapshot of the record
  fields under it, and uploads only the ciphertext with expiry and max opens.
- Link format: `https://vault.example.com/s/<id>#<linkKey>`. The fragment never
  reaches the server.
- Optional link password: the `linkKey` is additionally wrapped with a key
  derived from the password (Argon2id); the server checks an access hash before
  returning ciphertext.
- The server counts opens, refuses after expiry or the last open, and deletes
  the ciphertext then. The owner can revoke at any time.

### 5.4 Sign-in and sessions

- Sign-in: prelogin (returns salt and KDF parameters, constant response for
  unknown emails) → auth key + TOTP code → access token (15 min, memory only)
  + refresh token (httpOnly, Secure, SameSite=Strict cookie, 12 h, rotated).
- Rate limit per IP and per account; lock for 15 min after 10 failures; email
  the user on sign-in from a new browser.
- The app locks after 15 min idle (configurable): keys are dropped from memory
  and the master password is needed to unlock. Clipboard cleared 30 s after copy.

### 5.5 Server and web hardening

- Strict Content-Security-Policy (`script-src 'self'`, no third-party scripts),
  HSTS, `frame-ancestors 'none'`, no inline scripts.
- Server stores ciphertext, wrapped keys, public keys, salts, hashes and
  metadata only. Logs never contain request bodies.
- Every share, unshare, link, permission change, export and admin action is
  written to an append-only `events` table.

### 5.6 Known limits (stated in the app's help page)

- **Use only** hides the password in the app, but the browser holds the key, so
  a technical user could extract it. Same limit as Keeper. It is a convenience
  control, not a hard boundary.
- The server hands out public keys. A compromised server could substitute one
  during sharing. v1 shows each person's key fingerprint in their profile for
  manual check; automatic verification is a later item.
- No autofill means people copy and paste; clipboard clearing reduces exposure.

### 5.7 Forgotten master password

v1 has no recovery: private records of that user are lost; records in team
folders stay available through other members. The admin can remove the account
and re-invite. An opt-in "admin recovery" (user key escrowed to admins' public
keys) is a v1.1 item, to decide before inviting non-technical staff.

## 6. Data model (Postgres)

| Table | Key columns |
|---|---|
| `users` | id, email, name, role (admin/member), kdf_salt, kdf_params, auth_hash, wrapped_user_key, public_key, wrapped_private_key, totp_secret_enc, status (invited/active/disabled), created_at |
| `invites` | id, email, invited_by, token_hash, expires_at, accepted_at |
| `folders` | id, kind (private/team), owner_id, enc_name, created_at, deleted_at |
| `folder_members` | folder_id, user_id, permission, wrapped_folder_key (null while pending) |
| `records` | id, folder_id (nullable), owner_id, type, enc_body, revision, created_at, updated_at, deleted_at |
| `favourites` | user_id, record_id |
| `record_access` | record_id, holder_type (user/folder), holder_id, permission, wrapped_record_key, state (pending/active) |
| `share_links` | id, record_id, created_by, enc_payload, password_hash (nullable), expires_at, max_opens, opens, revoked_at, label_enc |
| `events` | id, at, actor_id, action, record_id/folder_id/target_user_id, ip, user_agent |
| `sessions` | id, user_id, refresh_hash, device_label, created_at, last_seen, revoked_at |

Search, sorting by name, weak/reused detection and "most used" ordering happen
in the browser after decryption (fine for thousands of records).

## 7. API outline (`/api/v1`)

- `auth`: `prelogin`, `register` (with invite token), `login`, `totp/setup`, `totp/verify`, `refresh`, `logout`, `password/change`
- `sync`: `GET /sync` returns everything the user can open (records, folders, wrapped keys, members' public keys) plus a revision number; `GET /sync?since=<rev>` for deltas
- `records`: create, update (with revision check, 409 on conflict), trash, restore, purge
- `folders`: create, rename, delete, members add/update/remove, rotate key
- `shares`: share record with user, update permission, remove; pending shares to complete
- `links`: create, list mine, revoke; public `GET /api/v1/public/links/:id` (+ password check)
- `users`: directory (name, email, public key, fingerprint) for the share picker
- `admin`: invite, resend, revoke invite, disable user, reset 2FA, events
- `import`: none server-side; import is parsed and encrypted in the browser, then uploaded in batches through `records`

## 8. Main flows

1. **First admin**: `docker compose up` → one-off `npm run bootstrap -- --email …` prints an invite link → admin signs up, sets master password, sets up 2FA.
2. **Invite**: admin enters email(s) → Resend sends link → teammate sets master password + 2FA → pending folder and record shares complete automatically next time an owner is online.
3. **Add and share**: + New → Login → save into a team folder (shared with the folder's members) or private folder → Share → People: add a person with a permission.
4. **Customer link**: record → Share → One-time link → expiry, opens, optional password → copy link → recipient opens `/s/<id>#key`, sees the fields with copy buttons, link burns per its limits.
5. **Move from Keeper**: Keeper → Settings → Export (JSON) → Clane Vault → + New → Import → preview mapped folders and records → import into chosen folders.

## 9. Error handling

- Network or server errors show a Clane toast with the action and a retry; edits
  are kept in the panel until saved.
- Edit conflict (two people edit one record): 409 → the app shows both
  versions side by side and lets the user keep one.
- Decryption failure on one record: that row shows "Can't open this record"
  with "Ask the owner to share it again"; the rest of the vault keeps working.
- Link expired, used up or revoked: the public page says which, without
  revealing the record.

## 10. Testing

- **Crypto package:** known-answer tests for Argon2id/HKDF/AES-GCM/X25519
  against published vectors; round-trip tests for every wrap path; negative
  tests (wrong key, tampered ciphertext, wrong AAD).
- **API:** integration tests against a real Postgres (Testcontainers):
  permissions per role and per share, revocation, link limits, rate limits,
  sync deltas, that the server never receives plaintext (assert on request bodies).
- **End to end (Playwright):** invite → sign up → 2FA → add record → share with a
  second user → second user sees it → remove → no longer visible; one-time link
  open once then dead; import a sample Keeper export; phone layout.
- **Visual check (existing agents in `~/.claude/agents`):** `web-test` captures
  the running app (and the mockup / design-system reference) in the dedicated
  Edge on CDP 9555; `screenshot-review` compares and writes `review.md`;
  `ui-fix` applies the findings in a worktree. `ui-fix` is written for the Clane
  Analytics repo, so the caller passes this repo's paths, token file and gates
  (or a project copy in `.claude/agents/` is added). `web-test` may create test
  users on our local app and reads verification emails from Mailpit
  (`http://localhost:8025`), so local Compose sends mail to Mailpit, not Resend.
- **Decisions confirmed 2026-10-04:** no master-password recovery in v1 (§5.7),
  "Use only" is a soft limit (§5.6).

## 11. Operations

- `deploy/docker-compose.yml` runs locally (`https://vault.localhost` via Caddy)
  and on the server (Nginx Proxy Manager forwards `vault.example.com` to the `web` container).
  The current Vaultwarden preview container is removed at cut-over.
- Backups: nightly encrypted `pg_dump` to `/backups` on the host, ready to copy
  to S3-compatible object storage; restore drill documented in `docs/operations.md`.
- Upgrades: `git pull && docker compose build && docker compose up -d`;
  Prisma migrations run on start.

## 12. Delivery phases

1. **Foundation:** repo, crypto package with tests, API auth + 2FA, private
   records, the vault UI shell with Clane design (list, panel, + New, generator).
2. **Teams:** invites and email, team folders, direct record sharing, pending
   shares, permissions, activity.
3. **Links and polish:** one-time links and public page, Needs attention, trash,
   Keeper/CSV import, phone layout, dark mode.
4. **Ship:** Docker Compose for the server, backups, Playwright suite, visual review,
   cut-over at `vault.example.com`.
