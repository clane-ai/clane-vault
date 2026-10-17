# Clane Vault

> **Security status: pre-audit, use for evaluation.** No external security audit has been done. Don't store
> production secrets in it or roll it out across a company until one has. See [SECURITY.md](SECURITY.md#status).

A team password manager you run on your own servers. Passwords, notes, fields and files are encrypted in the
browser before they're sent, so the server can't read them. Sign-in needs an authenticator code, or, for single
sign-on organisations that choose it, the provider's two-step check.

![The Clane Vault web app: shared folders with logins, a payment card, a bank account, API and SSH keys, a database,
a server with three attached files, a software licence and Wi-Fi networks](docs/images/vault.webp)

- Shared folders with Edit, View or Use only access per person or group, and a Personal space for each person.
- 14 record types, such as logins, payment cards, bank accounts, servers, databases, SSH and API keys, Wi-Fi,
  licences and identity documents, with custom fields. The record type is encrypted; the server sees only whether a
  record is a login or another item.
- Encrypted file attachments up to 100 MB each, with in-app preview for images, PDFs and text.
- One-time links for clients: a link opens once, and the key after `#` never reaches the server.
- Several organisations per account, each with its own keys.
- Bulk invites, groups, policies, single sign-on with Entra ID or Google (OpenID Connect), a risk dashboard, an event
  log and built-in encrypted backups.
- A web app, an installable app, and a browser extension for Chrome, Edge and Firefox.
- Import from Keeper, LastPass, 1Password, Bitwarden, Zoho Vault, Dashlane and CSV. Imports from Keeper, Bitwarden,
  1Password, LastPass and Dashlane keep record types.

Website: [vault.clane.ai](https://vault.clane.ai) · Made by Clane AI Labs, Ireland.

## How it runs

```
Users  →  HTTPS reverse proxy  →  Clane Vault (one container)  →  Postgres 14+
```

One image, `ghcr.io/clane-ai/clane-vault`. It runs at its own address or under a path such as
`https://intranet.example.com/vault`, and runs its database migrations on start. There is no telemetry and no
licence server. The only outbound call the app makes is the optional breached-password check: members who turn it on
send the first 5 characters of a password's SHA-1 hash to Have I Been Pwned, and an organisation policy can switch it
off.

```sh
# from deploy/client/
./install.sh            # Windows: .\install.ps1
docker compose exec clane-vault node dist/src/scripts/bootstrap.js --email you@example.com
```

The installer writes `.env` with random secrets, optionally starts a bundled Postgres, and waits for the health
check. The second command prints a one-time link for the first admin. The full guide, including reverse proxies,
backups, updates and attachment storage, is in [deploy/client/README.md](deploy/client/README.md).

## Security model

- The master password never leaves the device. It is stretched with Argon2id (64 MiB, 3 iterations) in the browser.
- Every item and every file has its own random key and is encrypted with AES-256-GCM.
- Keys are shared between browsers with X25519 sealed boxes, so the server relays keys it can't open. Public keys
  come from the server. Each browser pins the key it first shares to for each colleague and refuses to share to a
  changed key until someone compares the new fingerprint and accepts it. The first share to a colleague trusts what the
  server lists, so compare fingerprints out of band before sharing anything sensitive; see [docs/sharing.md](docs/sharing.md).
- An authenticator code is required at sign-in, unless an organisation trusts its Entra ID or Google two-step check.
  Ten failed attempts (password, authenticator code or recovery code) lock an account for 15 minutes.
- Each person gets a recovery kit. Admin recovery is off by default, needs two admins, and covers one organisation,
  never the personal vault.
- Stored in plain text: member names and emails, organisation and group names, record categories (login or item)
  and the event log.

**Pre-audit: use for evaluation.** No external security audit has been done yet. The designs are in [docs/design/](docs/design/), and
[docs/sharing.md](docs/sharing.md) describes what a compromised server could and couldn't do. To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Development

Requirements: Node.js 22 and Docker.

```sh
npm ci
docker compose -f deploy/docker-compose.dev.yml up -d   # Postgres on 127.0.0.1:5434
cp apps/api/.env.example apps/api/.env
npm run dev -w @clane-vault/api                          # API on :3001
npm run dev -w @clane-vault/web                          # web app on :5173
```

| Path | What it is |
|---|---|
| `packages/crypto` | Client-side encryption and key handling, shared by the web app and the extension |
| `apps/api` | Fastify API and Prisma schema |
| `apps/web` | React web app (also the installable app) |
| `apps/extension` | Browser extension (Manifest V3) |
| `e2e` | Playwright end-to-end tests |
| `deploy/client` | The install bundle for self-hosters |

Checks: `npm run typecheck`, `npm test` (the API tests start Postgres in Docker) and `npm run e2e`.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

[AGPL-3.0](LICENSE). You can use, study, change and self-host Clane Vault. If you run a changed version as a
service for others, you must offer them its source.
