# Public demo mode

A Clane Vault server can run as a public demo, as at https://demo.vault.clane.si. A visitor clicks **Try the demo** on
the sign-in page and gets a private, throwaway sandbox: their own account and an organisation, "Northwind (demo)", with
made-up sample data. They are signed in without an authenticator, and the sandbox is deleted 2 hours after it was made.

Sandboxes never see each other. People do paste real passwords into demos, so each sandbox is a separate organisation
with a separate account, and the usual access checks apply to every request.

## Running a demo instance

Use a server and database of their own for the demo, never your real ones. The server refuses to start in demo mode
when the database holds any account that isn't a demo account, the bootstrap or instance admin included, so a production
instance can't be switched to demo mode by mistake.

1. Install as usual (`deploy/client/README.md`) with a new, empty database. Don't run the bootstrap step: a demo instance
   has no admin.
2. In `.env`, set:

   ```
   DEMO_MODE=true
   # Optional:
   DEMO_TTL_MINUTES=120
   DEMO_SANDBOXES_PER_IP_PER_HOUR=5
   ```

3. Behind a reverse proxy, set `TRUST_PROXY` (`deploy/client/README.md`, "Reverse proxies and `TRUST_PROXY`"). The
   sandbox limit counts per client address, and without it every visitor shares the proxy's.
4. Start it. The log says `demo_mode` with a warning, and the sign-in page shows **Try the demo**.

| Setting | Default | What it does |
|---|---|---|
| `DEMO_MODE` | `false` | `true` turns demo mode on. Can't be combined with `HOSTED_MODE=true`. |
| `DEMO_TTL_MINUTES` | `120` | How long a sandbox lasts, from when it was made (5 minutes to 7 days). |
| `DEMO_SANDBOXES_PER_IP_PER_HOUR` | `5` | New sandboxes per client address per hour. More get `429 rate_limited`. |

## What a visitor gets

- Everything secret is made in the browser, as in a normal sign-up: a random master password (never shown; kept in the
  tab's session storage so a reload can unlock the vault again), the KDF salt, the key pairs and the encrypted vault.
  The account is created through the normal invite and sign-up endpoints.
- The sample data is added by the browser, encrypted like anything a person adds: four shared folders (Infrastructure,
  Finance, Office, Clients) with records of every type, custom fields, a fake SSH key, a PDF attached to the production
  server, a few items in the Personal space, and two made-up colleagues so the sharing and People screens aren't empty.
  The colleagues have key pairs made in the browser and can never sign in. The data is the same as the flyer
  screenshots' (`apps/web/src/features/demo/northwind.ts`).
- A strip at the top of the app: "Demo sandbox. Deleted at HH:MM. Don't enter real passwords.", with a link to the source
  code.

## What is off or limited

| | In demo mode |
|---|---|
| Authenticator (TOTP) | Skipped for demo accounts only. The server checks both that the instance is in demo mode and that the account is a demo account; a real account never skips it. |
| Email | Never sent. Invites show their link to copy instead. Email settings can be read, not changed or tested. |
| Single sign-on | Off: the settings can't be changed and the sign-in endpoints answer `403 demo_mode`. |
| Backups and server settings | Not reachable (`403 demo_mode`). Demo accounts are never instance admins. |
| New organisations | Off. Invitations to an account in another sandbox are dropped, and joining another sandbox is refused. |
| Recovery | Recovery kits and admin recovery requests are refused (`403 demo_mode`): there is no master password to recover. No recovery-kit prompt is shown. |
| File attachments | At most 5 MB per file and 20 MB per sandbox (lower `ATTACHMENT_*` values still apply). |
| Breach check | Off unless the visitor turns it on (as everywhere). |
| One-time links | Work as usual, until the sandbox is deleted. |

## Expiry and clean-up

At its expiry time a sandbox stops working at once: its sessions, refreshes and sign-ins are refused. Every minute the
API deletes expired sandboxes, one transaction per sandbox: the organisation and its accounts, with their records,
attachments (S3 objects through the attachment sweep), one-time links, folders, events, sessions, keys and invites.
Only rows marked as demo (`demoExpiresAt` on `User` and `Organization`) are ever deleted.

## API

| Endpoint | |
|---|---|
| `GET /api/v1/brand` | `demo: { ttlMinutes }` on a demo instance, `null` otherwise. |
| `POST /api/v1/auth/demo` | Makes a sandbox organisation and a one-time owner invite: `{ inviteToken, email, expiresAt }`. Limited per client address. |
| `POST /api/v1/auth/register` | The normal sign-up, with that invite. |
| `POST /api/v1/auth/demo/session` | With the setup token from the sign-up: signs the demo account in without an authenticator and adds up to 3 made-up colleagues (`{ colleagues: [{ name, material }] }`). |

Both demo endpoints answer 404 when `DEMO_MODE` isn't `true`.

## Testing

`npm test` covers the API side (`apps/api/test/demo.test.ts`). The browser test runs on a stack of its own (a new Postgres
container and free ports, so it never touches a dev database or dev servers):

```
npm run demo -w e2e
```
