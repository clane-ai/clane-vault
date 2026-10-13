# Email

Clane Vault sends plain-text email for invites, hosted-mode sign-up codes and security notices (a password reset was
requested, approved or used, 2FA was reset, admin recovery was turned on or ended, a new admin). Nothing in an email is
secret: links in invites are one-time tokens, and vault data never leaves the browser unencrypted.

## Where the settings come from

| Email | Uses |
|---|---|
| Invites and invitations to an organisation | That organisation's own settings, if it has them; otherwise the server's |
| Every security notice: sign-up codes (`HOSTED_MODE`), password reset requested / approved / used, escrow opened, admin recovery turned on or ended, 2FA reset, new admin, single sign-on settings changed | The server's settings, always (an organisation's admins can't read or drop them through their own mail server) |

"The server's settings" are, in order:

1. **Settings → Email** in the app (instance admins), stored in the database.
2. The environment: `RESEND_API_KEY` and `EMAIL_FROM` (both needed). Existing installs keep working unchanged.
3. Nothing: no email is sent. Self-hosted admins copy invite links from People; `HOSTED_MODE` refuses invites
   (`email_required`) until some email is set up (an organisation's own settings count for its invites).

## Settings in the app

- **Settings → Email** (under "Server", instance admins only): the server-wide settings.
- **Organisation settings → Email for this organisation** (the organisation's owners and admins): an optional override for that
  organisation's invites and notices, e.g. to send from the company's own domain. "Use the server's settings" removes it.

Each has:

| Field | Notes |
|---|---|
| Provider | **Resend** (HTTP API), **SMTP server** (any relay: Google Workspace, Postmark, SES, Mailgun, your own) or **Microsoft 365** (Microsoft Graph; see below) |
| From name, from address | The sender. With Resend the address's domain must be verified in Resend. With Microsoft 365 the from address is the **sender mailbox** the app sends as. |
| Resend API key | Write-only. Shown as "Set (ends in abcd)". |
| SMTP host, port, security | Security: **STARTTLS** (usually port 587), **TLS** (implicit TLS, usually 465) or **None** (plain, only for a relay on a trusted network, usually 25). |
| SMTP username, password | Optional (relays that allow by IP need none). The password is write-only and shown only as "Set". |
| Microsoft 365 directory (tenant) ID, application (client) ID, client secret | From the app registration in Microsoft Entra. The secret is write-only, shown as "Set (ends in abcd)". |
| Microsoft 365 connection | **Sign in with Microsoft (delegated)** or **App-only (client credentials)**; see below. With delegated sign-in the sender mailbox is optional (empty: the signed-in account). |

**Send test email** sends a message to your own address with the saved settings and shows the result: "Test email sent
to …", or a short reason such as "The SMTP server rejected the username or password (server said 535)", "Couldn't
connect to smtp.example.com:587: connection refused", "No answer from … within 10 s", or "Resend refused the email: the
API key was rejected". Error messages never contain the password or API key. Every connection, TLS handshake and
request is limited to 10 seconds.

## Microsoft 365 (Graph)

Microsoft has retired basic authentication (a username and password) for SMTP AUTH in Exchange Online: signing in to
`smtp.office365.com` with a password fails, typically with `535 5.7.139 Authentication unsuccessful, basic
authentication is disabled`. Organisations on Microsoft 365 choose the **Microsoft 365** provider instead: the server
signs in as an Entra app registration (OAuth 2.0 client credentials) and sends with Microsoft Graph
(`POST /users/{sender}/sendMail`). This needs only an app registration with admin consent; no SMTP AUTH, no Exchange
service principal registration, no user password.

### Set up in Microsoft Entra

1. Sign in to the Microsoft Entra admin center (<https://entra.microsoft.com>) as a Global Administrator, Application
   Administrator or Cloud Application Administrator (granting consent for Mail.Send needs a Global Administrator or
   Privileged Role Administrator).
2. **Identity → Applications → App registrations → New registration.** Name: e.g. `Clane Vault mail`. Supported
   account types: **Accounts in this organizational directory only (single tenant)**. Redirect URI: leave empty.
   **Register**.
3. On the app's **Overview**, copy the **Application (client) ID** and the **Directory (tenant) ID**.
4. **Certificates & secrets → Client secrets → New client secret.** Description `Clane Vault`, choose an expiry
   (e.g. 24 months) → **Add**. Copy the **Value** right away (it is shown once). Not the "Secret ID".
5. **API permissions → Add a permission → Microsoft Graph → Application permissions** → search `Mail.Send` → tick
   **Mail.Send** → **Add permissions**. Then **Grant admin consent for <your organisation>** → **Yes**. The status
   column must show "Granted".
6. In Clane Vault, **Settings → Email** (server) or **Organisation settings → Email for this organisation**: Provider
   **Microsoft 365**, Sender mailbox (e.g. `vault@yourdomain.com`, an existing user or shared mailbox in Exchange
   Online), From name, Directory (tenant) ID (the GUID, or a verified domain such as `contoso.onmicrosoft.com`),
   Application (client) ID, Client secret → **Save** → **Send test email**.

**Recommended: restrict the app to the sender mailbox.** The `Mail.Send` application permission allows sending as any
mailbox in the tenant. Limit it to the one mailbox with an Exchange Online Application Access Policy (Exchange Online
PowerShell, `Connect-ExchangeOnline` as an Exchange administrator):

```powershell
# A mail-enabled security group that contains only the sender mailbox
New-DistributionGroup -Name "Vault senders" -Alias vault-senders -Type Security -Members vault@yourdomain.com
New-ApplicationAccessPolicy -AppId <clientId> -PolicyScopeGroupId vault-senders@yourdomain.com -AccessRight RestrictAccess -Description "Clane Vault mail: only vault@yourdomain.com"
Test-ApplicationAccessPolicy -Identity vault@yourdomain.com -AppId <clientId>       # AccessCheckResult: Granted
Test-ApplicationAccessPolicy -Identity someone.else@yourdomain.com -AppId <clientId> # AccessCheckResult: Denied
```

Policy changes can take up to an hour to apply. Microsoft's newer replacement for Application Access Policies is
**RBAC for Applications** in Exchange Online (`New-ServicePrincipal`, `New-ManagementScope`,
`New-ManagementRoleAssignment -Role "Application Mail.Send"`); either works with Clane Vault, which only calls
`sendMail` for the configured sender.

When the client secret nears its expiry, create a new one (step 4) and enter it in the same settings.

### How it works

- The server gets a token from `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (client credentials,
  scope `https://graph.microsoft.com/.default`) and keeps it in memory for that settings row until about 5 minutes
  before it expires; any change to the settings drops it. A token Microsoft stops accepting early is replaced once.
- Each email is `POST https://graph.microsoft.com/v1.0/users/{sender}/sendMail` with a plain-text body, the recipient,
  the from name, and `saveToSentItems: false` (the sender's Sent Items doesn't fill up with invites).
- Only these two hosts are ever called; they are fixed in the code, not settings, so there is nothing to point
  elsewhere (no SSRF, same rules with `HOSTED_MODE`). The tenant must be a GUID or a domain name and is URL-encoded,
  as is the sender. Every request is limited to 10 seconds.
- Global Azure only: national clouds (Microsoft 365 GCC High / DoD, operated by 21Vianet in China) use other hosts
  and aren't supported.
- The client secret is stored and protected like the other secrets (below). A stored secret is kept only while the
  tenant and client ID stay the same. Tokens and secrets are never logged or returned.
- Works for both scopes, and as the server's transport for security notices, exactly like Resend and SMTP.

### Troubleshooting Microsoft 365

| Test result | What to check |
|---|---|
| rejected the client secret (AADSTS7000215) | Copy the secret's **Value**, not its Secret ID; or the secret was deleted. |
| client secret has expired (AADSTS7000222) | Create a new client secret and enter it. |
| application (client) ID wasn't found in this tenant (AADSTS700016) | The client ID is wrong, or the app is registered in another tenant than the tenant ID given. |
| can't find that tenant (AADSTS90002) | The tenant ID or domain is wrong (use the Directory (tenant) ID from the app's Overview). |
| denied sending as … (ErrorAccessDenied) | Mail.Send must be an **Application** permission (not Delegated) with **admin consent granted**; an Application Access Policy or RBAC for Applications scope must include the sender mailbox (allow up to an hour after a change). Or switch Connection to **Sign in with Microsoft (delegated)**, which needs no application permission. |
| Graph didn't accept the app's token (HTTP 401) | As above: application permission and admin consent. |
| sender mailbox … wasn't found … (ErrorInvalidUser, ResourceNotFound, MailboxNotEnabledForRESTAPI) | The sender address must be an existing mailbox in Exchange Online in this tenant (a licensed user or a shared mailbox), spelled as its primary address or UPN. |
| may not send as … (ErrorSendAsDenied) | Use the mailbox's own address as the sender. |
| throttling (HTTP 429) | Microsoft is rate-limiting the app; try again later. |
| No answer from login.microsoftonline.com / graph.microsoft.com | Outbound HTTPS (443) from the server to those hosts (firewall, proxy). |

## Microsoft 365 — delegated sign-in

The Microsoft 365 provider has two **Connection** modes:

- **App-only (client credentials)**, described above: the app gets the `Mail.Send` *application* permission with
  admin consent and can send as any mailbox it is allowed to (narrow it with an Application Access Policy or RBAC for
  Applications).
- **Sign in with Microsoft (delegated)**: an admin signs in once with their Microsoft account and the server sends as
  that mailbox, or as a shared mailbox that account has **Send As** (or **Send on behalf**) rights on. No application
  permission and no tenant-wide access: the app can only ever do what the signed-in account may do.

The app registration is a **confidential Web client**: the client secret stays on the server and the code is redeemed
there. A "Single-page application" or "Mobile and desktop" (public client) platform doesn't work and isn't supported.

### Set up in Microsoft Entra (delegated)

The Redirect URI is shown (read-only, with a copy button) in the email settings once you choose **Sign in with
Microsoft (delegated)**. It is always:

```
<PUBLIC_URL>/api/v1/admin/email/m365/callback
```

for example `https://vault.example.com/api/v1/admin/email/m365/callback`, or with a path
`https://example.com/vault/api/v1/admin/email/m365/callback`. It is the same for the server's settings and every
organisation's.

1. Sign in to the Microsoft Entra admin center (<https://entra.microsoft.com>) as an Application Administrator or
   Cloud Application Administrator (or Global Administrator).
2. **Identity → Applications → App registrations → New registration.** Name: e.g. `Clane Vault mail`. Supported
   account types: **Accounts in this organizational directory only (single tenant)**. Redirect URI: leave empty for
   now. **Register**.
3. **Authentication → Add a platform → Web.** Redirect URIs: paste the Redirect URI from the email settings, exactly.
   Leave "Access tokens" and "ID tokens" (implicit grant) unticked. **Configure**.
4. **API permissions → Add a permission → Microsoft Graph → Delegated permissions** and tick:
   - `Mail.Send`
   - `Mail.Send.Shared` (only to send from a shared mailbox)
   - `offline_access`
   - `User.Read`, `openid`, `email`, `profile`

   → **Add permissions**.
5. Optional: **Grant admin consent for <your organisation>**. Needed when the tenant doesn't let users consent to apps
   (the sign-in then fails with AADSTS65001); otherwise the admin who signs in consents for themselves.
6. **Certificates & secrets → Client secrets → New client secret** → copy the **Value** (not the Secret ID). On
   **Overview**, copy the **Application (client) ID** and the **Directory (tenant) ID**.
7. In Clane Vault, **Server → Email** (or **Admin → Email** for an organisation): Provider **Microsoft 365**,
   Connection **Sign in with Microsoft (delegated)**, Directory (tenant) ID, Application (client) ID, Client secret,
   and optionally **Sender mailbox**:
   - empty: emails are sent as the account that signs in;
   - a shared mailbox (e.g. `it-notices@example.com`): the account that signs in needs **Send As** (or **Send on
     behalf**) on it in Exchange Online (Exchange admin center → Recipients → Mailboxes → the shared mailbox →
     Delegation), and the app needs `Mail.Send.Shared`.

   **Save**, then **Sign in with Microsoft**, sign in with the mailbox's account (or the account with Send As), accept
   the consent prompt, and you are back on the settings page: **Connected as you@example.com · Reconnect ·
   Disconnect**. Then **Send test email**.

### How delegated sign-in works

- **Sign in with Microsoft** creates a single-use request (random state, nonce and PKCE verifier; 10 minutes) for this
  scope and admin, bound to an httpOnly cookie, and sends the browser to
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` (authorization code flow, PKCE S256, scopes
  `openid email profile offline_access https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Send`,
  plus `https://graph.microsoft.com/Mail.Send.Shared` when a sender mailbox is set).
- The callback accepts only a live request from the same browser, claims it once, and checks that the admin who started
  it is still allowed to change those settings (instance admin, or owner/admin of that organisation) from a session that
  is still signed in, and that the tenant and client ID haven't changed meanwhile. It redeems the code server-side
  (client secret + PKCE verifier), checks the id_token (nonce, audience, tenant, expiry; received directly from the
  token endpoint over TLS) and asks Graph `GET /me` who signed in (the object ID must match the id_token's).
- The refresh token is stored sealed like the other secrets (AES-256-GCM under `SERVER_SECRET`, bound to the settings
  row) and is never returned, logged or shown. Only the account (UPN), when and by whom are shown.
- Access tokens are kept in memory until ~5 minutes before expiry. Each refresh returns a new refresh token, which
  replaces the stored one with a compare-and-swap on a version counter, so two servers refreshing at once never
  overwrite a newer token with an older one.
- Each email is `POST https://graph.microsoft.com/v1.0/me/sendMail`. For a shared mailbox the message's `from` is the
  shared mailbox (Microsoft's documented way to send from another mailbox with delegated tokens; Exchange sets the
  sender according to Send As or Send on behalf).
- Changing the tenant, client ID, provider or Connection mode drops the sign-in. **Disconnect** deletes the stored
  refresh token; it doesn't call Microsoft. To revoke the app's access at Microsoft too, remove it in My Apps
  (<https://myapps.microsoft.com>) or under Enterprise applications in Entra.
- Events: `email.m365_connected`, `email.m365_disconnected`, `email.m365_connect_failed` (with the error code),
  `email.m365_reconnect_needed`. Only `login.microsoftonline.com` and `graph.microsoft.com` are called.

**When the sign-in stops working.** Microsoft revokes refresh tokens when the account's password is reset, its
sessions are revoked, consent is removed, a Conditional Access or MFA policy demands a new sign-in, or the token goes
unused for 90 days. The server then marks the connection **needs reconnecting** (shown in the email settings with the
reason, and in the organisation's Risk dashboard: the "Organisation email is set up" benchmark turns critical and the
alert "Microsoft 365 email needs reconnecting" counts it), logs `email.m365_reconnect_needed` once, and emails the
people who can fix it (instance admins for the server's settings; the organisation's owners and admins for an
organisation's) through a path that isn't Microsoft 365: the server's settings if they aren't Microsoft 365, else
`RESEND_API_KEY`. Until someone chooses **Reconnect**, emails use the next settings available (the server's, then the
environment's). Regular email keeps the token alive; on a server that sends very little, check the settings page now
and then.

### Troubleshooting delegated sign-in

| Message | What to check |
|---|---|
| The redirect URI isn't registered (AADSTS50011, often shown on Microsoft's page) | Authentication → **Web** platform → add the exact Redirect URI shown in the settings (scheme, host, path, no trailing slash). `PUBLIC_URL` must be the address people use. |
| Registered as a single-page application (AADSTS9002327) | Remove the URI from "Single-page application" and add it under **Web**. |
| Your organisation requires an administrator to approve (AADSTS65001) | API permissions → **Grant admin consent**, then sign in again. |
| The sign-in was cancelled or consent was declined (access_denied) | Sign in again and accept; or have an admin grant consent. |
| Application (client) ID wasn't found (AADSTS700016) | Client ID or tenant ID wrong, or the app is in another tenant. |
| Microsoft rejected the client secret (AADSTS7000215) / expired (AADSTS7000222) | Copy the secret's **Value**; create a new secret when it expires (the sign-in stays, only the secret is replaced). |
| Microsoft didn't grant offline access / Mail.Send | Add `offline_access` and `Mail.Send` (delegated) to API permissions and sign in again. |
| Sending from a shared mailbox needs Mail.Send.Shared | Add `Mail.Send.Shared` (delegated), grant consent if required, **Reconnect**. |
| <user> has no Send As permission on <mailbox> (ErrorSendAsDenied) | Exchange admin center → the shared mailbox → Delegation → **Send as** (or Send on behalf) → add the signed-in user; allow up to an hour. |
| Microsoft 365 sign-in needs reconnecting | Password reset, revoked sessions, consent removed or 90 days unused: **Reconnect**. |
| This sign-in expired or was started in another browser | Start again from the settings page in the same browser; finish within 10 minutes. |

## How secrets are protected

- Secrets (Resend API keys, SMTP passwords, Microsoft 365 client secrets and delegated refresh tokens) are encrypted with AES-256-GCM under a key derived from `SERVER_SECRET`
  (HKDF-SHA256). The additional authenticated data binds each ciphertext to its settings row, so a value copied into
  another row doesn't decrypt.
- The API never returns a secret, only whether one is set (and the last four characters of an API key). Saving without
  typing a new one keeps the stored one; switching provider or SMTP username drops it.
- Changing `SERVER_SECRET` makes stored secrets unreadable: the app then sends with the next source (the environment, or
  nothing) and the test email says to enter the secret again.
- Every change is in the event log (`email.settings_updated` with the fields that changed, `email.settings_removed`,
  `email.test` with success or failure), never with values of secrets.
- A stored SMTP password is only kept while the host, port, security mode and username stay the same; pointing the
  settings at another server needs the password typed again.
- `HOSTED_MODE`: an organisation's SMTP server must be on a public address (resolved once and connected to by IP, with
  TLS checked against the host name, so DNS rebinding can't redirect it) and on port 25, 465, 587 or 2525; no SMTP
  password is ever sent over security "None" (any scope). Instance admins may use internal relays.
- Test-email errors are short and generic: they never repeat the server's or the system's raw message.

## Troubleshooting

| Test result | What to check |
|---|---|
| rejected the username or password | The account's password and that SMTP AUTH is allowed. With `smtp.office365.com` password sign-in no longer works at all (`535 5.7.139`): use the **Microsoft 365** provider. |
| connection refused / no answer | Host, port and firewall egress from the server. |
| TLS failed | Port and security mismatch (STARTTLS on 465 or TLS on 587). |
| refused the sender or recipient | The from address must be one the account may send as. |
| Resend: from address or recipient was refused | Verify the sending domain in Resend. |
