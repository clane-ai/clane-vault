# Single sign-on (OpenID Connect)

An organisation can let its people sign in with its identity provider (Microsoft Entra ID, Google Workspace, Okta,
Keycloak, Auth0 or any OpenID Connect provider). Clane Vault stays zero-knowledge: the identity provider proves **who**
someone is, but the **master password** is still needed after SSO. It derives the keys that decrypt the vault in the
browser, and the server checks its auth key exactly as for a password sign-in. Nothing the identity provider sends can
open a vault.

## How a sign-in works

1. On the sign-in page the person types their email. If the address's domain is a **verified** domain of an
   organisation with SSO, the password step shows **Continue with &lt;organisation&gt; SSO**. ("Sign in with SSO" on
   the email step takes an organisation ID instead, for addresses outside verified domains.)
2. The browser goes to the identity provider: Authorization Code flow with PKCE (S256), a random `state` and `nonce`,
   scopes `openid email profile`, `login_hint` with the email. `state` is bound to an httpOnly cookie (`cv_sso`,
   SameSite=Lax) so a callback only works in the browser that started it; the request is single use and lives
   10 minutes.
3. The identity provider redirects to `${PUBLIC_URL}/api/v1/auth/sso/callback`. The server exchanges the code with the
   PKCE verifier and validates the id_token: `iss`, `aud`, `exp`, `nonce`, and its signature against the provider's
   JWKS (openid-client's non-repudiation checks are switched on; by default it would trust the token endpoint's TLS).
   It requires a verified email (below) in one of the organisation's SSO domains.
4. The account: the **identity link** (organisation + issuer + subject) made at the first SSO sign-in wins; without a
   link, the account with that email. Once an account is linked, a different identity-provider account with the same
   email is refused (`sso_identity_mismatch`), and a renamed identity-provider account keeps mapping to its original
   account: changing an email at the provider can't take over someone else's vault.
5. The server creates a short-lived **SSO proof** (single use, 5 minutes, bound to the same cookie; every try is
   counted atomically before the password is checked and the proof is burned after 5) and sends the browser to `/sso/complete#proof=…` (in the fragment, so it never reaches logs or
   `Referer` headers; the page removes it from the address bar).
6. The page asks for the **master password** (and the authenticator code, unless the organisation trusts the
   provider's MFA, below). The proof names the account and its KDF parameters, so a person whose address was renamed at
   the provider still derives the right key. Success creates a session that records it was established by this
   organisation's SSO. An account whose 2FA was reset sets up a new authenticator first; the identity link and any
   just-in-time join happen only after that.

New people can sign up through SSO when their address is in a **verified** domain and either the organisation has
**Auto-join verified domain users** on, or they have an open invite from that organisation. They choose a master
password, set up an authenticator (the account is global: password-only sign-ins still need it) and save their recovery
kit. No emailed sign-up code is needed: the identity provider verified the address. Auto-join and the domain's
verification are checked again when the sign-up or join actually happens (not only at the callback), and a domain's
TXT record is looked up again if it wasn't seen in the last 24 hours: a record that is gone un-verifies the domain
(event `sso.domain_unverified`, and "Require SSO" and auto-join switch off when no verified domain is left).

## Settings (Organisation settings → Single sign-on, owners and admins)

Setting SSO up, removing it, changing the issuer, "Require SSO" and "Trust the identity provider's MFA" are for the
**owner** only (`403 owner_only` for admins); admins manage domains, the client ID and secret, and auto-join. Every
change is emailed to the organisation's owners and admins with the server's own email settings (never the
organisation's), and logged.

| Setting | |
|---|---|
| Issuer URL | The provider's issuer; discovery reads `<issuer>/.well-known/openid-configuration`. Must be `https` (`SSO_ALLOW_HTTP_ISSUER=true` allows `http` for development only). |
| Client ID, client secret | From the app registration. The secret is encrypted at rest (AES-256-GCM, key derived from `SERVER_SECRET`, bound to the setting) and never shown again. |
| Redirect URI | Shown in the app: `${PUBLIC_URL}/api/v1/auth/sso/callback`. Register exactly this at the provider. |
| Organisation ID | For "Sign in with SSO" when someone's domain isn't verified. |
| Domains | Email domains SSO is for. **Verify** each with a DNS TXT record on the domain itself: `clane-vault-verify=<token>` (shown in the app). Public email providers (the list in `apps/api/src/lib/publicMailDomains.ts`: Gmail, Outlook/Hotmail/Live, Yahoo, iCloud, Proton, AOL, GMX, Yandex, Mail.ru, Zoho…) can't be added, and a domain verified by one organisation can't be verified by another (`domain_taken`). |
| Require SSO for members | Members whose address is in a verified domain can use this organisation (its team folders, shares, people) only from a session established by its SSO; anything else gets `403 sso_required` and the app offers "Sign in with &lt;organisation&gt; SSO". Their password sign-in keeps working for their private vault and other organisations. The **owner is exempt** (break-glass when the provider is down or misconfigured). |
| Trust the identity provider's MFA | After SSO, skip the authenticator code, only when: the address is in a verified domain; the account's **only** active membership is this organisation; it isn't a just-in-time join; and, when the provider sends an `amr` claim, it names a second factor (`mfa`, `otp`, `hwk`, `swk`, `fido` or `sms`). Such a session is confined to this organisation: other organisations, and the person's own private folders and records (left out of sync, shown as a locked "Private items" row; their routes answer `403 totp_step_up_required`), need the authenticator code once (`POST /auth/totp/step-up`; the app asks for it). Turn on only if the provider enforces MFA. |
| Auto-join verified domain users | People with an address in a verified domain become members on their first SSO sign-in (or sign up through SSO). |

**Test connection** runs discovery, checks the provider offers the code flow with PKCE S256, and sends a token request
with a made-up code: `invalid_grant` means the client ID and secret were accepted, `invalid_client` that they weren't.
The stored secret is only ever sent to the stored issuer and client ID; testing another one needs its secret typed in.
Error details are generic (no raw network errors).

Changing the issuer removes all identity links of the organisation (subjects of another provider mean nothing).
Removing the last verified domain switches "Require SSO" and auto-join off. A domain whose TXT record disappears is
un-verified the next time it would grant something new (re-checked at most daily); remove the domain in the app to
revoke it at once.

Verified domains also serve **email domain auto-join** (Keeper's email auto-provisioning), which works without SSO:
anyone with an address in the domain can ask to join by email, then signs up with a master password and authenticator
([provisioning](provisioning.md#email-domain-auto-join)). Removing or un-verifying the last verified domain switches it
off too.

Why verified domains: an organisation's admins control their identity provider, which can claim any email address.
Only for a domain whose DNS they control do we let their provider create accounts, add people to the organisation, skip
the authenticator code or suggest SSO on the sign-in page. For other addresses SSO still proves the address to the
organisation, but the master password and authenticator code protect the account as usual.

## Microsoft Entra ID

1. Entra admin center → **App registrations** → **New registration**. Supported account types: *this organizational
   directory only*. Redirect URI: platform **Web**, `https://vault.example.com/api/v1/auth/sso/callback`.
2. **Certificates & secrets** → **New client secret**; copy the value (not the ID). Note its expiry.
3. **Token configuration** → **Add optional claim** → token type **ID** → `email` and `xms_edov`. (Accept adding the
   Microsoft Graph `email` permission.) Entra doesn't send `email_verified`; Clane Vault accepts Entra's `xms_edov: true`
   ("email domain owner verified") instead, and only for issuers on `login.microsoftonline.com`.
4. **API permissions**: Microsoft Graph delegated `openid`, `email`, `profile` (grant admin consent).
5. In Clane Vault: issuer `https://login.microsoftonline.com/<tenant-id>/v2.0` (a tenant-specific issuer; the
   multi-tenant `common`/`organizations` endpoints are not supported because their tokens can't be checked against one
   issuer), the **Application (client) ID** and the secret.
6. Users need the `mail` attribute set (it becomes the `email` claim) and it must match their Clane Vault address.
   Enforce MFA with Conditional Access before turning on "Trust the identity provider's MFA".

## Google Workspace

1. Google Cloud console (a project owned by your Workspace) → **APIs & Services** → **OAuth consent screen**: user type
   **Internal**; scopes `openid`, `email`, `profile`.
2. **Credentials** → **Create credentials** → **OAuth client ID** → **Web application**. Authorized redirect URI:
   `https://vault.example.com/api/v1/auth/sso/callback`. Copy the client ID and secret.
3. In Clane Vault: issuer `https://accounts.google.com`, the client ID and secret.
4. Google sends `email_verified: true` for Workspace accounts and an `hd` claim with the Workspace domain. Only addresses
   in the organisation's SSO domains are accepted, so personal Gmail accounts are refused even though an *Internal*
   consent screen already limits sign-in to your Workspace.
5. Enforce 2-Step Verification in the Admin console before turning on "Trust the identity provider's MFA".

## Other providers

Any OpenID Connect provider with discovery, the authorization code flow with PKCE (S256) and an
`email` + `email_verified` claim works (Okta, Keycloak, Auth0, Authentik, JumpCloud…). Client authentication is
`client_secret_post`; id_tokens must be RS256-signed (the OpenID Connect default).

## Security notes

- State, nonce and PKCE on every request; requests and proofs are single use, short-lived and bound to the browser;
  authorization requests and proofs older than an hour are deleted.
- `returnTo` only accepts paths inside the app (never `//host`, `/\host` or absolute URLs).
- Rate limits: discovery 30/min, start 20/min, callback 30/min, sign-in 20/min, sign-up 10/min per address, and start
  60/min per organisation; wrong master passwords count toward the account lockout as usual.
- No codes, tokens or secrets are logged: the callback's query string is redacted from request logs and events record
  only outcomes (`sso.callback`, `sso.callback_failed` with a reason (an identity provider's error text is stored
  without control characters), `auth.login` with `via: "sso"` and `totpSkipped`, `auth.step_up`,
  `sso.identity_linked`, `sso.jit_join`, `sso.settings_updated`, `sso.domain_*`, `sso.test`, and `sso.bypass_owner`
  once per session when an owner uses a "Require SSO" organisation without SSO). Unauthenticated starts aren't logged.
- `HOSTED_MODE`: issuer, token and JWKS requests only connect to public addresses (organisation admins aren't trusted
  with the server's network). The check runs in the socket's own DNS lookup, so the address checked is the address
  connected to (no rebinding gap). `SSO_ALLOW_HTTP_ISSUER=true` refuses to start with `HOSTED_MODE=true` or
  `NODE_ENV=production`.
- The SSO check for "Require SSO" is per session: it lasts for the session (12 hours of refreshes), and turning the
  setting off applies at once.
- Discovery shows which organisations use SSO for a verified domain (their name and ID) to anyone who types an address
  in that domain. It never says anything about accounts.
