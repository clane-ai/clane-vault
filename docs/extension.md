# Browser extension

The Clane Vault extension fills and saves passwords in **Chrome, Edge and Firefox** (Manifest V3). It is a client of
the same vault server as the web app and keeps the same zero-knowledge model: the master password is turned into keys
inside the extension, the server only ever sees ciphertext, and nothing secret is written to disk.

Source: `apps/extension`. Build: `npm run build -w apps/extension` writes

| Output | Use |
|---|---|
| `apps/extension/dist/chrome/` | unpacked build for Chrome and Edge |
| `apps/extension/dist/firefox/` | unpacked build for Firefox (background scripts, gecko id `vault-extension@clane.si`) |
| `apps/extension/dist/clane-vault-chrome-<version>.zip` | upload to the Chrome Web Store and Microsoft Edge Add-ons |
| `apps/extension/dist/clane-vault-firefox-<version>.zip` | upload to addons.mozilla.org (AMO) |

The product name follows `VITE_PRODUCT_NAME` / `VITE_PRODUCT_SHORT` at build time, like the web app.

## Install

**From the stores** (once published): install "Clane Vault" from the Chrome Web Store, Edge Add-ons or AMO.

**Unpacked (Chrome / Edge)**: open `chrome://extensions` (or `edge://extensions`), switch on **Developer mode**, choose
**Load unpacked** and pick `apps/extension/dist/chrome`. To install from the zip, unzip it first and load the folder.

**Temporary (Firefox)**: open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on** and pick
`apps/extension/dist/firefox/manifest.json` (or the zip). Temporary add-ons are removed when Firefox closes; a
permanent install needs the AMO-signed build (Firefox 128 or newer).

## First run

1. Click the toolbar icon. Enter the **server address** (default `https://vault.clane.si`; self-hosted instances use
   their own address). Only `https://` is accepted, plus `http://localhost` and `http://127.0.0.1` for development.
   The browser asks to let the extension reach that one server.
2. **Sign in** with email, master password and authenticator code. Accounts that haven't finished 2FA setup do it in
   the web vault first. Organisations that require single sign-on: sign in on the web vault (pairing the extension
   with an SSO session is a later item); the extension shows "requires single sign-on" for those organisations.
3. Optional: **Settings → Offer to save logins**. This asks for access to all sites, needed to notice sign-in forms.

## Using it

- The popup lists logins for the current site first (same registrable domain), then everything else; search covers
  title, username, site and folder.
- **Fill** puts the username and password into the page. **Copy username / password / one-time code** copies to the
  clipboard, which is cleared after 30 seconds. The one-time code shows its countdown.
- **Use only** items can be filled but never shown or copied (password and one-time code), and only on their own
  site: there is no **Fill anyway** for them.
- The organisation switcher works like the web app's (`X-Org-Id`); **Open web vault**, **Lock** and **Sign out** are in
  the header and Settings. The password generator uses the same generator as the web app.
- **Save offers**: after you submit a sign-in form, a small banner asks **Save** (new login in your private vault),
  **Update** (the saved password changed; needs edit permission) or **Never for this site**.

## Permissions and why

| Permission | Why |
|---|---|
| `activeTab` | Read the URL of, and fill, only the tab you clicked the toolbar icon in. |
| `scripting` | Inject the fill script into that tab's top frame; register the save-offer script when you turn it on. |
| `storage` | `storage.session` (memory only) for keys and the session; `storage.local` for settings only. |
| `alarms`, `idle` | Auto-lock after idle time and when the screen locks; clipboard clearing. |
| `clipboardWrite`, `offscreen` (Chrome/Edge) | Clear a copied secret after 30 s even when the popup is closed. |
| Optional host: your server | Talk to the vault API. Asked on first run, for that one origin. |
| Optional host: all sites | Only for save offers, asked when you switch them on. Fill doesn't need it. |

No remote code, no analytics, no third-party requests: the extension talks only to the server you chose. The CSP is
`script-src 'self' 'wasm-unsafe-eval'` (Argon2id runs as WebAssembly).

## Security model

- **Keys**: the master password goes through Argon2id with the account's parameters (64 MiB, t=3 minimum), exactly as
  in the web app (`@clane-vault/crypto`); the unwrapped user key and private key live in the background worker's
  memory and in `chrome.storage.session` (memory only, cleared when the browser closes, not readable by content
  scripts). They are **never** written to `storage.local` or disk. Decrypted items stay in the worker's memory; the
  popup receives titles, usernames and sites, and a password or one-time code only when you copy it.
- **Sessions**: sign-in sends `client: "extension"`. The server then returns the refresh token in the response body
  (no cookie) and labels the session **"Browser extension"** (Settings → sessions, event log). The extension keeps it in
  `storage.session` and sends it in the body of `POST /auth/refresh` and `/auth/logout`. Refresh uses the same code path
  as the web cookie: rotation on every use, compare-and-swap, a 30-second grace window and reuse detection (an old
  token after the window revokes the session). A body token is accepted only for sessions created as an extension
  session, so a web cookie's value can't be replayed in a body. Logout (cookie or body) needs the token's secret; a
  session id alone revokes nothing. The access token lasts 15 minutes, the session 12 hours.
- **Auto-lock**: after 15 minutes without popup activity (1 minute to 4 hours in Settings), when the screen locks, when
  the machine has been idle for the auto-lock time (Firefox doesn't report a locked screen everywhere), and with
  **Lock**. An organisation's `autoLockMinutes` policy shortens it (the strictest of your organisations applies).
  Locking wipes keys and decrypted items; unlocking needs the master password. When the browser closes, the session
  is gone and the next start asks for a full sign-in.
- **Fill rules**: only on a click in the popup; only into the **top frame** of the active tab (never into iframes,
  whatever their origin); the page's registrable domain (eTLD+1 from the public suffix list, private suffixes such as
  `github.io` included) must match the item's URL, otherwise the popup names both sites and needs **Fill anyway**;
  plain `http://` pages need the same explicit confirmation. The confirmation is bound to the page origin the popup
  showed: if the tab has moved to another origin meanwhile, it asks again. Only absolute `https://` / `http://` pages
  count; `about:`, `data:`, `blob:` and `file:` pages are never filled. The fill script re-checks the page origin right before
  filling (a tab that navigated in between is not filled) and ignores hidden, invisible and disabled fields.
- **Save offers**: the content script runs only in top frames and only when you turned offers on. It reacts only to
  what the user does (trusted submit, click and Enter events, not page script) and sends the submitted username and
  password to the background, which compares them with your items; nothing secret goes back to the page. The page URL
  comes from the browser, not the message. Because "offer / no offer" says whether a pair is already stored, a tab may
  submit at most 5 logins a minute (20 across tabs), so a page can't use it to test password guesses. Never on the
  vault server's own pages (that form holds the master password). The banner is a closed shadow root that answers only
  real (trusted) clicks, and only after it has been visible, unmoved and on top for 0.7 s; a banner the page made
  see-through, filtered, hidden, transformed or covered refuses Save, Update and Never (Close always works). Known
  limit: an overlay with `pointer-events: none` drawn over the banner can't be detected from inside a page. A pending
  offer is kept for 5 minutes in `storage.session` and only for the same site.
- **Organisation policies**: `extensionAllowed: false` hides that organisation's items in the extension (client side).
- **Clipboard**: cleared 30 seconds after a copy (Chrome/Edge via an offscreen document, Firefox from the background
  page). The clear is unconditional: anything copied in those 30 seconds is cleared too.
- Same known limit as the web app: "Use only" is a convenience control; the extension holds the key, so a technical
  user could extract the password.

## Publishing notes

- **Version**: `apps/extension/package.json` → `manifest.json`. Raise it for every store upload.
- **Chrome Web Store / Edge Add-ons**: upload the chrome zip. Justify `activeTab`, `scripting`, `offscreen`
  (clipboard clearing) and the optional host permissions (your vault server; all sites only for the opt-in save
  offers). Single purpose: "password manager for Clane Vault". Privacy: no data collected by the publisher; vault data
  goes only to the user's own server, end-to-end encrypted.
- **AMO**: upload the firefox zip. The build is not minified, so no separate source upload is needed for review
  beyond pointing at this repository; `data_collection_permissions` is `none`. Firefox closes the popup when a
  permission prompt appears: if the server permission isn't granted on first run, open the popup again and press
  **Continue** once more.
- **Self-hosted builds**: set `VITE_PRODUCT_NAME` before building to rebrand; the default server address is in
  `apps/extension/src/shared/domain.ts`.

## Development

- `npm run test -w apps/extension` (unit tests: domain matching, form detection, the message handlers with a fake API,
  the refresh client) and `npm run typecheck -w apps/extension`.
- End-to-end in Chromium: `npm run build -w apps/extension -- --e2e` (adds localhost host access to
  `dist/chrome-e2e`), then `npm run test:extension -w e2e`. The test runs against a self-contained fake API and
  login page; it needs no dev servers or database.
- API side: `apps/api/test/extension-auth.test.ts`.
