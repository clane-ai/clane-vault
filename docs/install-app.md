# Install the app and use it offline

The web vault is an installable app (a PWA). Installed, it opens in its own window with its own icon, and it can show a
read-only copy of your vault when the server can't be reached.

## Install

The server must be reached over **https** (browsers only install apps and run service workers on secure origins;
`http://localhost` also works for testing).

| Device | How |
|---|---|
| Chrome or Edge on Windows, macOS, Linux, ChromeOS | Open the vault, then the install icon at the right of the address bar (or menu → **Install app** / **Apps → Install this site as an app**). |
| Android (Chrome, Edge, Samsung Internet) | Menu (⋮) → **Install app** or **Add to Home screen**. |
| iPhone and iPad (Safari) | Share → **Add to Home Screen**. |
| Firefox (desktop) | Not installable as an app. Use the browser tab; the offline copy works there too. |

The installed app's name and icons come from the build-time branding (`VITE_PRODUCT_NAME`, `VITE_PRODUCT_SHORT`, the icons in
`apps/web/public/brand`). To remove it, uninstall it like any other app or remove the home-screen icon.

## What the service worker caches

`/sw.js` caches the **app shell** only: `index.html`, the built JavaScript and CSS, fonts, the manifest and icons. It
never handles `/api/` requests, so nothing the server sends about your vault passes through or is stored by the
service worker. Pages always come from the network when it's there; the cached shell is used only when it isn't.
Each release changes the service worker, which replaces the old cache on the next visit. The server sends `/sw.js`
with `Cache-Control: no-cache, max-age=0` and the manifest as `application/manifest+json`. The CSP allows
`worker-src 'self'` and `manifest-src 'self'` and nothing else new.

## Offline copy

**Settings → This device → Offline copy**, on by default, per device and browser.

While it is on, the app keeps in the browser's IndexedDB (database `clane-offline`), for the signed-in account only:

- the account's key material, exactly as the server sends it for unlocking: KDF salt and parameters, the user key
  wrapped under the master-password key, the public key and the wrapped private key;
- for each organisation (and the private vault), the last `/sync` response as received: encrypted records, folder
  names and keys, plus the metadata in it (record ids, types, dates, permissions, folder member names and emails);
- the list of organisations.

Nothing decrypted is stored: no passwords, notes, titles, keys or master password. File attachments
(`docs/attachments.md`) are listed from the sync's encrypted metadata with their size and "Available online", but their
content is never stored on the device: opening a file needs a connection. The service worker never caches API traffic,
file chunks included. A newer sync replaces the older
one, so items the server stopped sending (deleted, unshared, or own private items held back until a session proves its
authenticator code) leave the copy too.

### Using it

When the server can't be reached (no network, or a gateway answering 502–504), the app opens on the unlock screen with
"You're offline". Enter the master password: it is checked against the stored key material on the device, exactly as
the online unlock does, and the vault opens **read-only** with an **Offline — read only** banner. You can search,
reveal and copy (subject to each item's permission), but you can't add, edit, move, share, trash, import or change
settings; admin pages, settings and share links say they need a connection. The app keeps trying the server every
15 seconds and when the browser reports it's back online; then it returns to normal mode with the vault reloaded from
the server, keeping you unlocked if the account and its key material haven't changed (otherwise it locks).

### When it is deleted

- **Sign out** (also when offline; the server session is then ended the next time the app reaches the server, before
  anything else happens);
- the server refuses the session (expired, revoked from another device, or signed out elsewhere);
- another account signs in on the same browser (only one account's copy is kept);
- the device setting is turned off;
- for one organisation, when its policy turns **Offline copies** off (`docs/policies.md`): that organisation's vault is
  removed from the copy at the next sign-in, refresh or sync and not stored again;
- for one organisation, when you are no longer a member: removed at the next sign-in or refresh.

### Security notes

- The offline copy is protected by the master password and the KDF, the same as the encrypted data on the server.
  Anyone who can read the browser profile can attempt offline guessing of the master password against it, so use a
  strong master password (the organisation's password policy can require one) and full-disk encryption on devices.
- Unlocking offline needs only the master password, as unlocking a signed-in session online does; the authenticator
  code is asked at sign-in, which still needs the server.
- Changes made elsewhere aren't visible offline until the next sync, and revoked access stays readable in the copy
  until the device reconnects or signs out. Organisations that can't accept this switch offline copies off by policy.
- Turn the setting off on shared or untrusted computers.
