# Branding: product name, organisation logos

## Product name

The product name has a build-time default and an optional runtime override.

| Where | Default | Override |
|---|---|---|
| Web app (sign-in page, page title, header, Settings) | `VITE_PRODUCT_NAME` / `VITE_PRODUCT_SHORT` at build time ("Clane Vault" / "Vault") | Settings → Server → Branding |
| Emails and the authenticator-app issuer | `PRODUCT_NAME` on the API ("Clane Vault") | Settings → Server → Branding |

**Settings → Server (instance admins) → Branding** sets the product name and the short name for the whole instance.
Each is 1–40 characters. Control characters are stripped and spaces collapsed, and `<` and `>` are refused. Leave a
field empty, or use **Use defaults**, to go back to the build's name. Changes are logged as `instance.brand_change`
(old and new values).

The web app reads `GET /api/v1/brand` (public, no sign-in) before its first paint, waiting at most 1.5 s. The response
is `{ productName, shortName, logoVersion }`, where `null` means "use the build's". If the request fails, times out or
returns something invalid, the app uses the build-time names, or the last names it saw on this device when offline.
Emails sent after a change use the new name; other API processes pick it up within 15 seconds.

The web manifest (the installed app's name) and the browser extension keep the build-time names.

### Sign-in page logo

An instance admin can upload a logo in the same Branding card. It replaces the mark on the sign-in page, with the
product name beside it. Because it appears before sign-in it is public: `GET /api/v1/brand/logo?v=<logoVersion>`.
Changes are logged as `instance.logo_set` and `instance.logo_remove`.

## Organisation logo and name

Owners and admins of an organisation can rename it and upload or remove its logo in **Organisation settings**. To get
there, use the account menu at the bottom left, or the organisation menu at the top left. The logo appears in the
sidebar header and the organisation switcher. Without a logo the app shows the product mark and the organisation's
initials. Events: `org.rename` (old and new name), `org.logo_set` and `org.logo_remove`.

The logo is served only to the organisation's active members: `GET /api/v1/orgs/:id/logo?v=<logoVersion>` with the
bearer token. The app fetches it with `fetch` and shows it from a `blob:` URL, since an `<img>` can't send the token,
so the CSP's `img-src` allows `blob:`. Anyone else gets `404`, whether or not the organisation has a logo. The version
comes with the organisation list (`GET /me/orgs` → `orgs[].logoVersion`) and `GET /org`.

## Upload rules (both logos)

- `PUT /api/v1/org/logo` (with `X-Org-Id`) or `PUT /api/v1/admin/instance/brand/logo`. The raw image is the request
  body, and the declared content type is ignored. `DELETE` on the same path removes the logo.
- Only **PNG, JPEG or WebP** are accepted, recognised by their magic bytes. **SVG is never accepted** because it can
  carry script. Anything else gets `415 unsupported_type`.
- At most **256 KB** (`413 too_large`) and **1024 × 1024 pixels**, read from the image header (`400 too_many_pixels`).
  An unreadable header gets `400 bad_image`.
- Logos are stored in the database (`OrgLogo`, `InstanceBrand`, as `bytea`) with their SHA-256. The first 16 hex
  characters are the version used as a cache-buster.
- Responses carry the stored type, `X-Content-Type-Options: nosniff`, `Content-Disposition: inline`,
  `Content-Security-Policy: default-src 'none'; sandbox`, an `ETag` (`304` on `If-None-Match`) and
  `Cache-Control: private, max-age=86400`. The instance logo uses `public`. All other API responses stay `no-store`.

Database migration: `20261016000000_branding_logos`.
