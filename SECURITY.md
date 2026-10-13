# Security policy

## Reporting a vulnerability

Report it privately through GitHub (the repository's **Security** tab → **Report a vulnerability**), or email
hello@clane.ai with "Security" in the subject. Please don't open a public issue or pull request for a vulnerability.

Include what you found, the version (`ghcr.io/clane-ai/clane-vault` tag or commit), steps to reproduce, and what an
attacker could do with it.

We aim to reply within 2 working days. We'll tell you how the fix is going and credit you in the changelog unless
you'd rather not be named. Please give us time to release a fix before you publish details. For issues that expose
vault contents, keys or another person's account, we aim to release a fix within 14 days.

## Supported versions

Only the latest release gets security fixes. Self-hosters update by setting `CLANE_VAULT_VERSION` and running
`docker compose up -d` (see [deploy/client/README.md](deploy/client/README.md)).

## Scope

In scope: this repository, the published image and the browser extension. That includes the client-side
cryptography (`packages/crypto`), the API's authorisation, one-time links, recovery, attachments, the extension's
autofill and the install bundle.

Out of scope: weaknesses that need an already-compromised device or browser, denial of service by sheer volume,
missing security headers on a reverse proxy you run, and reports from automated scanners without a demonstrated
impact.

## Security model

What the server stores in plain text and what a compromised server could still do are described in
[docs/sharing.md](docs/sharing.md) and [docs/design/](docs/design/). We most want reports that break a stated
guarantee.
