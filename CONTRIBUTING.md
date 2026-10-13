# Contributing to Clane Vault

Thanks for helping. Bug reports, fixes, import formats and documentation are welcome.

## Before you start

- **Security issues** go to hello@clane.ai, not to a public issue. See [SECURITY.md](SECURITY.md).
- For anything larger than a small fix, open an issue first so we can agree on the approach. Changes to the
  cryptography or the data model need a short design note (see [docs/design/](docs/design/) for examples).

## Development setup

See [Development](README.md#development) in the README. You need Node.js 22 and Docker.

## Pull requests

1. Branch from `main` and keep the change focused.
2. Add or update tests. The API tests run against a real Postgres in Docker; end-to-end tests use Playwright.
3. Run `npm run typecheck` and `npm test` before you push.
4. Update the docs in `docs/` or `deploy/client/README.md` if behaviour or configuration changes, and add a line
   under `## Unreleased` in `CHANGELOG.md`.
5. Sign off every commit (see below).

Code style: follow the code around you. Comments explain why, not what. UI copy is plain British English in
sentence case.

## Sign-off (DCO)

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change or have the right to submit it under the project's licence.

```sh
git commit -s -m "Fix the import of Bitwarden secure notes"
```

This adds `Signed-off-by: Your Name <you@example.com>` to the commit message.

## Licence

By contributing, you agree that your contribution is licensed under the project's licence,
[AGPL-3.0](LICENSE).
