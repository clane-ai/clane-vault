# Security policy

## Status

**Pre-audit, use for evaluation.** Clane Vault hasn't had an external security audit or penetration test. Run it to
evaluate it, with test data. Don't store production secrets in it or roll it out across an organisation until an
audit has been done and its findings fixed; this section will say when.

Known limits that an audit would look at first are listed under *Trust limits* in [docs/sharing.md](docs/sharing.md):
in short, a compromised server can't read secrets, but it can hand out the wrong public key for a person you have never
shared with from that browser, plant fake shared folders or records, and hide or roll back data.

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

### Agent access: the disclosed exception

Agent access ([docs/agents.md](docs/agents.md)) is off unless the server is configured for it. When it is on, it is a
deliberate exception to zero-knowledge, limited to what is shared with an agent:

| Data | Server (API, database) | Gateway (hosted: Clane; self-hosted: you) | Model / agent client |
|---|---|---|---|
| Records never shared to an agent | ciphertext only (unchanged) | nothing (no key reaches it) | nothing |
| Records in folders, groups or shares an agent holds | ciphertext only | **plaintext at use time**, and *could* decrypt at any time while the agent is live (it holds the wrapped key and the KEK) | names, hosts, policy; responses with the secret scrubbed |
| Personal items with *Can use* (a person's own agent) | ciphertext only | **plaintext at use time**; could decrypt any time while the agent is live | names, hosts, policy; responses with the secret scrubbed |
| Deposits and agent updates (a personal agent's `save_secret`, `update_secret`, `capture`) | ciphertext, a gateway signature, the previous version of an updated item | **plaintext at write time**, even for an item the agent is never given to use | for `save_secret` and `update_secret`, the value it supplied; for `capture`, only the new item's handle |
| Agent private key | KMS-wrapped envelope only | plaintext in memory per call; wrapped at rest | never |
| Who used what, where, when | metadata events | metadata log | its own calls |

*Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted.*

A *.env file* item given to an agent at *Can use* gives the gateway its record key, so the gateway can decrypt every entry
in the file while the grant lives, though the policy lets it send only one. Its key names (`STRIPE_LIVE_KEY`,
`DATABASE_URL`) reach the model through `list_secrets`, as titles and hosts already do, and describe a project's stack.

Residual risks, which no mitigation in this release removes:

- **Non-admin users pin the gateway: trust-on-first-use in practice.** A person who creates a personal agent pins the
  gateway identity themselves, and most won't compare its fingerprint with the published one. A malicious API server
  could present its own "gateway" to a first-time user and receive every record key that user then gives their agent.
  It can't do this to a user whose browser already holds a pin from an organisation. See
  [docs/agents.md](docs/agents.md#personal-agents).
- **Admins don't see what personal agents hold.** An organisation's event log shows only that a member created,
  verified, connected or revoked a personal agent; an organisation that needs more control switches personal agents off.
- **Agent updates rest on a server flag.** Whether a personal agent may update an item (*Agent can update*) is
  `agentWrite`, server state. A malicious server together with a hijacked agent could overwrite any item the agent
  holds a key for. Each update is signed by the gateway and the server keeps the previous version (the last 5, for 30
  days, *Restore previous*), so an overwrite is visible and reversible, not impossible. Saved items never become records
  without the owner's Keep, so the server can't plant one in a vault.
- **A malicious server can substitute the key the agent holds for an item with *Agent can update* and read what the
  agent next writes to it.** The agent's copy of a record key is sealed to its public key, which anyone can seal to, and
  the gateway can't tell a substituted one from the owner's. Unkept deposits are not affected by this substitution: the
  gateway updates a deposit only if it carries the gateway's own signature over that body.
- **A malicious server can bind a new personal agent to its own key instead of the owner's.** Only the owner's browser
  checks the binding; `verifiedAt` is server state. The verify dialog shows the mismatch ("bound to a different account
  key"), and an agent that failed it must not be connected, or everything it saves (`save_secret`, `capture`) is sealed
  to the server's key and readable by the server. *Connect* in Settings → My agents appears only after this browser
  checked the binding, but the OAuth consent page doesn't check it yet. Items given to the agent to use are not affected:
  grants and Keep check the binding in the browser before sealing.
- **The gateway sees what it writes.** It encrypts a saved or updated value itself, so it sees it even if the agent is
  never given that item to use. With `save_secret` and `update_secret` the model supplied the value, so it has seen it
  too; `capture` keeps a created credential away from the model.

- **A hijacked agent** (prompt injection) can make legitimate-looking calls to an allowed host with bad intent (delete
  the repo, email the customer list). Per-path policy narrows it; nothing removes it.
- **A gateway host breach**, with its KMS permissions, can read agent-scoped plaintext. This is the accepted exception
  until the gateway runs in an enclave (Phase 5).
- **An insider at the operator** who controls both the deploy pipeline and the KMS key policy can read agent-scoped
  items until Phase 5.
- **Legal compulsion**: for agent-scoped data the operator could comply, by deploying a modified gateway. Users with
  legal exposure should not share such items with agents on the hosted service, or should self-host.
- **Re-encoding hosts**: an allowed host that re-encodes a secret in a form the scrubber doesn't know can get it into
  a response, and so to the model provider.
- **Self-reported use**: `agent.use` events are reported by the gateway itself, so a compromised gateway can
  under-report. Enrolment, verification, revocation, OAuth grants and KMS audit entries are recorded outside it.

**Rotate every agent-scoped credential after a gateway incident.**

Agent OAuth refresh tokens are derived from `JWT_SECRET`: rotating it ends every agent OAuth grant (connected apps must
connect again), as well as signing everyone out.
