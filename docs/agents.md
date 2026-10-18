# Agent access

**Evaluation feature.** Agent access is a deliberate, disclosed exception to zero-knowledge: items you share with an agent can be read by whoever runs the gateway. Everything else stays end-to-end encrypted. See [Trust limits](#trust-limits) and `SECURITY.md`.

Agent access lets cloud AI agents (Claude.ai and ChatGPT connectors, the Claude and OpenAI APIs, Claude Code) **use** credentials held in a team vault without the model ever seeing a value, and without installing anything. The agent talks to one remote MCP server, the gateway (`https://vault.clane.ai/mcp` on the hosted service, `https://<your host>/mcp` self-hosted). The gateway makes the outbound HTTPS call itself with the credential injected, and returns the response with the credential scrubbed out.

It is off unless the server is configured for it (self-hosted: `deploy/client/README.md`, *Agent access (optional)*). With it off, every agent, `/agent/*` and `/oauth/*` route answers 404 and the Agents page isn't shown.

## What an agent is

An agent is a machine member of an organisation, created by an owner or admin under **Admin → Agents**. It has:

- its own X25519 key, generated **inside the gateway**. The private key never reaches the API in a usable form: the API stores it only as an envelope wrapped by the gateway's key-encryption key (KEK);
- **Use** permission only, on what it is given. It can't edit, export, share or see a value. The server enforces this: asking for more answers `400 agent_use_only`, and a group grant above *Use* is capped silently;
- no password, sign-in, 2FA, email, recovery or settings. It isn't a seat, adds no pooled storage, and never appears on the People page, the risk dashboard, password health or provisioning lists.

The People page routes refuse agents (`409 is_agent`). An agent is ended only by **Revoke** on the Agents page.

Hosted plans: Personal 0 agents, Team 3 (also during the Business trial), Business 10. Revoked agents don't count. A downgrade blocks new agents only. Self-hosted (`BILLING_MODE=off`): unlimited.

## Enrolment and the gateway fingerprint

1. **New agent** → name and an optional expiry. The API asks the gateway for a key. The gateway generates the key pair, wraps the private key, and signs `agent-key:<orgId>:<agentId>:<publicKey>` with its own Ed25519 **identity key** (the attestation, `g1.<keyId>.<signature>`). Gateway down: `503 gateway_unavailable`, and nothing is created.
2. **Verify.** Your browser checks the attestation against the gateway identity key and shows the agent's fingerprint and the **gateway fingerprint**, marked *Pinned*, *New* or *Changed*. Compare the gateway fingerprint with the published one (below), then confirm. Your browser pins the gateway identity and the agent key. Until verified, the agent is *Awaiting verification*: no picker lists it and nothing can be shared with it. A signature that doesn't verify shows *The gateway did not sign this key*; revoke that agent.

**The published fingerprint.**

- Hosted: the fingerprint of `https://vault.clane.ai/mcp` is published on the Clane status page. (*Placeholder until the hosted gateway launches.*)
- Self-hosted: print it and give it to your admins through a channel the server doesn't control (chat, a wiki, in person):

      docker compose exec gateway /nodejs/bin/node dist/cli.js identity

  It prints the key id and the fingerprint.

**What the pin protects.** A compromised API server, or anyone who can write to its database, can't substitute an agent key it controls: every browser that shares with an agent checks the agent key's attestation against the pinned gateway identity before sealing anything to it, and refuses if it fails. **What it doesn't protect.** A compromised gateway signs whatever it likes, and it holds the agent keys anyway. The gateway is the trust boundary.

**Members trust the gateway on first use.** An admin pins the gateway explicitly when verifying an agent. A member who isn't an admin pins it the first time they share with an agent, from that browser: the share sheet shows its fingerprint. This is the same trust-on-first-use limit as for people's keys (`docs/sharing.md`, *Trust limits*): on that first share, a malicious server could present a gateway key of its own. Pins are kept per signed-in user and organisation, in one fixed slot (not one per key id).

**A changed gateway identity.** If the gateway's identity key changes (a new data volume, a lost KEK, a replaced gateway):

- the API refuses to start, and refuses new agents with `503 gateway_identity_changed`, until the operator sets `GATEWAY_ACCEPT_NEW_IDENTITY=true` (set it back to `false` afterwards);
- members' browsers **refuse** to share with any agent until an admin confirms the new fingerprint on the Agents page. Members never re-pin a changed gateway themselves;
- **every existing agent's attestation is invalid**, because it was signed by the old key. Such agents show *Needs re-enrolment*: revoke each one, create it again and share with it again. Its stored ciphertext is untouched, but nothing new can be sealed to it.

## Scopes

An agent gets access the same way a person does, always with *Use*:

- **Folders.** The folder owner adds the agent in the folder's people sheet.
- **Groups.** An admin adds the agent to a group. Key holders then see it in the approval queue, marked *Agent*, and approve or decline. This is how an admin scopes an agent to folders they don't own.
- **Single records.** Share the record with the agent.

Every place a person shares with an agent shows this, above the confirm button, every time:

> Give agents restricted credentials: a Stripe restricted key, a read-only database user, a scoped token. Never a root or owner credential. What you share here can be read by the gateway and used by whatever drives the agent.
>
> Sharing with an agent makes those items readable by the gateway operator. Everything else stays end-to-end encrypted.

## The usage policy (Agent use)

A record is only usable by an agent if it has a usage policy: the **Agent use** section of the record editor (edit holders). The policy is part of the encrypted record body, so the server can neither read nor change it. A record without one is listed to the agent but never used (`reason: "no_policy"`).

- **Allowed hosts** (required, up to 32). Exact host names, optionally with `:port`. Without a port only the scheme's default port matches. `*.example.com` matches exactly one label (`api.example.com`), never `example.com` itself and never deeper names. IP literals are never allowed, and a wildcard never matches an IP. **Unicode host names are refused: write the punycode form** (`xn--…`).
- **How to send it**: `Authorization: Bearer <secret>`, `Authorization: Basic base64(username:secret)`, a named header with an optional prefix, or a query parameter. **The query parameter is the weaker option**: URLs end up in proxy, server and browser logs. Use it only when the API offers nothing else.
- **Which field**: by default an API key record's secret, or the password of a login, server or database record; or another field.
- **Methods** and **paths** (optional). A list narrows the call. **An empty list denies every call**, it doesn't mean "any". Paths match by whole segment: `/v1` covers `/v1` and `/v1/x`, not `/v1x`; `/files/` covers `/files/a`. Hosted, these fields are a Business feature in the editor; because the policy is ciphertext, the gateway enforces whatever a policy contains on every plan, and a downgrade never loosens one. (On Team, a member who isn't an admin can still set them, because the plan check reads `/org/plan`, which is admin-only. This can only narrow what an agent may do.)

The gateway also refuses, whatever the policy says:

- **Encoded `/`, `\` or `.` in a path** (`%2f`, `%5c`, `%2e`, and double-encoded forms), and control characters. An upstream server may decode them into a different path. This makes APIs that use encoded slashes in a path, such as GitLab project paths (`/projects/group%2Fproject`), unusable through an agent: use the numeric project id instead.
- **Non-public addresses.** Every address a host resolves to must be public: loopback, private, link-local, CGNAT, multicast, unique-local, cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal` and others), documentation and benchmarking ranges (`198.18.0.0/15` among them), and IPv6 forms that embed any of these are refused. The gateway connects to the address it checked, so DNS rebinding can't move the call. `https` only (plain `http` only to a `GATEWAY_ALLOW_PRIVATE_CIDRS` range, self-hosted).
- **Redirects** are followed at most 3 hops, each re-checked against the policy, and **a redirect to a different origin never carries the credential**, even to another allowed host. A `Location` that contains the secret is never followed.

**An older app drops the policy.** A client from before agent access doesn't know the field, so saving the record from it removes the policy. The agent then gets `no_policy` for that record: it fails closed, but the agent stops working until someone adds the policy back from a current client. The current editor keeps a policy byte for byte when you don't touch it, and refuses a record-type change that would leave the policy naming a field the new type doesn't have.

## Tools

The gateway offers two MCP tools. There is no tool that returns a credential.

- `list_secrets` → the items the agent may use: `handle`, title, type, hosts, how it is sent, and methods/paths if set. Never a secret field. A **handle** is `<folder>/<title>`, slugged. The folder part names the folder that **holds the record's key** (for a record in a subfolder, the team folder it belongs to), or `shared` for a record shared directly. Duplicates get `-2`, `-3`.
- `http_request` `{ item, method, url, headers?, body? }` → `{ status, headers, body, truncated? }`, or `{ error: "refused", reason }`. The gateway drops any `Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key` and policy header the agent sent, injects the real one, and scrubs the secret (raw, base64, base64url, URL-encoded, hex, JSON-escaped and the `username:secret` form) from the response headers and decompressed body as `[clane:redacted]`.

Refusal reasons: `not_found`, `no_policy`, `host`, `scheme`, `ssrf`, `method`, `path`, `timeout`, `request_too_large`, `upstream_error`, `busy` (one call at a time per session).

## Connecting a client

Use the **Connect** sheet on the Agents page: it has the URL, these snippets with your URL filled in, and creates API tokens. OAuth flows end on a consent page where an **owner or admin** signs in, picks the agent and clicks *Allow*. Members never see it.

**Tell the model** (one prompt for every client):

> Use `list_secrets` to see what you may call, then `http_request` with the item handle. You will never see a credential.

**Claude.ai (web and desktop)**, Pro and Max: **Customize → Connectors → + Add → Add custom connector** → a name and the URL → **Continue** → under *OAuth client* choose **Register automatically** (the gateway uses dynamic client registration) → **Add** → **Connect** → sign in to Clane Vault, pick the agent, **Allow**. Team and Enterprise: an owner adds the connector under **Organization settings → Connectors**, then members click **Connect** under **Customize → Connectors**. Source: [Claude help, custom connectors](https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp).

**ChatGPT**: [ChatGPT Plugins](https://chatgpt.com/plugins) → **+** → **Add custom MCP server** → name and description, MCP server URL (with `/mcp`), authentication OAuth → **I understand and want to continue** → **Create as a plugin** → sign in to Clane Vault, pick the agent, **Allow**. Your ChatGPT account and workspace policies decide whether custom MCP servers are allowed (some plans need developer mode or an admin's approval). Source: [OpenAI Apps SDK, connect from ChatGPT](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt).

**Claude Code**: `claude mcp add --transport http clane-vault https://vault.clane.ai/mcp`, then `/mcp` in Claude Code to sign in. Non-interactive, with an API token: `claude mcp add --transport http clane-vault https://vault.clane.ai/mcp --header "Authorization: Bearer cvat_…"`. Source: [Claude Code, MCP](https://code.claude.com/docs/en/mcp).

**Claude API** (Messages API MCP connector), with header `anthropic-beta: mcp-client-2025-11-20`. Both halves are required:

```json
{
  "model": "claude-opus-5-5",
  "max_tokens": 16000,
  "mcp_servers": [{ "type": "url", "url": "https://vault.clane.ai/mcp", "name": "clane-vault", "authorization_token": "cvat_…" }],
  "tools": [{ "type": "mcp_toolset", "mcp_server_name": "clane-vault" }],
  "messages": [{ "role": "user", "content": "Create a Stripe test customer for ACME." }]
}
```

Source: [Claude API, MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector).

**OpenAI Responses API** (remote MCP tool). `authorization` is the bare token, without `Bearer`:

```json
{
  "model": "<model>",
  "tools": [{ "type": "mcp", "server_label": "clane_vault", "server_url": "https://vault.clane.ai/mcp",
              "authorization": "cvat_…", "require_approval": "never" }],
  "input": "Create a Stripe test customer for ACME."
}
```

OpenAI doesn't store `authorization`: send it with every request. Source: [OpenAI, MCP and connectors](https://developers.openai.com/api/docs/guides/tools-connectors-mcp). (Checked 2026-10-18; these UIs change, so check the sources if a step doesn't match.)

## API tokens and OAuth

- **OAuth 2.1** (Claude.ai, ChatGPT, Claude Code): dynamic client registration, PKCE S256 only, authorization code bound to the agent, the client and the admin who allowed it. Access tokens are ES256 JWTs valid 15 minutes, for this gateway only; refresh tokens last 30 days and rotate, and reusing an old one revokes the grant. The Connect sheet lists each *Connected app* with who allowed it, and **Revoke** ends it at the gateway's next call. Client registration is rate-limited per address (10 an hour); registered clients that never connect aren't swept.
- **API tokens** (Claude API, OpenAI API, CI): **Create API token** shows `cvat_…` **once**; the server keeps only its hash. The gateway exchanges it for a 15-minute access token. Revoke a token in the Connect sheet; it stops at once.

Anyone holding a token can *use* the agent's credentials against the allowed hosts until it is revoked, as the agent could.

## Expiry and revocation

An expiry date ends access (`403 agent_expired`); the gateway drops its cache at once. **Revoke** removes the agent from every folder, group and share, ends every token and grant, deletes its wrapped key and drops the gateway's cache. The agent stays in the event log by name.

Revoke then lists **the folders and records the gateway could open for this agent: rotate the credentials in them.** The gateway could read those items while the agent was live, and folder keys aren't rotated on removal (`docs/sharing.md`, *Follow-ups*), so changing the credentials themselves is what closes it. Do the same for every agent-scoped credential after any suspected gateway incident.

Events: `agent.create`, `agent.verify`, `agent.update`, `agent.revoke`, `agent.token_create`, `agent.token_revoke`, `agent.grant`, `agent.grant_revoke`, `agent.sync` (at most hourly), `agent.expired`, and from the gateway `agent.use`, `agent.refused`, `agent.reflected` (record, host, method, reason; never paths, query strings, bodies or values). `agent.use` is reported by the gateway itself.

## Keys at rest: KMS or a file key

Each agent's private key is encrypted under its own random key (DEK), and the DEK is wrapped by the gateway's KEK. The result (`k1.…`) is stored in the API database, useless without the KEK. `GATEWAY_KEK` chooses the KEK:

**AWS KMS** (`aws-kms:<key ARN>`). A symmetric KMS key. The gateway uses the default AWS credential chain (instance or task role). Limit the key policy to the gateway's role, not to engineers, and require the encryption context the gateway sends: `orgId` and `agentId` for agent keys, `purpose` (`gateway-identity`) for its own identity key:

```json
{
  "Sid": "GatewayOnly",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account>:role/<gateway-role>" },
  "Action": ["kms:Encrypt", "kms:Decrypt"],
  "Resource": "*",
  "Condition": { "ForAllValues:StringEquals": { "kms:EncryptionContextKeys": ["orgId", "agentId", "purpose"] }, "Null": { "kms:EncryptionContextKeys": "false" } }
}
```

CloudTrail then logs every unwrap, with the org and agent: the operator-side audit trail.

**Google Cloud KMS** (`gcp-kms:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`). The gateway calls the Cloud KMS REST API with credentials from the metadata server (the attached service account, on GCE, GKE or Cloud Run). Grant that service account `roles/cloudkms.cryptoKeyEncrypterDecrypter` on this key only. The org and agent ids go in as additional authenticated data; Cloud Audit Logs record each call when data-access logging is on for Cloud KMS.

**File key** (`file:<path to 32 random bytes>`, the compose default). Weaker: the key sits on the same host as the gateway, so anyone who can read the host's disk or the secret file can unwrap every agent key whose ciphertext they also get from the database. There's no external audit trail of unwraps.

**Back up the KEK** (or keep the KMS key from being deleted) and the gateway's data volume (its identity key, wrapped under the KEK). **Lose the KEK and every agent must be re-enrolled**: revoke each one, create it again, verify it and share with it again. Nothing else is affected: people's data doesn't depend on it. A new KEK or a lost data volume also means a new gateway identity (see *A changed gateway identity*).

## Settings

On the **API** (`.env`). Agent access is off unless `GATEWAY_INTERNAL_URL` is set, and then the other three are required too, or the API won't start:

| Setting | |
|---|---|
| `GATEWAY_INTERNAL_URL` | The gateway's internal port, e.g. `http://gateway:3003`. |
| `GATEWAY_PUBLIC_URL` | The public MCP URL, e.g. `https://vault.example.com/mcp`. Must be **exactly** the gateway's `PUBLIC_URL`. |
| `GATEWAY_API_TOKEN` | Shared secret with the gateway, 32+ characters. |
| `AGENT_TOKEN_PRIVATE_KEY` | P-256 PKCS#8 PEM that signs agent access tokens (`\n` for newlines on one line). |
| `GATEWAY_ACCEPT_NEW_IDENTITY` | `true` accepts and pins a changed gateway identity. Default `false`. |

On the **gateway**:

| Setting | Default | |
|---|---|---|
| `API_URL` | | The API's origin plus base path. https, or plain http only to localhost or a private network name or address. |
| `GATEWAY_API_TOKEN` | | The same value as the API's. |
| `PUBLIC_URL` | | e.g. `https://vault.clane.ai/mcp`; its path is the MCP route. https (http only for localhost). |
| `GATEWAY_KEK` | | `aws-kms:<key arn>`, `gcp-kms:<resource name>` or `file:<path>`. |
| `GATEWAY_IDENTITY_KEY_FILE` | | Where the identity key is kept (wrapped under the KEK); created at first start. |
| `GATEWAY_CACHE_TTL_SECONDS` | 60 | How long an agent's opened key and sync data stay in memory. `0`: a KMS call per request. |
| `GATEWAY_AGENT_RATE_PER_MINUTE` | 60 | `http_request` calls per agent per minute. |
| `GATEWAY_MAX_RESPONSE_BYTES` | 4194304 | Response cap, after decompression; longer responses are cut and marked `truncated`. |
| `GATEWAY_UPSTREAM_TIMEOUT_MS` | 30000 | Total time for an outbound call, redirects included. |
| `GATEWAY_ALLOW_PRIVATE_CIDRS` | empty | Comma-separated CIDRs an agent may reach over `http`/`https` though private. Self-hosted only; never set on a hosted service. Metadata addresses stay blocked. |
| `PORT` | 3002 | Public: `/mcp` and its metadata. |
| `INTERNAL_PORT` | 3003 | `/internal/*` only (enrolment, cache drop, health), with `X-Gateway-Token`. **Never publish or proxy it.** |
| `INTERNAL_HOST` | 0.0.0.0 | Address the internal port binds to. |
| `TRUST_PROXY` | 0 | Number of reverse proxies in front (as on the API). |

Rules the gateway enforces at start: it refuses `NODE_OPTIONS`, any Node flag outside a short allowlist, and starting without `--disable-sigusr1` (SIGUSR1 would open the inspector). The image's command is `--disable-sigusr1 dist/server.js`; run it from source with `npm run dev -w @clane-vault/gateway`, which builds and then runs it the same way. A bad setting prints one line, `{"event":"config_error","msg":…}`, and exits 1. After changing the API's `PUBLIC_URL` (its OAuth issuer), restart the gateway.

**Limits**: `http_request` `GATEWAY_AGENT_RATE_PER_MINUTE` per agent; `list_secrets` 20 a minute per agent; 600 requests a minute per client address; 10 unknown API tokens a minute per address; 20 open MCP sessions per agent (idle ones close after 30 minutes); one call in flight per session; request bodies up to 1 MiB.

**Errors.** Bodies are `{ "error": "<code>" }`.

| Status | Code | Where |
|---|---|---|
| 400 | `agent_use_only` | Sharing more than *Use* with an agent. |
| 400 | `user_not_active` | Sharing with an agent that isn't verified yet. |
| 400 | `invalid_redirect_uri` | Consent page: the redirect URI isn't one the client registered. |
| 400 | `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `invalid_target` | OAuth (RFC 6749). |
| 401 | `invalid_client` | OAuth: unknown client. |
| 401 | `unauthorized` | Bad or revoked token or grant; gateway: with `WWW-Authenticate` (`error="invalid_token"` when a token was sent). |
| 402 | `agent_limit` (`used`, `allowed`) | Hosted: no free agent slot. |
| 403 | `agent_expired`, `agent_unverified` | The agent expired, or isn't verified. |
| 403 | `forbidden` | Gateway: an MCP session used with another agent's token. |
| 409 | `stale_key` | Verify: the key isn't the agent's current key. |
| 409 | `is_agent` | A People page action on an agent. |
| 409 | `agent_revoked` | Changing a revoked agent. |
| 429 | `rate_limited` | With `Retry-After`. |
| 503 | `gateway_unavailable` | The API can't reach the gateway; nothing was created. |
| 503 | `gateway_identity_changed` | The gateway identity changed; see above. |
| 503 | `api_unavailable` | Gateway: can't reach the API (with `Retry-After`). |

## Trust limits

- **The gateway operator can read agent-scoped items.** Hosted, that's Clane; self-hosted, it's you. While an agent is live, the gateway holds its wrapped key and the KEK, so it could decrypt any item shared with the agent at any time, not only at use time. Items never shared with an agent stay end-to-end encrypted.
- **A hijacked agent** (prompt injection) can't see a value, but can make legitimate-looking calls to an allowed host with bad intent. Narrow hosts, methods and paths, and give agents restricted credentials.
- **A host that re-encodes the secret** in a form the scrubber doesn't know can get it into a response, and so to the model provider.
- **Trust on first use** of the gateway identity, per user, as above.
- **JavaScript can't guarantee zeroing.** The gateway zeroes key and secret buffers after each call, but decrypted values also exist as JavaScript strings, which can't be zeroed, and the garbage collector may copy buffers. Core dumps, the inspector, heap snapshots and diagnostic reports are off. The real answer is running the gateway in an enclave (Phase 5), with an attestation your browser checks, so that not even the operator can read agent-scoped items.
