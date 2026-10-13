import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";

/**
 * A minimal OpenID Connect provider for tests (API tests and the e2e run): discovery, JWKS, an authorization endpoint
 * that signs the user in at once (no login page) and a token endpoint that checks the client secret, the redirect URI
 * and PKCE (S256) before issuing an RS256 id_token. Who signs in: the `login_hint` user if registered, else `next`.
 * `tamper` changes the next id_token (wrong audience, nonce, issuer, expired, extra claims) to test validation.
 */
export interface MockUser { sub: string; email: string; email_verified?: boolean; name?: string; [claim: string]: unknown }
export interface MockClient { id: string; secret: string; redirectUris: string[] }
export interface Tamper { aud?: string; nonce?: string; iss?: string; expired?: boolean; claims?: Record<string, unknown>;
  /** Sign with a key that isn't in the JWKS (same kid). */ badKey?: boolean }

export class MockOidc {
  readonly users = new Map<string, MockUser>();
  readonly clients = new Map<string, MockClient>();
  next: MockUser | null = null;
  tamper: Tamper | null = null;
  /** Every token request (for assertions). */
  readonly tokenRequests: { clientId: string; ok: boolean }[] = [];
  private codes = new Map<string, { clientId: string; redirectUri: string; challenge: string; nonce?: string; user: MockUser; used: boolean }>();
  private server!: Server;
  private key!: { privateKey: CryptoKey; jwk: JWK };
  issuer = "";

  async start(port = 0, host = "127.0.0.1"): Promise<this> {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    this.key = { privateKey, jwk: { ...(await exportJWK(publicKey)), kid: "mock-1", alg: "RS256", use: "sig" } };
    this.server = createServer((req, res) => { void this.handle(req, res).catch(() => { res.statusCode = 500; res.end(); }); });
    await new Promise<void>((r) => this.server.listen(port, host, r));
    this.issuer = `http://${host}:${(this.server.address() as AddressInfo).port}`;
    return this;
  }
  stop(): Promise<void> { return new Promise((r) => { this.server.closeAllConnections?.(); this.server.close(() => r()); }); }

  addClient(c: MockClient) { this.clients.set(c.id, c); return c; }
  addUser(u: MockUser) { this.users.set(u.email.toLowerCase(), u); return u; }

  private json(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? "/", this.issuer);
    if (url.pathname === "/.well-known/openid-configuration") return this.json(res, 200, {
      issuer: this.issuer, authorization_endpoint: `${this.issuer}/authorize`, token_endpoint: `${this.issuer}/token`, jwks_uri: `${this.issuer}/jwks`,
      response_types_supported: ["code"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "email", "profile"], token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      code_challenge_methods_supported: ["S256"], claims_supported: ["sub", "email", "email_verified", "name"],
    });
    if (url.pathname === "/jwks") return this.json(res, 200, { keys: [this.key.jwk] });
    if (url.pathname === "/authorize") {
      const q = url.searchParams;
      const client = this.clients.get(q.get("client_id") ?? "");
      const redirectUri = q.get("redirect_uri") ?? "";
      if (!client || !client.redirectUris.includes(redirectUri)) return this.json(res, 400, { error: "invalid_request", error_description: "unknown client or redirect_uri" });
      if (q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") || !(q.get("scope") ?? "").split(" ").includes("openid"))
        return this.json(res, 400, { error: "invalid_request" });
      const user = this.users.get((q.get("login_hint") ?? "").toLowerCase()) ?? this.next;
      const back = new URL(redirectUri);
      if (!user) { back.searchParams.set("error", "access_denied"); back.searchParams.set("state", q.get("state") ?? ""); }
      else {
        const code = randomBytes(16).toString("base64url");
        this.codes.set(code, { clientId: client.id, redirectUri, challenge: q.get("code_challenge")!, ...(q.get("nonce") ? { nonce: q.get("nonce")! } : {}), user, used: false });
        back.searchParams.set("code", code);
        if (q.get("state")) back.searchParams.set("state", q.get("state")!);
      }
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let raw = "";
      for await (const c of req) raw += String(c);
      const p = new URLSearchParams(raw);
      let clientId = p.get("client_id") ?? "", secret = p.get("client_secret") ?? "";
      const basic = /^Basic (.+)$/.exec(req.headers.authorization ?? "");
      if (basic) { const [i, s] = Buffer.from(basic[1]!, "base64").toString().split(":"); clientId = decodeURIComponent(i ?? ""); secret = decodeURIComponent(s ?? ""); }
      const client = this.clients.get(clientId);
      if (!client || client.secret !== secret) { this.tokenRequests.push({ clientId, ok: false }); return this.json(res, 401, { error: "invalid_client" }); }
      const c = this.codes.get(p.get("code") ?? "");
      const verifier = p.get("code_verifier") ?? "";
      if (p.get("grant_type") !== "authorization_code" || !c || c.used || c.clientId !== clientId || c.redirectUri !== p.get("redirect_uri")
        || createHash("sha256").update(verifier).digest("base64url") !== c.challenge) {
        this.tokenRequests.push({ clientId, ok: false });
        return this.json(res, 400, { error: "invalid_grant" });
      }
      c.used = true;
      const t = this.tamper; this.tamper = null;
      const now = Math.floor(Date.now() / 1000);
      const { sub, ...claims } = c.user;
      const nonce = t?.nonce ?? c.nonce;
      const idToken = await new SignJWT({ ...claims, ...(nonce ? { nonce } : {}), ...(t?.claims ?? {}) })
        .setProtectedHeader({ alg: "RS256", kid: "mock-1" }).setIssuer(t?.iss ?? this.issuer).setAudience(t?.aud ?? clientId).setSubject(sub)
        .setIssuedAt(t?.expired ? now - 7200 : now).setExpirationTime(t?.expired ? now - 3600 : now + 300).sign(t?.badKey ? (await generateKeyPair("RS256")).privateKey : this.key.privateKey);
      this.tokenRequests.push({ clientId, ok: true });
      return this.json(res, 200, { access_token: randomBytes(16).toString("base64url"), token_type: "Bearer", expires_in: 300, id_token: idToken });
    }
    return this.json(res, 404, { error: "not_found" });
  }
}
