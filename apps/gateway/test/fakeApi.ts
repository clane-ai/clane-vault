import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import {
  b64url, encryptFolderName, encryptRecordBody, generateKeyPair as generateX25519, sealOrgFolderKey, sealOrgRecordShare, serverRecordType,
  wrapKey, type RecordBody,
} from "@clane-vault/crypto";
import type { Kek } from "../src/kek.js";
import { wrapAgentKey } from "../src/envelope.js";
import type { UseEvent } from "../src/apiClient.js";

/**
 * The API's /agent/* contract (plan Task 5) with real ciphertext: the agent key pair wrapped under the KEK, folder keys
 * sealed to the agent's key, bodies encrypted, ES256 access tokens and a JWKS. Routes live under `${url}/api/v1`.
 */
export async function startFakeApi(o: { kek: Kek; aud?: string }) {
  const orgId = randomUUID(), agentId = randomUUID(), ownerId = randomUUID(), tokenId = randomUUID();
  const agent2 = { id: randomUUID() }; // a second agent of the org: its tokens verify, it holds nothing
  const kp = await generateX25519();
  const publicKey = b64url.encode(kp.publicKey);
  const wrappedPrivateKey = await wrapAgentKey(o.kek, { orgId, agentId, publicKey }, kp.privateKey);
  kp.privateKey.fill(0);
  const signing = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(signing.publicKey)), alg: "ES256", use: "sig" };
  jwk.kid = await calculateJwkThumbprint(jwk);
  const token = randomBytes(32).toString("base64url"); // X-Gateway-Token
  const staticToken = `cvat_${tokenId}_${randomBytes(32).toString("base64url")}`;
  const aud = o.aud ?? "https://gw.test/mcp";
  const folders: { id: string; name: string; key: Uint8Array; encName: string; wrappedFolderKey: string }[] = [];
  const records: Record<string, unknown>[] = [];
  const events: UseEvent[] = [];
  const bodies: string[] = []; // every request body the API received
  let revoked = false, expired = false, syncCalls = 0, tokenCalls = 0;
  let url = "";

  /** `over` replaces claims (undefined removes one); `sub` and `exp` (a jose time span or epoch seconds) too. */
  const issueToken = (over: Record<string, unknown> & { sub?: string; exp?: string | number } = {}) => {
    const { sub = agentId, exp = "15m", ...claims } = over;
    return new SignJWT({ scope: "agent", org: orgId, grant: randomUUID(), ...claims }).setProtectedHeader({ alg: "ES256", kid: jwk.kid })
      .setSubject(sub).setAudience(aud).setIssuer(url).setJti(randomUUID()).setIssuedAt().setExpirationTime(exp).sign(signing.privateKey);
  };

  const record = (id: string, body: RecordBody, encBody: string, holder: Record<string, unknown>) => ({
    id, type: serverRecordType(body), encBody, revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission: "use",
    ...holder, ownerId, ownerName: "Owner", attachments: [],
  });

  async function addFolderRecord(folderName: string, body: RecordBody): Promise<string> {
    let f = folders.find((x) => x.name === folderName);
    if (!f) {
      const id = randomUUID(), key = new Uint8Array(randomBytes(32));
      f = { id, name: folderName, key, encName: await encryptFolderName(id, folderName, key), wrappedFolderKey: await sealOrgFolderKey(key, { orgId, folderId: id }, kp.publicKey) };
      folders.push(f);
    }
    const id = randomUUID(), recordKey = new Uint8Array(randomBytes(32));
    records.push(record(id, body, await encryptRecordBody(id, body, recordKey), {
      folderId: f.id, holderType: "folder", wrappedRecordKey: await wrapKey(recordKey, f.key, `record-key:${id}`), keyFolderId: f.id }));
    return id;
  }

  async function addSharedRecord(body: RecordBody): Promise<string> {
    const id = randomUUID(), recordKey = new Uint8Array(randomBytes(32));
    records.push(record(id, body, await encryptRecordBody(id, body, recordKey), {
      folderId: null, holderType: "user", wrappedRecordKey: await sealOrgRecordShare(recordKey, { orgId, recordId: id }, kp.publicKey), keyFolderId: null, sealedTo: publicKey }));
    return id;
  }

  const syncBody = () => ({
    serverTime: new Date().toISOString(), orgId, membershipKeys: [{ publicKey, wrappedPrivateKey: "", state: "current" }],
    folders: folders.map((f) => ({ id: f.id, kind: "team", encName: f.encName, ownerId, deletedAt: null, wrappedFolderKey: f.wrappedFolderKey, sealedTo: publicKey,
      myPermission: "use", members: [], groups: [] })),
    records, wrappedPrivateKey, kekId: o.kek.id, expiresAt: null, entitlements: { approvals: false },
  });

  const send = (res: ServerResponse, status: number, body?: unknown) => {
    res.writeHead(status, { "content-type": "application/json" }).end(body === undefined ? undefined : JSON.stringify(body));
  };
  const read = async (req: IncomingMessage) => { let s = ""; for await (const c of req) s += c; bodies.push(s); return s; };
  // requireAgent's order: gateway token, access token, agent state, expiry.
  async function agentAuth(req: IncomingMessage): Promise<number | null> {
    if (req.headers["x-gateway-token"] !== token) return 401;
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    try { await jwtVerify(bearer ?? "", signing.publicKey, { issuer: url, audience: aud, algorithms: ["ES256"] }); } catch { return 401; }
    return revoked ? 401 : expired ? 403 : null;
  }

  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", url).pathname.replace(/^\/api\/v1/, "");
    if (req.method === "GET" && path === "/.well-known/jwks.json") return send(res, 200, { keys: [jwk] });
    if (req.method === "POST" && path === "/oauth/token") {
      tokenCalls++;
      if (req.headers["x-gateway-token"] !== token) return send(res, 401, { error: "invalid_client" });
      const f = new URLSearchParams(await read(req));
      if (f.get("grant_type") !== "urn:clane:agent-token") return send(res, 400, { error: "unsupported_grant_type" });
      if (f.get("token") !== staticToken || revoked) return send(res, 400, { error: "invalid_grant" });
      return send(res, 200, { access_token: await issueToken({ grant: tokenId }), token_type: "Bearer", expires_in: 900 });
    }
    if (path === "/agent/sync" || path === "/agent/events") {
      const refused = await agentAuth(req);
      if (refused) return send(res, refused, { error: refused === 401 ? "unauthorized" : "agent_expired" });
      if (req.method === "GET" && path === "/agent/sync") { syncCalls++; return send(res, 200, syncBody()); }
      if (req.method === "POST") { events.push(...(JSON.parse(await read(req)) as { events: UseEvent[] }).events); return send(res, 200, { ok: true }); }
    }
    send(res, 404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    url, token, staticToken, events, bodies, kid: jwk.kid!, agent: { id: agentId, orgId, publicKey }, agent2,
    addFolderRecord, addSharedRecord, issueToken,
    get syncCalls() { return syncCalls; },
    get tokenCalls() { return tokenCalls; },
    revoke() { revoked = true; },
    expire() { expired = true; },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
