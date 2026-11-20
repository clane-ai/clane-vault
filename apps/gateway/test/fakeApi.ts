import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import {
  aeadEncrypt, b64url, decryptRecordBody, encryptFolderName, encryptRecordBody, generateKeyPair as generateX25519, openDepositKey, sealOrgFolderKey, sealOrgRecordShare,
  sealPersonalAgentRecordKey, sealReveal, sealRevealStub, serverRecordType, standingRevealTag, utf8, wrapKey, type RecordBody, type RecordType,
} from "@clane-vault/crypto";
import type { Kek } from "../src/kek.js";
import { wrapAgentKey, wrapPersonalAgentKey } from "../src/envelope.js";
import type { UseEvent } from "../src/apiClient.js";

/**
 * The API's /agent/* contract (plan Task 5) with real ciphertext: the agent key pair wrapped under the KEK, folder keys
 * sealed to the agent's key, bodies encrypted, ES256 access tokens and a JWKS. Routes live under `${url}/api/v1`; the AS metadata
 * (plan Task 12) at `${url}/.well-known/oauth-authorization-server`, naming a public `issuer` that is not `url` (as hosted).
 */
export async function startFakeApi(o: { kek: Kek; aud?: string; issuer?: string; metadataDown?: boolean }) {
  const orgId = randomUUID(), agentId = randomUUID(), ownerId = randomUUID(), tokenId = randomUUID();
  const agent2 = { id: randomUUID() }; // a second agent of the org: its tokens verify, it holds nothing
  const kp = await generateX25519();
  const publicKey = b64url.encode(kp.publicKey);
  const wrappedPrivateKey = await wrapAgentKey(o.kek, { orgId, agentId, publicKey }, kp.privateKey);
  kp.privateKey.fill(0);
  // A personal agent: its key wrapped under k2, bound to its owner's public key; records sealed to it one by one.
  const personalId = randomUUID(), personalOwnerId = randomUUID();
  const ownerKeys = await generateX25519(), pkp = await generateX25519();
  const personalPublicKey = b64url.encode(pkp.publicKey);
  let ownerPublicKey = b64url.encode(ownerKeys.publicKey);
  const personalWrapped = await wrapPersonalAgentKey(o.kek, { ownerUserId: personalOwnerId, ownerPublicKey, agentId: personalId, publicKey: personalPublicKey }, pkp.privateKey);
  pkp.privateKey.fill(0);
  type PersonalRecord = { id: string; encBody: string; revision: number; write: boolean; deletedAt: string | null; wrappedRecordKey: string };
  type Deposit = { id: string; type: string; encBody: string; revision: number; ownerSealedKey: string; agentSealedKey: string; signature: string };
  const personalRecords: PersonalRecord[] = [], recordKeys = new Map<string, Uint8Array>(), deposits: Deposit[] = [];
  /** Every write call the API received: method, path and parsed body. */
  const writes: { method: string; path: string; body: Record<string, unknown> }[] = [];
  let policyWrite = true, inboxFree: number | null = null, refuseWrites: string | null = null;
  // Reveal (Tasks 17, 18): stubs, the owner's policy, the requests the API received, and how the "owner" answers.
  const stubs: { recordId: string; sealedStub: string }[] = [];
  type RevealReq = { id: string; recordId: string; fields: string[]; reason: string; requestPublicKey: string; signature: string; expiresAt: string;
    status: "pending" | "approved" | "denied" | "expired" | "delivered"; sealed?: string };
  const reveals: RevealReq[] = [];
  let policyReveal: "off" | "approval" | "standing" = "off", refuseReveal: string | null = null, refuseStanding = false;
  let onReveal: ((r: RevealReq) => void | Promise<void>) | null = null;
  const signing = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(signing.publicKey)), alg: "ES256", use: "sig" };
  jwk.kid = await calculateJwkThumbprint(jwk);
  const token = randomBytes(32).toString("base64url"); // X-Gateway-Token
  const staticToken = `cvat_${tokenId}_${randomBytes(32).toString("base64url")}`;
  const aud = o.aud ?? "https://gw.test/mcp";
  const issuer = o.issuer ?? "https://vault.test/app";
  let metadataDown = o.metadataDown ?? false;
  const folders: { id: string; name: string; key: Uint8Array; encName: string; wrappedFolderKey: string }[] = [];
  const records: Record<string, unknown>[] = [];
  const events: UseEvent[] = [];
  const bodies: string[] = []; // every request body the API received
  let revoked = false, expired = false, syncCalls = 0, tokenCalls = 0;
  let url = "";

  /** `over` replaces claims (undefined removes one); `sub` (null removes it), `iss` and `exp` (a jose time span or epoch seconds) too. */
  const issueToken = (over: Record<string, unknown> & { sub?: unknown; iss?: string; exp?: string | number } = {}) => {
    const { sub = agentId, iss = issuer, exp = "15m", ...claims } = over;
    const now = Math.floor(Date.now() / 1000);
    if (typeof sub !== "string" && sub !== null) // jose won't sign a non-string sub; sign the payload as is
      return new CompactSign(new TextEncoder().encode(JSON.stringify({ scope: "agent", org: orgId, sub, aud, iss, iat: now, exp: now + 900, ...claims })))
        .setProtectedHeader({ alg: "ES256", kid: jwk.kid }).sign(signing.privateKey);
    const j = new SignJWT({ scope: "agent", org: orgId, grant: randomUUID(), ...claims }).setProtectedHeader({ alg: "ES256", kid: jwk.kid });
    if (sub !== null) j.setSubject(sub);
    return j.setAudience(aud).setIssuer(iss).setJti(randomUUID()).setIssuedAt().setExpirationTime(exp).sign(signing.privateKey);
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

  /**
   * `sealFor`: the agent id in the seal's AAD (another one makes a record this agent can't open). `raw`: encrypted as given, not normalised.
   * `tagBy`: agentReveal gets a tag for each listed agent, made with the owner's key or an editor's (one that isn't the owner's).
   */
  async function addPersonalRecord(body: RecordBody, sealFor = personalId, write = false, raw = false, tagBy?: "owner" | "editor"): Promise<string> {
    const id = randomUUID(), recordKey = new Uint8Array(randomBytes(32));
    if (tagBy && body.agentReveal) {
      const signer = tagBy === "owner" ? ownerKeys.privateKey : (await generateX25519()).privateKey, ar = body.agentReveal;
      body = { ...body, agentReveal: { ...ar, auth: Object.fromEntries(await Promise.all(ar.agents.map(async (a) =>
        [a, await standingRevealTag(signer, pkp.publicKey, { recordId: id, agentId: a, fields: ar.fields })] as const))) } };
    }
    recordKeys.set(id, recordKey);
    const encBody = raw ? await aeadEncrypt(recordKey, utf8.encode(JSON.stringify(body)), `record-body:${id}`) : await encryptRecordBody(id, body, recordKey);
    personalRecords.push({ id, encBody, revision: 1, write, deletedAt: null,
      wrappedRecordKey: await sealPersonalAgentRecordKey(recordKey, { ownerUserId: personalOwnerId, agentId: sealFor, recordId: id }, pkp.publicKey) });
    return id;
  }

  const personalSyncBody = () => ({
    owner: { userId: personalOwnerId, publicKey: ownerPublicKey }, agentId: personalId, publicKey: personalPublicKey, wrappedPrivateKey: personalWrapped,
    kekId: o.kek.id, expiresAt: null, records: personalRecords, reveal: policyReveal === "off" ? [] : stubs,
    deposits: deposits.map(({ id, encBody, revision, agentSealedKey, signature }) => ({ id, encBody, revision, agentSealedKey, signature })),
    inboxFree: inboxFree ?? 100 - deposits.length, policy: { write: policyWrite, reveal: policyReveal },
  });

  /** The API's /agent/deposits and /agent/records/:id: every business refusal is 409 { error }. */
  async function agentWrite(req: IncomingMessage, res: ServerResponse, path: string, sub: unknown) {
    const b = JSON.parse(await read(req)) as Record<string, unknown>;
    writes.push({ method: req.method ?? "", path, body: b });
    const refuse = (error: string) => send(res, 409, { error });
    if (refuseWrites) return refuse(refuseWrites);
    if (sub !== personalId || !policyWrite) return refuse("not_writable");
    if (req.method === "POST" && path === "/agent/deposits") {
      deposits.push({ ...(b as Deposit), revision: 1 });
      return send(res, 201, { id: b.id, revision: 1 });
    }
    const m = /^\/agent\/(deposits|records)\/([^/]+)$/.exec(path);
    const row = m && (m[1] === "deposits" ? deposits : personalRecords).find((x) => x.id === m[2]);
    if (req.method !== "PUT" || !row || (m[1] === "records" && !(row as PersonalRecord).write)) return refuse("not_writable");
    if (row.revision !== b.revision) return refuse("conflict");
    Object.assign(row, { encBody: b.encBody, revision: row.revision + 1 }, m[1] === "deposits" ? { signature: b.signature } : {});
    return send(res, 200, { id: row.id, revision: row.revision });
  }

  /** POST /agent/reveals and GET /agent/reveals/:id: refusals are 409 { error }; another agent's request is 404. */
  async function agentReveal(req: IncomingMessage, res: ServerResponse, path: string, sub: unknown) {
    if (sub !== personalId) return send(res, 409, { error: "reveal_off" });
    if (req.method === "POST" && path === "/agent/reveals/standing") {
      const b = JSON.parse(await read(req)) as Record<string, unknown>;
      writes.push({ method: "POST", path, body: b });
      return refuseStanding ? send(res, 409, { error: "reveal_off" }) : send(res, 201, { ok: true });
    }
    if (req.method === "POST" && path === "/agent/reveals") {
      const b = JSON.parse(await read(req)) as RevealReq;
      writes.push({ method: "POST", path, body: b as unknown as Record<string, unknown> });
      if (refuseReveal) return send(res, 409, { error: refuseReveal });
      const r: RevealReq = { ...b, status: "pending" };
      reveals.push(r);
      send(res, 201, { id: b.id, expiresAt: b.expiresAt });
      await onReveal?.(r);
      return;
    }
    const m = /^\/agent\/reveals\/([^/]+)$/.exec(path);
    const r = m && req.method === "GET" ? reveals.find((x) => x.id === m[1]) : undefined;
    if (!r) return send(res, 404, { error: "not_found" });
    if (r.status === "approved") { const sealed = r.sealed; r.status = "delivered"; delete r.sealed; return send(res, 200, { status: "approved", sealed }); }
    return send(res, 200, { status: r.status === "delivered" ? "expired" : r.status });
  }
  /** The owner's browser: seal these fields to the request's key (as the web app does on Allow once). `sealer`: another key, to forge one. */
  async function approveReveal(id: string, fields: Record<string, string>, sealer: Uint8Array = ownerKeys.privateKey) {
    const r = reveals.find((x) => x.id === id)!;
    r.sealed = await sealReveal(fields, { requestId: r.id, recordId: r.recordId, agentId: personalId }, b64url.decode(r.requestPublicKey), sealer);
    r.status = "approved";
  }

  const send = (res: ServerResponse, status: number, body?: unknown) => {
    res.writeHead(status, { "content-type": "application/json" }).end(body === undefined ? undefined : JSON.stringify(body));
  };
  const read = async (req: IncomingMessage) => { let s = ""; for await (const c of req) s += c; bodies.push(s); return s; };
  // requireAgent's order: gateway token, access token, agent state, expiry.
  async function agentAuth(req: IncomingMessage): Promise<number | { sub: unknown }> {
    if (req.headers["x-gateway-token"] !== token) return 401;
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    let sub: unknown;
    try { sub = (await jwtVerify(bearer ?? "", signing.publicKey, { issuer, audience: aud, algorithms: ["ES256"] })).payload.sub; } catch { return 401; }
    return revoked ? 401 : expired ? 403 : { sub };
  }

  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", url).pathname.replace(/^\/api\/v1/, "");
    if (req.method === "GET" && path === "/.well-known/oauth-authorization-server")
      return metadataDown ? send(res, 503, { error: "unavailable" }) : send(res, 200, { issuer, jwks_uri: `${issuer}/api/v1/.well-known/jwks.json` });
    if (req.method === "GET" && path === "/.well-known/jwks.json") return send(res, 200, { keys: [jwk] });
    if (req.method === "POST" && path === "/oauth/token") {
      tokenCalls++;
      if (req.headers["x-gateway-token"] !== token) return send(res, 401, { error: "invalid_client" });
      const f = new URLSearchParams(await read(req));
      if (f.get("grant_type") !== "urn:clane:agent-token") return send(res, 400, { error: "unsupported_grant_type" });
      if (f.get("token") !== staticToken || revoked) return send(res, 400, { error: "invalid_grant" });
      return send(res, 200, { access_token: await issueToken({ grant: tokenId }), token_type: "Bearer", expires_in: 900 });
    }
    if (path === "/agent/deposits" || path.startsWith("/agent/deposits/") || path.startsWith("/agent/records/")) {
      const a = await agentAuth(req);
      if (typeof a === "number") return send(res, a, { error: a === 401 ? "unauthorized" : "agent_expired" });
      return agentWrite(req, res, path, a.sub);
    }
    if (path === "/agent/reveals" || path.startsWith("/agent/reveals/")) {
      const a = await agentAuth(req);
      if (typeof a === "number") return send(res, a, { error: a === 401 ? "unauthorized" : "agent_expired" });
      return agentReveal(req, res, path, a.sub);
    }
    if (path === "/agent/sync" || path === "/agent/events") {
      const a = await agentAuth(req);
      if (typeof a === "number") return send(res, a, { error: a === 401 ? "unauthorized" : "agent_expired" });
      if (req.method === "GET" && path === "/agent/sync") { syncCalls++; return send(res, 200, a.sub === personalId ? personalSyncBody() : syncBody()); }
      if (req.method === "POST") { events.push(...(JSON.parse(await read(req)) as { events: UseEvent[] }).events); return send(res, 200, { ok: true }); }
    }
    send(res, 404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    url, issuer, token, staticToken, events, bodies, kid: jwk.kid!, agent: { id: agentId, orgId, publicKey }, agent2,
    addFolderRecord, addSharedRecord, issueToken,
    /** A personal agent: its tokens carry `owner` and no `org`; its sync is a PersonalAgentSync. */
    personal: {
      agentId: personalId, ownerId: personalOwnerId, ownerKeys, publicKey: personalPublicKey,
      token: (over: Record<string, unknown> = {}) => issueToken({ sub: personalId, org: undefined, owner: personalOwnerId, ...over }),
      addRecord: addPersonalRecord,
      records: personalRecords, deposits, writes,
      /** A stored body as its owner reads it: a deposit through ownerSealedKey and the owner's key, a record with its record key. */
      async open(id: string): Promise<RecordBody> {
        const d = deposits.find((x) => x.id === id);
        if (d) return decryptRecordBody(id, d.encBody, await openDepositKey(d.ownerSealedKey, { ownerUserId: personalOwnerId, id }, ownerKeys));
        const r = personalRecords.find((x) => x.id === id)!;
        return decryptRecordBody(id, r.encBody, recordKeys.get(id)!);
      },
      /** The owner's policies (write), the inbox space the API reports (null: 100 minus this agent's deposits), a 409 for every write. */
      setPolicyWrite(v: boolean) { policyWrite = v; },
      setInboxFree(n: number | null) { inboxFree = n; },
      refuseWrites(error: string | null) { refuseWrites = error; },
      /** What the API reports as the owner's key from now on (the wrapped key stays bound to the first). */
      setOwnerPublicKey(b64: string) { ownerPublicKey = b64; },
      /** *Can reveal*: a stub sealed to the agent for `recordId` (a record it holds, or none: then the item is reveal-only). */
      async addStub(fields: string[], o: { recordId?: string; title?: string; type?: RecordType } = {}): Promise<string> {
        const recordId = o.recordId ?? randomUUID();
        stubs.push({ recordId, sealedStub: await sealRevealStub({ title: o.title ?? "Revealable", type: o.type ?? "login", fields },
          { ownerUserId: personalOwnerId, agentId: personalId, recordId }, pkp.publicKey) });
        return recordId;
      },
      stubs, reveals, approveReveal,
      setPolicyReveal(m: "off" | "approval" | "standing") { policyReveal = m; },
      refuseReveal(error: string | null) { refuseReveal = error; },
      /** POST /agent/reveals/standing answers 409 reveal_off while set. */
      refuseStanding(v: boolean) { refuseStanding = v; },
      /** Called once the API has answered a new request's POST. */
      onReveal(f: ((r: RevealReq) => void | Promise<void>) | null) { onReveal = f; },
    },
    get syncCalls() { return syncCalls; },
    get tokenCalls() { return tokenCalls; },
    revoke() { revoked = true; },
    expire() { expired = true; },
    /** The metadata route answers 503 while set. */
    set metadataDown(v: boolean) { metadataDown = v; },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
