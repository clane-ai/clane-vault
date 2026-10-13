import {
  configureKdfFloor, createAccount, createMembershipKeys, decryptRecordBody, encryptFolderName, encryptNewRecord, randomBytes, sealOrgFolderKey, sealOrgRecordShare,
  serverRecordType, unwrapKey, wrapKey, type AccountMaterial, type KdfParams, type MembershipKeyMaterial, type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
import type { KV, Platform } from "../src/background/core";
import type { FillResult } from "../src/shared/forms";

configureKdfFloor({ m: 1024, t: 1 });
export const FAST_KDF: KdfParams = { alg: "argon2id", m: 1024, t: 1, p: 1 };
export const PASSWORD = "correct horse battery staple";
export const EMAIL = "ana@example.com";
export const ORG = "11111111-1111-4111-8111-111111111111";
export const ORG2 = "22222222-2222-4222-8222-222222222222";

interface Rec { id: string; type?: string; encBody: string; wrappedRecordKey: string; permission: string; ownerId: string; revision: number; orgId?: string; sealedTo?: string; holderType?: "user" | "folder"; folderId?: string }
interface TeamFolder { id: string; orgId: string; encName: string; wrappedFolderKey: string; sealedTo: string }

/** A small in-memory stand-in for the API: the auth routes, /sync and record writes. */
export async function fakeApi() {
  const acct = await createAccount(PASSWORD, FAST_KDF);
  const user = { id: "u-1", email: EMAIL, name: "Ana" };
  const records: Rec[] = [];
  const s = { access: "a0", refresh: "r0", seq: 0, requireCode: true, ssoOrg: null as string | null, calls: [] as { method: string; path: string; search: string; body: unknown; headers: Record<string, string>; url: string }[] };
  const orgs: { id: string; name: string; slug: string; role: string; isDefault: boolean; policies?: Record<string, unknown> }[] =
    [{ id: ORG, name: "Acme", slug: "acme", role: "member", isDefault: true }, { id: ORG2, name: "Beta", slug: "beta", role: "member", isDefault: false }];

  async function add(body: RecordBody, opts: { permission?: string; ownerId?: string } = {}) {
    const id = crypto.randomUUID();
    const e = await encryptNewRecord(id, body, acct.keys.userKey);
    records.push({ id, type: serverRecordType(body), encBody: e.encBody, wrappedRecordKey: e.wrappedRecordKey, permission: opts.permission ?? "owner", ownerId: opts.ownerId ?? user.id, revision: 1 });
    return id;
  }
  // Per-org key pairs: my membership key in an org, and what other members share with me there (sealed to it).
  const mkeys = new Map<string, MembershipKeyMaterial>();
  const teamFolders: TeamFolder[] = [];
  async function membershipKey(orgId: string) {
    let m = mkeys.get(orgId);
    if (!m) { m = (await createMembershipKeys(acct.keys.userKey, { orgId, userId: user.id })).material; mkeys.set(orgId, m); }
    return m;
  }
  /** A record someone else shared with me in `orgId`, sealed to my membership key there. */
  async function addOrgShare(body: RecordBody, orgId: string) {
    const id = crypto.randomUUID();
    const e = await encryptNewRecord(id, body, randomBytes(32));
    const m = await membershipKey(orgId);
    const { b64url } = await import("@clane-vault/crypto");
    records.push({ id, encBody: e.encBody, wrappedRecordKey: await sealOrgRecordShare(e.recordKey, { orgId, recordId: id }, b64url.decode(m.publicKey)), permission: "view", ownerId: "u-2", revision: 1, orgId, sealedTo: m.publicKey });
    return id;
  }
  /** A team folder in `orgId` whose key is sealed to my membership key, with one record in it. */
  async function addTeamRecord(body: RecordBody, orgId: string) {
    const folderId = crypto.randomUUID(), id = crypto.randomUUID();
    const fk = randomBytes(32);
    const m = await membershipKey(orgId);
    const { b64url } = await import("@clane-vault/crypto");
    teamFolders.push({ id: folderId, orgId, encName: await encryptFolderName(folderId, "Ops", fk), wrappedFolderKey: await sealOrgFolderKey(fk, { orgId, folderId }, b64url.decode(m.publicKey)), sealedTo: m.publicKey });
    const e = await encryptNewRecord(id, body, randomBytes(32));
    records.push({ id, encBody: e.encBody, wrappedRecordKey: await wrapKey(e.recordKey, fk, `record-key:${id}`), permission: "edit", ownerId: "u-2", revision: 1, orgId, holderType: "folder", folderId });
    return id;
  }
  async function bodyOf(id: string) {
    const r = records.find((x) => x.id === id)!;
    const rk = await unwrapKey(r.wrappedRecordKey, acct.keys.userKey, `record-key:${id}`);
    return decryptRecordBody(id, r.encBody, rk);
  }

  const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const authView = () => ({ accessToken: s.access, user, material: acct.material as AccountMaterial, orgs });
  const rotate = () => { s.seq++; s.access = `a${s.seq}`; s.refresh = `r${s.seq}`; };

  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    // The server may live under a path (https://host/vault): the API is wherever /api/v1 starts.
    const path = url.pathname.replace(/^(\/[^/]+)*?\/api\/v1/, "");
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined;
    s.calls.push({ method, path, search: url.search, body, headers, url: url.href });
    const authed = headers.authorization === `Bearer ${s.access}`;
    if (path === "/auth/prelogin") return json(200, { kdfSalt: acct.material.kdfSalt, kdfParams: acct.material.kdfParams });
    if (path === "/auth/login") {
      if (body?.email !== EMAIL || body.authKey !== acct.authKey) return json(401, { error: "invalid_credentials" });
      if (s.requireCode && !body.code) return json(401, { error: "totp_required" });
      if (body.client !== "extension") return json(400, { error: "expected extension client" });
      rotate();
      return json(200, { ...authView(), refreshToken: s.refresh });
    }
    if (path === "/auth/refresh") {
      if (body?.refreshToken !== s.refresh) return json(401, { error: "session_expired" });
      rotate();
      return json(200, { ...authView(), refreshToken: s.refresh });
    }
    if (path === "/auth/logout") { s.refresh = "revoked"; return new Response(null, { status: 204 }); }
    if (!authed) return json(401, { error: "unauthorized" });
    const org = headers["x-org-id"];
    if (org && s.ssoOrg === org) return json(403, { error: "sso_required", orgId: org });
    if (path === "/auth/totp/step-up") return json(200, { ok: true });
    if (path === "/sync") {
      // Spaces: no X-Org-Id = Personal (my own records); ?space=org = that org's only; X-Org-Id alone = both (older clients).
      const orgOnly = url.searchParams.get("space") === "org";
      const inOrg = (o?: string) => (org ? (o ? o === org : !orgOnly) : !o);
      const mk = org ? mkeys.get(org) : undefined;
      return json(200, { serverTime: new Date().toISOString(), ...(org ? { orgId: org, membershipKeys: mk ? [{ ...mk, state: "current" }] : [] } : {}),
        folders: teamFolders.filter((f) => f.orgId === org).map((f) => ({ id: f.id, kind: "team", encName: f.encName, ownerId: "u-2", deletedAt: null, wrappedFolderKey: f.wrappedFolderKey, sealedTo: f.sealedTo, myPermission: "edit", members: [], groups: [] })),
        records: records.filter((r) => inOrg(r.orgId)).map((r) => ({
          id: r.id, folderId: r.folderId ?? null, type: r.type ?? "login", encBody: r.encBody, revision: r.revision, updatedAt: new Date().toISOString(), deletedAt: null,
          permission: r.permission, wrappedRecordKey: r.wrappedRecordKey, holderType: r.holderType ?? "user", keyFolderId: r.folderId ?? null, ownerId: r.ownerId,
          ...(r.sealedTo ? { sealedTo: r.sealedTo } : {}),
          // Servers from 1.6 list files on records (docs/attachments.md); the extension ignores them.
          attachments: [{ id: "00000000-0000-4000-8000-0000000000aa", encMeta: "v1.AAAA", wrappedFileKey: "v1.AAAA", nonceBase: "AAAAAAAAAAA", size: 26, chunkSize: 1048576, chunkCount: 1,
            createdBy: r.ownerId, createdByName: "Someone", createdAt: new Date().toISOString() }] })) });
    }
    if (path === "/records" && method === "POST") {
      const b = body as { id: string; type: string; encBody: string; wrappedRecordKey: string; folderId: null };
      records.push({ id: b.id, type: b.type, encBody: b.encBody, wrappedRecordKey: b.wrappedRecordKey, permission: "owner", ownerId: user.id, revision: 1 });
      return json(201, { id: b.id, revision: 1 });
    }
    const m = /^\/records\/([^/]+)$/.exec(path);
    if (m && method === "PUT") {
      const r = records.find((x) => x.id === m[1]);
      if (!r) return json(404, { error: "not_found" });
      if ((body as { revision: number }).revision !== r.revision) return json(409, { error: "conflict" });
      r.encBody = (body as { encBody: string }).encBody; r.revision++;
      if ((body as { type?: string }).type) r.type = (body as { type: string }).type;
      return json(200, { revision: r.revision });
    }
    return json(404, { error: "not_found" });
  }) as typeof globalThis.fetch;

  return { fetch, s, records, orgs, add, addOrgShare, addTeamRecord, bodyOf, keys: acct.keys as UnlockedKeys, user };
}

export function memoryKV(): KV & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    get: async <T,>(k: string) => (data.has(k) ? structuredClone(data.get(k)) as T : undefined),
    set: async (k, v) => { data.set(k, structuredClone(v)); },
    remove: async (k) => { data.delete(k); },
  };
}

/** A platform with in-memory storage, a fixed clock and recorded fills. */
export function fakePlatform(fetch: typeof globalThis.fetch, tabs: Record<number, string> = {}) {
  const clock = { t: 1_800_000_000_000 };
  const fills: { tabId: number; origin: string; username: string | null; password: string | null }[] = [];
  const alarms: number[] = [];
  let clipboardClears = 0;
  const p: Platform & { session: ReturnType<typeof memoryKV>; local: ReturnType<typeof memoryKV> } = {
    session: memoryKV(), local: memoryKV(), fetch, now: () => clock.t,
    tabUrl: async (id) => tabs[id],
    fill: async (tabId, origin, username, password): Promise<FillResult> => { fills.push({ tabId, origin, username, password }); return { ok: true, filled: ["username", "password"] }; },
    armAutoLock: (m) => { alarms.push(m); },
    scheduleClipboardClear: () => { clipboardClears++; },
  };
  return { p, clock, fills, alarms, tabs, clipboardClears: () => clipboardClears };
}
