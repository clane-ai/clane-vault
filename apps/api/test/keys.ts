import type { FastifyInstance } from "fastify";
import { expect } from "vitest";
import {
  b64url, createAccount, createMembershipKeys, createMembershipRecoveryGrant, openMembershipEscrow, openMembershipRecoveryGrant, resealFolderKeyToMembership,
  resealRecordShareToMembership, sealMembershipEscrow, unlockMembershipKeys, wrapMembershipKeys, type MembershipKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import { FAST_KDF } from "./helpers.js";

/**
 * Test clients for membership keys (docs/design/2026-10-08-per-org-keypairs.md): what the web client does on
 * unlock (create the key, move rows to it, escrow), what an admin's client does to approve, and the scoped reset.
 */
export interface KeyUser { id: string; accessToken: string; orgId: string; keys: UnlockedKeys; totpSecret: string; email: string }
type T = { app: FastifyInstance };
let ip = 0;
const addr = () => `10.230.${(++ip >> 8) & 255}.${ip & 255}`;
export const req = (t: T, u: { accessToken: string }, method: "GET" | "POST" | "PUT" | "DELETE", url: string, payload?: object, org?: string | null) =>
  t.app.inject({ method, url: `/api/v1${url}`, payload, remoteAddress: addr(), headers: { authorization: `Bearer ${u.accessToken}`, ...(org ? { "x-org-id": org } : {}) } });

const ring = new WeakMap<object, Map<string, MembershipKeys>>();
/** The membership keys this test client has unlocked, by org. */
export const keysOf = (u: object) => { let m = ring.get(u); if (!m) { m = new Map(); ring.set(u, m); } return m; };

/** Ensures the user has a current membership key in the org (creating it like a client on unlock) and returns it unlocked. */
export async function keyUp(t: T, u: KeyUser, orgId = u.orgId): Promise<MembershipKeys> {
  const res = await req(t, u, "GET", "/membership-key", undefined, orgId);
  expect(res.statusCode, res.body).toBe(200);
  const cur = (res.json().keys as { publicKey: string; wrappedPrivateKey: string; state: string }[]).find((k) => k.state === "current");
  let keys: MembershipKeys;
  if (cur) keys = await unlockMembershipKeys(u.keys.userKey, { orgId, userId: u.id }, cur);
  else {
    const made = await createMembershipKeys(u.keys.userKey, { orgId, userId: u.id });
    const r = await req(t, u, "POST", "/membership-key", made.material, orgId);
    expect(r.statusCode, r.body).toBe(201);
    keys = made.keys;
  }
  keysOf(u).set(orgId, keys);
  return keys;
}

/** The client's migration step: every row of mine in the org still sealed to my account key, re-sealed to my membership key. */
export async function migrateRows(t: T, u: KeyUser, orgId = u.orgId): Promise<number> {
  const mine = keysOf(u).get(orgId) ?? await keyUp(t, u, orgId);
  let moved = 0;
  for (;;) {
    const p = (await req(t, u, "GET", "/membership-key/pending", undefined, orgId)).json() as { folders: { folderId: string; sealedTo: string | null; wrappedFolderKey: string }[]; shares: { recordId: string; sealedTo: string | null; wrappedRecordKey: string }[] };
    const folders = await Promise.all(p.folders.filter((f) => f.sealedTo === null).map(async (f) => ({ folderId: f.folderId, from: null, wrappedFolderKey: await resealFolderKeyToMembership(f.wrappedFolderKey, { orgId, folderId: f.folderId }, u.keys, mine) })));
    const shares = await Promise.all(p.shares.filter((s) => s.sealedTo === null).map(async (s) => ({ recordId: s.recordId, from: null, wrappedRecordKey: await resealRecordShareToMembership(s.wrappedRecordKey, { orgId, recordId: s.recordId }, u.keys, mine) })));
    if (!folders.length && !shares.length) return moved;
    const r = await req(t, u, "PUT", "/membership-key/rows", { to: b64url.encode(mine.publicKey), folders, shares }, orgId);
    expect(r.statusCode, r.body).toBe(200);
    moved += r.json().updated;
  }
}

/** The client's escrow step: move rows, acknowledge if asked, then seal the membership key to every admin the server lists. */
export async function escrowKey(t: T, m: KeyUser, orgId = m.orgId): Promise<number> {
  const mine = await keyUp(t, m, orgId);
  await migrateRows(t, m, orgId);
  let st = (await req(t, m, "GET", "/membership-key", undefined, orgId)).json();
  if (st.escrow.ackRequired) {
    expect((await req(t, m, "POST", "/me/admin-recovery-ack", { orgId })).statusCode).toBe(200);
    st = (await req(t, m, "GET", "/membership-key", undefined, orgId)).json();
  }
  const needed = st.escrow.needed as { adminId: string; publicKey: string }[];
  if (!needed.length) return 0;
  const escrows = await Promise.all(needed.map(async (a) => ({ adminId: a.adminId, adminPublicKey: a.publicKey, sealedKey: await sealMembershipEscrow(b64url.decode(a.publicKey), mine, { userId: m.id, adminId: a.adminId }) })));
  const res = await req(t, m, "PUT", "/membership-key/escrows", { memberPublicKey: b64url.encode(mine.publicKey), escrows }, orgId);
  expect(res.statusCode, res.body).toBe(200);
  return res.json().stored as number;
}

/** The admin client's approval: fresh 2FA (`code`), open own escrow with own membership key, re-wrap under a link secret. */
export async function approveScoped(t: T, a: KeyUser, requestId: string, code: string, orgId = a.orgId) {
  const e = await req(t, a, "POST", `/admin/recovery-requests/${requestId}/escrow`, { code }, orgId);
  expect(e.statusCode, e.body).toBe(200);
  const { sealedKey, memberPublicKey, member, approvalToken } = e.json();
  const own = keysOf(a).get(orgId) ?? await keyUp(t, a, orgId);
  const key = await openMembershipEscrow(own, sealedKey, { userId: member.id, adminId: a.id }, memberPublicKey);
  const g = await createMembershipRecoveryGrant(requestId, { orgId, userId: member.id }, key);
  const res = await req(t, a, "POST", `/admin/recovery-requests/${requestId}/approve`, { approvalToken, memberPublicKey, wrappedMembershipKey: g.wrappedMembershipKey, proof: g.proof }, orgId);
  expect(res.statusCode, res.body).toBe(200);
  return { ...g, memberPublicKey, ...(res.json() as { linkBase: string; expiresAt: string }) };
}

/**
 * The member's client after the link check (`body` from POST /auth/recovery/admin/:id): opens the membership key, makes
 * new account keys under a new master password and re-wraps the membership key. The finish payload and the new keys.
 */
export async function scopedReset(requestId: string, fragment: string, body: { userId: string; orgId: string; memberPublicKey: string; wrappedMembershipKey: string }, password = "a brand new master password") {
  const key = await openMembershipRecoveryGrant(requestId, { orgId: body.orgId, userId: body.userId }, fragment, body.wrappedMembershipKey, body.memberPublicKey);
  const acct = await createAccount(password, FAST_KDF);
  const membership = await wrapMembershipKeys(acct.keys.userKey, { orgId: body.orgId, userId: body.userId }, key);
  return { payload: { authKey: acct.authKey, material: acct.material, membership }, keys: acct.keys, membershipKey: key, password };
}

/** A finish payload for refusal tests (any new keys; the server refuses before using them). */
export async function anyScopedPayload(orgId: string, userId: string) {
  const acct = await createAccount("some new master password", FAST_KDF);
  const made = await createMembershipKeys(acct.keys.userKey, { orgId, userId });
  return { authKey: acct.authKey, material: acct.material, membership: made.material };
}
