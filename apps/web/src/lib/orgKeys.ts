import {
  b64url, createMembershipKeys, keyFingerprint, ownerRecordKeyFromFolder, resealFolderKeyToMembership, resealRecordShareToMembership, rotateFolderKeySeal,
  rotateRecordShareSeal, sealFolderKeyFor, sealMembershipEscrow, sealOrgFolderKey, sealOrgRecordShare, shareRecordKey, unlockMembershipKeys, unwrapKey,
  type MembershipKeys, type SealKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import type { OrgApi } from "./api";
import { storageKey } from "@/lib/base";

/**
 * Per-organisation membership keys on the client (docs/design/2026-10-08-per-org-keypairs.md).
 *
 * - Sealing: a folder key or a direct share made in an org is sealed to the recipient's current membership key there
 *   (or, while they have none yet, to their account key), and the server is told which (`sealedTo`).
 * - The membership job (`syncMembershipKeys`), on unlock for the active org: create my key, move my rows to it,
 *   rotate it after an admin opened its escrow, rebuild owner rows after a scoped reset, and escrow it to the org's
 *   admins while admin recovery is on. Each step is idempotent and resumes where it stopped.
 */

/** Someone to seal to: their account key and (in this org) their membership key, both base64url as the server lists them. */
export interface Recipient { id: string; publicKey: string; membershipKey?: string | null }

export async function sealFolderKeyTo(folderKey: Uint8Array, ids: { orgId: string; folderId: string }, to: Recipient) {
  if (to.membershipKey) return { wrappedFolderKey: await sealOrgFolderKey(folderKey, ids, b64url.decode(to.membershipKey)), sealedTo: to.membershipKey };
  return { wrappedFolderKey: await sealFolderKeyFor(folderKey, ids.folderId, b64url.decode(to.publicKey)), sealedTo: null };
}

export async function sealShareTo(recordKey: Uint8Array, ids: { orgId: string; recordId: string }, to: Recipient) {
  if (to.membershipKey) return { sealedRecordKey: await sealOrgRecordShare(recordKey, ids, b64url.decode(to.membershipKey)), sealedTo: to.membershipKey };
  return { sealedRecordKey: await shareRecordKey(recordKey, ids.recordId, b64url.decode(to.publicKey)), sealedTo: null };
}

/**
 * My own current membership key in the org, verified: unwrapped under my user key and checked against its public key
 * (`unlockMembershipKeys`). What I seal my own copy of a new folder key to; a key the server merely lists for me could be
 * anyone's. null: I have none yet (my own account key, which I hold, is used instead).
 */
export async function myMembershipKey(oapi: Pick<OrgApi, "get">, orgId: string, userId: string, userKey: Uint8Array): Promise<string | null> {
  const st = await oapi.get<{ keys: { publicKey: string; wrappedPrivateKey: string; state: string }[] }>("/membership-key");
  const cur = st.keys.find((k) => k.state === "current");
  if (!cur) return null;
  const k = await unlockMembershipKeys(userKey, { orgId, userId }, cur);
  k.privateKey.fill(0);
  return cur.publicKey;
}

// ---- Key pinning (trust on first use) ----

const PINS = (me: string) => storageKey(`cv.pins.${me}`);
function readPins(me: string): Record<string, string> { try { return JSON.parse(localStorage.getItem(PINS(me)) ?? "{}") as Record<string, string>; } catch { return {}; } }
function writePins(me: string, pins: Record<string, string>) { try { localStorage.setItem(PINS(me), JSON.stringify(pins)); } catch { /* private mode */ } }

/** What gets pinned: the membership key, or (none yet) the account key, marked as such. */
const pinValue = (key: string | null | undefined, accountKey?: string | null) => key ? key : accountKey ? `acct:${accountKey}` : null;

/**
 * The key this device last sealed to for that person in that org. "changed" means the server now lists another one: expected
 * after their account reset or a key rotation, but worth a look (the approval prompts show both fingerprints). A person
 * pinned with a membership key who is now listed with none (sealing would go to their account key) is "changed" too:
 * a server can't quietly downgrade someone to a key of its choosing. Account key → first membership key is the normal
 * upgrade ("new").
 */
export function pinStatus(me: string, orgId: string, userId: string, key: string | null | undefined, accountKey?: string | null): { status: "new" | "same" | "changed"; previous?: string } {
  const now = pinValue(key, accountKey);
  const prev = readPins(me)[`${orgId}:${userId}`];
  if (!prev) return { status: "new" };
  if (prev === now) return { status: "same" };
  if (prev.startsWith("acct:") && now && !now.startsWith("acct:")) return { status: "new" };
  return { status: "changed", previous: prev };
}
export function pinKey(me: string, orgId: string, userId: string, key: string | null | undefined, accountKey?: string | null) {
  const v = pinValue(key, accountKey);
  if (!v) return;
  const pins = readPins(me);
  pins[`${orgId}:${userId}`] = v;
  writePins(me, pins);
}
/** Sealing refused: the server lists another key for this person than the one this device pinned. */
export class KeyChangedError extends Error {
  constructor(readonly userId: string) { super("Their key changed since this device last shared with them"); this.name = "KeyChangedError"; }
}
/**
 * Called before sealing to someone. A changed key is refused until the user accepts it after comparing fingerprints
 * (`pinKey` from the picker, *Give access again*, or approving a group request, which all show the new fingerprint).
 */
export function assertPinned(me: string, orgId: string, to: Recipient) {
  if (pinStatus(me, orgId, to.id, to.membershipKey, to.publicKey).status === "changed") throw new KeyChangedError(to.id);
}
export const fingerprintOf = async (keyB64: string) => keyFingerprint(b64url.decode(keyB64));

// ---- The membership job ----

interface KeyRow { publicKey: string; wrappedPrivateKey: string; state: "current" | "retiring"; escrowOpenedAt: string | null }
export interface KeyState {
  userKeyGen: number; keys: KeyRow[]; rotateNeeded: boolean; pendingRows: number; repairNeeded: boolean;
  escrow: { enabled: boolean; ackRequired: boolean; needed: { adminId: string; publicKey: string }[]; holders: { adminId: string; name: string }[]; recoverable: boolean };
}
interface Pending {
  folders: { folderId: string; sealedTo: string | null; wrappedFolderKey: string }[];
  shares: { recordId: string; sealedTo: string | null; wrappedRecordKey: string }[];
  folderAfter: string | null; shareAfter: string | null;
}
export interface SyncResult { created: boolean; rotated: boolean; moved: number; repaired: number; escrowed: number }

/**
 * One pass of the membership job for `orgId` (the requests go through `oapi`, pinned to that org). `folderKeys`: team
 * folder keys this client already holds (to rebuild owner rows after a reset). `oldAccounts`: account keys from the
 * archive (after a kit or old-password restore), by base64url public key, to move rows sealed to them ("acct:…").
 */
export async function syncMembershipKeys(oapi: OrgApi, orgId: string, userId: string, keys: UnlockedKeys,
  opts: { folderKeys?: ReadonlyMap<string, Uint8Array>; oldAccounts?: ReadonlyMap<string, SealKeys>; assertOpen?: () => void } = {}): Promise<SyncResult> {
  const assertOpen = opts.assertOpen ?? (() => {});
  const ids = { orgId, userId };
  const result: SyncResult = { created: false, rotated: false, moved: 0, repaired: 0, escrowed: 0 };
  let st = await oapi.get<KeyState>("/membership-key");
  const ring = new Map<string, MembershipKeys>();
  try {
    for (const k of st.keys) { try { ring.set(k.publicKey, await unlockMembershipKeys(keys.userKey, ids, k)); } catch { /* a key I can't open is never used */ } }
    let current = st.keys.find((k) => k.state === "current" && ring.has(k.publicKey))?.publicKey ?? null;

    if (!current) {
      const made = await createMembershipKeys(keys.userKey, ids);
      assertOpen();
      const r = await oapi.post<{ created: boolean; key: { publicKey: string; wrappedPrivateKey: string } }>("/membership-key", made.material);
      if (r.created) { ring.set(made.material.publicKey, made.keys); current = made.material.publicKey; result.created = true; }
      else { made.keys.privateKey.fill(0); ring.set(r.key.publicKey, await unlockMembershipKeys(keys.userKey, ids, r.key)); current = r.key.publicKey; }
    } else if (st.rotateNeeded) {
      // An admin's client saw this key (escrow opened): from now on everything is sealed to a fresh one.
      const next = await createMembershipKeys(keys.userKey, ids);
      assertOpen();
      await oapi.post("/membership-key/rotate", { from: current, ...next.material });
      ring.set(next.material.publicKey, next.keys); current = next.material.publicKey; result.rotated = true;
    }
    const to = ring.get(current)!;

    // Move my rows: from my account key, a retiring membership key or (after an archive restore) an old account key.
    let folderAfter: string | null = null, shareAfter: string | null = null;
    for (let page = 0; page < 100; page++) {
      const q: URLSearchParams = new URLSearchParams({ ...(folderAfter ? { folderAfter } : {}), ...(shareAfter ? { shareAfter } : {}), ...(opts.oldAccounts?.size ? { acct: "1" } : {}) });
      const p: Pending = await oapi.get<Pending>(`/membership-key/pending${q.size ? `?${q}` : ""}`);
      const folders = [], shares = [];
      for (const f of p.folders) {
        try {
          const from = sourceOf(f.sealedTo, keys, ring, opts.oldAccounts);
          if (!from) continue;
          const w = from.kind === "membership"
            ? await rotateFolderKeySeal(f.wrappedFolderKey, { orgId, folderId: f.folderId }, from.keys, to)
            : await resealFolderKeyToMembership(f.wrappedFolderKey, { orgId, folderId: f.folderId }, from.keys, to);
          folders.push({ folderId: f.folderId, from: f.sealedTo, wrappedFolderKey: w });
        } catch { /* unreadable: left for someone to give again */ }
      }
      for (const s of p.shares) {
        try {
          const from = sourceOf(s.sealedTo, keys, ring, opts.oldAccounts);
          if (!from) continue;
          const w = from.kind === "membership"
            ? await rotateRecordShareSeal(s.wrappedRecordKey, { orgId, recordId: s.recordId }, from.keys, to)
            : await resealRecordShareToMembership(s.wrappedRecordKey, { orgId, recordId: s.recordId }, from.keys, to);
          shares.push({ recordId: s.recordId, from: s.sealedTo, wrappedRecordKey: w });
        } catch { /* as above */ }
      }
      assertOpen();
      // `to`: the key these rows are now sealed to. The server refuses the batch if it is no longer my current key
      // (another device rotated meanwhile); the next run moves them again from the then-retiring key.
      if (folders.length || shares.length) result.moved += (await oapi.put<{ updated: number }>("/membership-key/rows", { to: current, folders, shares })).updated;
      if (!p.folderAfter && !p.shareAfter) break;
      folderAfter = p.folderAfter; shareAfter = p.shareAfter;
    }

    // After a scoped reset: my owner rows in this org's team folders come back from the folder rows.
    if (st.repairNeeded && opts.folderKeys) {
      const { rows } = await oapi.get<{ rows: { recordId: string; ownerWrapped: string; folderId: string; folderWrapped: string }[] }>("/membership-key/owner-repair");
      const fixes = [];
      let missing = 0;
      for (const r of rows) {
        const ok = await unwrapKey(r.ownerWrapped, keys.userKey, `record-key:${r.recordId}`).then((k) => { k.fill(0); return true; }, () => false);
        if (ok) continue;
        const fk = opts.folderKeys.get(r.folderId);
        if (!fk) { missing++; continue; }
        try { fixes.push({ recordId: r.recordId, from: r.ownerWrapped, wrappedRecordKey: await ownerRecordKeyFromFolder(r.recordId, r.folderWrapped, fk, keys.userKey) }); } catch { missing++; }
      }
      assertOpen();
      for (let i = 0; i < fixes.length; i += 200) result.repaired += (await oapi.put<{ updated: number }>("/me/owner-rows", { rows: fixes.slice(i, i + 200) })).updated;
      if (!missing) await oapi.post("/membership-key/repaired");
    }

    // Escrow to each admin the server lists (only once the policy is on, acknowledged, and every row is moved).
    st = await oapi.get<KeyState>("/membership-key");
    if (st.escrow.enabled && !st.escrow.ackRequired && st.escrow.needed.length) {
      const escrows = await Promise.all(st.escrow.needed.map(async (a) => ({ adminId: a.adminId, adminPublicKey: a.publicKey, sealedKey: await sealMembershipEscrow(b64url.decode(a.publicKey), to, { userId, adminId: a.adminId }) })));
      assertOpen();
      result.escrowed = (await oapi.put<{ stored: number }>("/membership-key/escrows", { memberPublicKey: current, escrows })).stored;
    }
    return result;
  } finally {
    for (const k of ring.values()) k.privateKey.fill(0);
  }
}

type Source = { kind: "account"; keys: SealKeys } | { kind: "membership"; keys: MembershipKeys };
function sourceOf(sealedTo: string | null, account: SealKeys, ring: Map<string, MembershipKeys>, old?: ReadonlyMap<string, SealKeys>): Source | null {
  if (sealedTo === null) return { kind: "account", keys: account };
  if (sealedTo.startsWith("acct:")) { const k = old?.get(sealedTo.slice(5)); return k ? { kind: "account", keys: k } : null; }
  const m = ring.get(sealedTo);
  return m ? { kind: "membership", keys: m } : null;
}
