import type { AccountMaterial } from "@clane-vault/crypto";
import type { SyncResponse } from "@/features/vault/types";
import { ApiError } from "./api";
import type { Org } from "./session";
import { storageKey } from "@/lib/base";

/**
 * The offline copy (docs/install-app.md): what the server already hands this device, kept in IndexedDB so the vault can
 * be opened read-only without a connection. Only ciphertext and metadata: the key material is the same encrypted bundle
 * the unlock screen uses online (KDF salt and params, wrapped keys), and each org's last sync response as received.
 * Nothing decrypted is ever stored. One account per device: saving for another user wipes the previous one.
 */
export interface OfflineCopy {
  userId: string; email: string; name: string; recoveryKit?: boolean;
  material: AccountMaterial; orgs: Org[];
  /** Last sync per org id ("-" for no org). Private items withheld by the server (privateLocked) are simply absent. */
  syncs: Record<string, { sync: SyncResponse; savedAt: string }>;
}

const DB = storageKey("clane-offline"), STORE = "copies";
const PREF = storageKey("cv.offline");
export const orgKey = (orgId: string | null | undefined) => orgId ?? "-";

/** Per device, default on. */
export function offlineEnabled(): boolean { try { return localStorage.getItem(PREF) !== "off"; } catch { return true; } }
export function setOfflineEnabled(on: boolean) { try { if (on) localStorage.removeItem(PREF); else localStorage.setItem(PREF, "off"); } catch { /* private mode */ } }

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("no IndexedDB"));
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => { req.result.createObjectStore(STORE, { keyPath: "userId" }); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> {
  const db = await open();
  try {
    return await new Promise<T | undefined>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req ? req.result : undefined);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally { db.close(); }
}

// Writes are serialised so a sync saved right after the account isn't lost to a read-modify-write race.
let queue: Promise<unknown> = Promise.resolve();
const serial = <T>(fn: () => Promise<T>): Promise<T> => { const p = queue.then(fn, fn); queue = p.catch(() => undefined); return p; };

async function all(): Promise<OfflineCopy[]> { return (await tx<OfflineCopy[]>("readonly", (s) => s.getAll())) ?? []; }

/** The copy on this device, if any (and the toggle is on). */
export async function loadCopy(): Promise<OfflineCopy | null> {
  if (!offlineEnabled()) return null;
  try { return (await serial(all))[0] ?? null; } catch { return null; }
}

/**
 * The syncs that may stay with the current org list: the private vault ("-"), and orgs the account still belongs to
 * whose policy allows offline copies. An org that removed the member, or switched offline copies off, loses its copy at
 * the next sign-in or refresh, even if the member never opens that org again.
 */
function keptSyncs(syncs: OfflineCopy["syncs"], orgs: Org[]): OfflineCopy["syncs"] {
  const ok = new Set(orgs.filter((o) => o.policies?.offlineAllowed !== false).map((o) => orgKey(o.id)));
  return Object.fromEntries(Object.entries(syncs).filter(([k]) => k === orgKey(null) || ok.has(k)));
}

/** After a sign-in, refresh or reconnect: removes any other account's copy and stores this account's key material and orgs. */
export function saveAccount(user: { id: string; email: string; name: string; recoveryKit?: boolean }, material: AccountMaterial, orgs: Org[]): Promise<void> {
  return serial(async () => {
    const copies = await all();
    for (const c of copies) if (c.userId !== user.id) await tx("readwrite", (s) => s.delete(c.userId));
    if (!offlineEnabled()) { await tx("readwrite", (s) => s.delete(user.id)); return; }
    const prev = copies.find((c) => c.userId === user.id);
    const copy: OfflineCopy = { userId: user.id, email: user.email, name: user.name, ...(user.recoveryKit !== undefined ? { recoveryKit: user.recoveryKit } : {}), material, orgs, syncs: keptSyncs(prev?.syncs ?? {}, orgs) };
    await tx("readwrite", (s) => s.put(copy));
  }).catch(() => undefined);
}

/** Stores an org's sync response as received (replacing the previous one, so withheld private items drop out too). */
export function saveSync(userId: string, org: string, sync: SyncResponse): Promise<void> {
  return serial(async () => {
    if (!offlineEnabled()) return;
    const copy = (await all()).find((c) => c.userId === userId);
    if (!copy) return; // only alongside the account it belongs to
    copy.syncs = { ...copy.syncs, [org]: { sync, savedAt: new Date().toISOString() } };
    await tx("readwrite", (s) => s.put(copy));
  }).catch(() => undefined);
}

/** An org whose policy forbids offline copies (docs/policies.md): its sync is never kept, and an older one goes. */
export function dropSync(userId: string, org: string): Promise<void> {
  return serial(async () => {
    const copy = (await all()).find((c) => c.userId === userId);
    if (!copy?.syncs[org]) return;
    const { [org]: _gone, ...rest } = copy.syncs;
    copy.syncs = rest;
    await tx("readwrite", (s) => s.put(copy));
  }).catch(() => undefined);
}

export async function loadSync(userId: string, org: string): Promise<{ sync: SyncResponse; savedAt: string } | null> {
  const copy = await loadCopy();
  return copy?.userId === userId ? copy.syncs[org] ?? null : null;
}

/** Sign-out, session ended, toggle off: every copy on this device goes. */
export function wipeOffline(): Promise<void> {
  return serial(async () => { await tx("readwrite", (s) => s.clear()); }).catch(() => undefined);
}

/** The server can't be reached (no network, or a gateway answering 502/503/504), as opposed to a refusal. */
export function isUnreachable(e: unknown): boolean {
  return e instanceof TypeError || (e instanceof ApiError && [502, 503, 504].includes(e.status));
}
