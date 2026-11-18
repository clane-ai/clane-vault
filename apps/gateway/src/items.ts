import {
  CryptoError, agentSecretOf, basicUsername, decryptFolderName, envKeys, decryptRecordBody, openOrgFolderKey, openOrgRecordShare, openPersonalAgentRecordKey, openRevealStub, unwrapKey,
  type AgentInject, type AgentMethod, type AgentPolicy, type MembershipKeys, type RecordBody, type RecordType,
} from "@clane-vault/crypto";
import { isPersonal, type AgentSync, type OrgAgentSync, type PersonalAgentSync } from "./apiClient.js";
import type { HeldSecrets, Logger } from "./log.js";

export interface ItemSummary {
  handle: string; recordId: string; title: string; type: RecordType; hosts: string[]; inject: AgentInject | { kind: "none" }; approval: boolean;
  methods?: AgentMethod[]; paths?: string[];
  /** A personal agent's: an unkept deposit of its own; one it may change with update_secret. */
  revision: number; deposit?: true; can_update?: true;
  /** An env file's: its keys (never a value), and the one entry its policy injects. */
  env_keys?: string[]; env_injects?: string;
  /** A personal agent's kept record or reveal stub: "use" when it holds the record key, "reveal" when the owner allowed get_secret. */
  modes?: ("use" | "reveal")[]; reveal?: { fields: string[]; approval: boolean };
}
/** A personal agent's unkept deposits are listed with its records: the same handles, opened with agentSealedKey. */
type SyncRecord = (AgentSync["records"][number] | PersonalAgentSync["records"][number]) & { deposit?: true };
type OrgRecord = OrgAgentSync["records"][number];

/** An item, or every item, would not open (no folder key, no folder, a dead agent key); a CryptoError is the other kind. */
export class ItemUnopenable extends Error { override name = "ItemUnopenable"; }
type Refusal = { error: "refused"; reason: "not_found" | "no_policy" | "not_kept" };

/** Lower-case, runs outside [a-z0-9] → "-", trimmed, at most 60 characters. */
export const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60).replace(/-$/, "");

const live = (sync: AgentSync): SyncRecord[] => [
  ...(sync.records as SyncRecord[]).filter((r) => !r.deletedAt),
  ...(isPersonal(sync) ? sync.deposits.map((d) => ({ id: d.id, encBody: d.encBody, revision: d.revision, wrappedRecordKey: d.agentSealedKey,
    write: sync.policy.write, deletedAt: null, deposit: true as const })) : []),
];

/** A personal agent's records are each sealed to it, under the one prefix "personal". */
function personalOpener(sync: PersonalAgentSync, keys: MembershipKeys) {
  return {
    async prefix(): Promise<string> { return "personal"; },
    async body(r: SyncRecord): Promise<RecordBody> {
      const rk = await openPersonalAgentRecordKey(r.wrappedRecordKey, { ownerUserId: sync.owner.userId, agentId: sync.agentId, recordId: r.id }, keys);
      try { return await decryptRecordBody(r.id, r.encBody, rk); } finally { rk.fill(0); }
    },
    close() {},
  };
}

/** Opens folder keys once per call; close() zeroes every one. */
function opener(sync: AgentSync, keys: MembershipKeys) {
  return isPersonal(sync) ? personalOpener(sync, keys) : orgOpener(sync, keys);
}

function orgOpener(sync: OrgAgentSync, keys: MembershipKeys) {
  const folderKeys = new Map<string, Uint8Array>(), prefixes = new Map<string, string>();
  async function folderKey(id: string) {
    let k = folderKeys.get(id);
    if (!k) {
      const f = sync.folders.find((x) => x.id === id);
      if (!f?.wrappedFolderKey) throw new ItemUnopenable("no folder key");
      k = await openOrgFolderKey(f.wrappedFolderKey, { orgId: sync.orgId, folderId: id }, keys);
      folderKeys.set(id, k);
    }
    return k;
  }
  return {
    async prefix(rec: SyncRecord): Promise<string> {
      const r = rec as OrgRecord;
      if (r.holderType === "user") return "shared";
      const id = r.keyFolderId ?? "";
      let p = prefixes.get(id);
      if (p === undefined) {
        const f = sync.folders.find((x) => x.id === id);
        if (!f) throw new ItemUnopenable("no folder");
        p = slug(await decryptFolderName(id, f.encName, await folderKey(id))) || "folder";
        prefixes.set(id, p);
      }
      return p;
    },
    async body(rec: SyncRecord): Promise<RecordBody> {
      const r = rec as OrgRecord;
      const rk = r.holderType === "folder"
        ? await unwrapKey(r.wrappedRecordKey, await folderKey(r.keyFolderId ?? ""), `record-key:${r.id}`)
        : await openOrgRecordShare(r.wrappedRecordKey, { orgId: sync.orgId, recordId: r.id }, keys);
      try { return await decryptRecordBody(r.id, r.encBody, rk); } finally { rk.fill(0); }
    },
    close() { for (const k of folderKeys.values()) k.fill(0); folderKeys.clear(); },
  };
}

/**
 * Summaries in record-id order; `onlyPrefix` decrypts just the records under one handle prefix (collisions never cross prefixes).
 * One record that won't open is skipped and logged; when none opens at all (a dead key), it throws.
 */
async function summarize(sync: AgentSync, keys: MembershipKeys, log?: Logger, onlyPrefix?: string): Promise<ItemSummary[]> {
  const o = opener(sync, keys), used = new Set<string>(), out: ItemSummary[] = [];
  let failed = 0, opened = 0;
  const handleFor = (prefix: string, title: string) => {
    const base = `${prefix}/${slug(title) || "item"}`;
    let handle = base;
    for (let n = 2; used.has(handle); n++) handle = `${base}-${n}`;
    used.add(handle);
    return handle;
  };
  // Reveal stubs of a personal agent: on a record it holds, or alone (a reveal-only item, listed with the same handles).
  const stubs = new Map(isPersonal(sync) ? sync.reveal.map((x) => [x.recordId, x.sealedStub] as const) : []);
  const openStub = async (recordId: string) => {
    const sealed = stubs.get(recordId);
    if (!sealed || !isPersonal(sync)) return null;
    try { return await openRevealStub(sealed, { ownerUserId: sync.owner.userId, agentId: sync.agentId, recordId }, keys); } catch (e) {
      log?.error({ event: "stub_skipped", recordId, reason: e instanceof CryptoError ? e.code : "unopenable" });
      return null;
    }
  };
  const keyed = live(sync);
  const stubOnly = [...stubs.keys()].filter((id) => !keyed.some((r) => r.id === id && !r.deposit)).map((id) => ({ id, stubOnly: true as const }));
  try {
    for (const e of [...keyed, ...stubOnly].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
      if ("stubOnly" in e) {
        if (onlyPrefix !== undefined && onlyPrefix !== "personal") continue;
        const st = await openStub(e.id);
        if (!st) continue;
        out.push({ handle: handleFor("personal", st.title), recordId: e.id, title: st.title, type: st.type, hosts: [], inject: { kind: "none" }, approval: false,
          revision: 0, modes: ["reveal"], reveal: { fields: st.fields, approval: true } });
        continue;
      }
      const r = e;
      let prefix: string, body: RecordBody;
      try {
        prefix = await o.prefix(r);
        if (onlyPrefix !== undefined && prefix !== onlyPrefix) {
          if ((r as OrgRecord).holderType === "folder") opened++; // its folder key opened: the agent's key works
          continue;
        }
        body = await o.body(r);
        opened++;
      } catch (e) {
        failed++;
        log?.error({ event: "item_skipped", recordId: r.id, reason: e instanceof CryptoError ? e.code : "unopenable" });
        continue;
      }
      const handle = handleFor(prefix, body.title);
      const p = body.agentPolicy; // only summary fields are kept; the body is dropped here
      const st = isPersonal(sync) && !r.deposit ? await openStub(r.id) : null;
      out.push({ handle, recordId: r.id, title: body.title, type: body.type, hosts: p?.hosts ?? [], inject: p?.inject ?? { kind: "none" }, approval: p?.approval ?? false,
        ...(p?.methods ? { methods: p.methods } : {}), ...(p?.paths ? { paths: p.paths } : {}),
        ...(body.type === "envFile" ? { env_keys: envKeys(body.data?.content ?? "") } : {}),
        ...(p?.secret?.startsWith("env:") ? { env_injects: p.secret.slice(4) } : {}),
        revision: r.revision, ...(r.deposit ? { deposit: true as const } : {}), ...("write" in r && r.write ? { can_update: true as const } : {}),
        ...(isPersonal(sync) && !r.deposit ? { modes: st ? ["use", "reveal"] as ("use" | "reveal")[] : ["use"] as ("use" | "reveal")[] } : {}),
        ...(st ? { reveal: { fields: st.fields, approval: true } } : {}) });
    }
  } finally {
    o.close();
  }
  // A personal agent's key is proven by its k2 envelope: a record it can't open (sealed to another agent) is only skipped.
  if (failed > 0 && opened === 0 && !isPersonal(sync)) throw new ItemUnopenable("none of the agent's items could be opened");
  return out;
}

/** `keys` come from `AgentKeyCache.use` (or open + release in finally). */
export async function listItems(sync: AgentSync, keys: MembershipKeys, log?: Logger): Promise<ItemSummary[]> {
  return summarize(sync, keys, log);
}

/** `item` is a handle or a record id (a deposit's too). */
export async function findItem(sync: AgentSync, keys: MembershipKeys, item: string, log?: Logger): Promise<{ id: string; revision: number; deposit?: true; write: boolean } | undefined> {
  let r = live(sync).find((x) => x.id === item);
  const slash = item.indexOf("/");
  if (!r && slash > 0) {
    const hit = (await summarize(sync, keys, log, item.slice(0, slash))).find((s) => s.handle === item);
    r = hit && live(sync).find((x) => x.id === hit.recordId);
  }
  return r && { id: r.id, revision: r.revision, ...(r.deposit ? { deposit: true as const } : {}), write: "write" in r && r.write };
}

/** For get_secret: the item's reveal stub fields, "no_stub" for an item the agent has without one, undefined for no such item. */
export async function revealableItem(sync: PersonalAgentSync, keys: MembershipKeys, item: string, log?: Logger): Promise<{ recordId: string; fields: string[] } | "no_stub" | undefined> {
  const all = await summarize(sync, keys, log, "personal");
  const hit = all.find((s) => s.handle === item) ?? all.find((s) => s.recordId === item);
  if (!hit) return undefined;
  return hit.reveal ? { recordId: hit.recordId, fields: hit.reveal.fields } : "no_stub";
}

/** The handle of the item with this id, or undefined. */
export async function handleOf(sync: AgentSync, keys: MembershipKeys, id: string, log?: Logger): Promise<string | undefined> {
  return (await summarize(sync, keys, log, isPersonal(sync) ? "personal" : undefined)).find((s) => s.recordId === id)?.handle;
}

/** `item` is a handle or a record id. The secret is held in `held` (scrubbed from logs) only while `f` runs. A deposit is not_kept. */
export async function withItem<T>(sync: AgentSync, keys: MembershipKeys, item: string, held: HeldSecrets,
  f: (x: { recordId: string; policy: AgentPolicy; secret: string; username: string }) => Promise<T>, log?: Logger): Promise<T | Refusal> {
  const hit = await findItem(sync, keys, item, log);
  const r = hit && live(sync).find((x) => x.id === hit.id);
  if (!r) return { error: "refused", reason: "not_found" };
  if (r.deposit) return { error: "refused", reason: "not_kept" };
  const o = opener(sync, keys);
  let body: RecordBody;
  try { body = await o.body(r); } finally { o.close(); }
  const policy = body.agentPolicy, secret = agentSecretOf(body);
  if (!policy || !secret) return { error: "refused", reason: "no_policy" };
  const username = basicUsername(body);
  const release = held.hold(secret, policy.inject.kind === "basic" ? username : undefined);
  try {
    return await f({ recordId: r.id, policy, secret, username });
  } finally {
    release();
  }
}
