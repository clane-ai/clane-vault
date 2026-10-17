import {
  agentSecretOf, basicUsername, decryptFolderName, decryptRecordBody, openOrgFolderKey, openOrgRecordShare, unwrapKey,
  type AgentInject, type AgentMethod, type AgentPolicy, type MembershipKeys, type RecordBody, type RecordType,
} from "@clane-vault/crypto";
import type { AgentSync } from "./apiClient.js";
import type { HeldSecrets } from "./log.js";

export interface ItemSummary {
  handle: string; recordId: string; title: string; type: RecordType; hosts: string[]; inject: AgentInject | { kind: "none" }; approval: boolean;
  methods?: AgentMethod[]; paths?: string[];
}
type SyncRecord = AgentSync["records"][number];
type Refusal = { error: "refused"; reason: "not_found" | "no_policy" };

/** Lower-case, runs outside [a-z0-9] → "-", trimmed, at most 60 characters. */
export const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60).replace(/-$/, "");

const live = (sync: AgentSync) => sync.records.filter((r) => !r.deletedAt);

/** Opens folder keys once per call; close() zeroes every one. */
function opener(sync: AgentSync, keys: MembershipKeys) {
  const folderKeys = new Map<string, Uint8Array>(), prefixes = new Map<string, string>();
  async function folderKey(id: string) {
    let k = folderKeys.get(id);
    if (!k) {
      const f = sync.folders.find((x) => x.id === id);
      if (!f?.wrappedFolderKey) throw new Error("no folder key");
      k = await openOrgFolderKey(f.wrappedFolderKey, { orgId: sync.orgId, folderId: id }, keys);
      folderKeys.set(id, k);
    }
    return k;
  }
  return {
    async prefix(r: SyncRecord): Promise<string> {
      if (r.holderType === "user") return "shared";
      const id = r.keyFolderId ?? "";
      let p = prefixes.get(id);
      if (p === undefined) {
        const f = sync.folders.find((x) => x.id === id);
        if (!f) throw new Error("no folder");
        p = slug(await decryptFolderName(id, f.encName, await folderKey(id))) || "folder";
        prefixes.set(id, p);
      }
      return p;
    },
    async body(r: SyncRecord): Promise<RecordBody> {
      const rk = r.holderType === "folder"
        ? await unwrapKey(r.wrappedRecordKey, await folderKey(r.keyFolderId ?? ""), `record-key:${r.id}`)
        : await openOrgRecordShare(r.wrappedRecordKey, { orgId: sync.orgId, recordId: r.id }, keys);
      try { return await decryptRecordBody(r.id, r.encBody, rk); } finally { rk.fill(0); }
    },
    close() { for (const k of folderKeys.values()) k.fill(0); folderKeys.clear(); },
  };
}

/** Summaries in record-id order; `onlyPrefix` decrypts just the records under one handle prefix (collisions never cross prefixes). */
async function summarize(sync: AgentSync, keys: MembershipKeys, onlyPrefix?: string): Promise<ItemSummary[]> {
  const o = opener(sync, keys), used = new Set<string>(), out: ItemSummary[] = [];
  try {
    for (const r of live(sync).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
      let prefix: string, body: RecordBody;
      try {
        prefix = await o.prefix(r);
        if (onlyPrefix !== undefined && prefix !== onlyPrefix) continue;
        body = await o.body(r);
      } catch { continue; } // an item the agent can't open is left out, not fatal to the rest
      const base = `${prefix}/${slug(body.title) || "item"}`;
      let handle = base;
      for (let n = 2; used.has(handle); n++) handle = `${base}-${n}`;
      used.add(handle);
      const p = body.agentPolicy; // only summary fields are kept; the body is dropped here
      out.push({ handle, recordId: r.id, title: body.title, type: body.type, hosts: p?.hosts ?? [], inject: p?.inject ?? { kind: "none" }, approval: p?.approval ?? false,
        ...(p?.methods ? { methods: p.methods } : {}), ...(p?.paths ? { paths: p.paths } : {}) });
    }
  } finally {
    o.close();
  }
  return out;
}

export async function listItems(sync: AgentSync, keys: MembershipKeys, _agentId: string): Promise<ItemSummary[]> {
  return summarize(sync, keys);
}

/** `item` is a handle or a record id. The secret is held in `held` (scrubbed from logs) only while `f` runs. */
export async function withItem<T>(sync: AgentSync, keys: MembershipKeys, _agentId: string, item: string, held: HeldSecrets,
  f: (x: { recordId: string; host: string; policy: AgentPolicy; secret: string; username: string }) => Promise<T>): Promise<T | Refusal> {
  let r = live(sync).find((x) => x.id === item);
  const slash = item.indexOf("/");
  if (!r && slash > 0) {
    const hit = (await summarize(sync, keys, item.slice(0, slash))).find((s) => s.handle === item);
    r = hit && live(sync).find((x) => x.id === hit.recordId);
  }
  if (!r) return { error: "refused", reason: "not_found" };
  const o = opener(sync, keys);
  let body: RecordBody;
  try { body = await o.body(r); } finally { o.close(); }
  const policy = body.agentPolicy, secret = agentSecretOf(body);
  if (!policy || !secret) return { error: "refused", reason: "no_policy" };
  const username = basicUsername(body);
  const release = held.hold(secret, policy.inject.kind === "basic" ? username : undefined);
  try {
    return await f({ recordId: r.id, host: policy.hosts[0] ?? "", policy, secret, username });
  } finally {
    release();
  }
}
