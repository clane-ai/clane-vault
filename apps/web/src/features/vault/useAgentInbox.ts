import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  agentDepositMessage, b64url, decryptRecordBody, encryptRecordBody, openDepositKey, sealPersonalAgentRecordKey, serverRecordType, sha256B64, verifyGatewayMessage, wrapKey,
  type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
import { api, ApiError } from "@/lib/api";
import { accountPublicKeyOf, ensureGatewayPinned, KeyChangedError, PERSONAL_SLOT, pinKey, pinnedGateway, pinStatus, verifyPersonalAgentKey } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import type { MyAgent } from "@/features/settings/myAgents";
import { agentPolicyError } from "./AgentPolicyEditor";
import type { VaultRecord } from "./types";
import { ConflictError } from "./useVault";

/** A deposit as GET /me/agent-deposits lists it: ciphertext, the record key sealed to me, and the gateway's d1 signature. */
export interface DepositRow {
  id: string; agentId: string; agentName: string; app: string; type: string; encBody: string; revision: number; ownerSealedKey: string; signature: string;
  createdAt: string; updatedAt: string; expiresAt: string;
}
/**
 * `ok: false`: "invalid" (not signed by the pinned gateway for my key, or it doesn't open: shown as forged, Delete only), or
 * "unpinned" (no personal gateway pinned on this device: nothing can be checked yet, so the owner pins first).
 */
export type OpenedDeposit = { id: string; agentId: string; agentName: string; app: string; createdAt: string; expiresAt: string; revision: number }
  & ({ ok: true; body: RecordBody; recordKey: Uint8Array } | { ok: false; reason: "unpinned" | "invalid" });

/**
 * ok only when the d1 signature verifies against pinnedGateway(me, PERSONAL_SLOT) over a message naming MY public key
 * (derived from the unlocked private key), and the key and body then open. Nothing is decrypted before the signature passes.
 */
export async function openDeposit(d: DepositRow, me: string, keys: UnlockedKeys): Promise<OpenedDeposit> {
  const base = { id: d.id, agentId: d.agentId, agentName: d.agentName, app: d.app, createdAt: d.createdAt, expiresAt: d.expiresAt, revision: d.revision };
  const gw = pinnedGateway(me, PERSONAL_SLOT);
  if (!gw) return { ...base, ok: false, reason: "unpinned" };
  const ownerPublicKey = await accountPublicKeyOf(keys.privateKey).catch(() => null);
  const message = ownerPublicKey && agentDepositMessage({ ownerUserId: me, ownerPublicKey, agentId: d.agentId, id: d.id, revision: d.revision, encBodyHash: await sha256B64(d.encBody) });
  if (!message || !await verifyGatewayMessage(d.signature, "d1", message, gw)) return { ...base, ok: false, reason: "invalid" };
  let recordKey: Uint8Array;
  try { recordKey = await openDepositKey(d.ownerSealedKey, { ownerUserId: me, id: d.id }, keys); } catch { return { ...base, ok: false, reason: "invalid" }; }
  try { return { ...base, ok: true, body: await decryptRecordBody(d.id, d.encBody, recordKey), recordKey }; }
  catch { recordKey.fill(0); return { ...base, ok: false, reason: "invalid" }; }
}

const KEY = "agent-inbox";
/** Private copies of the session keys, zeroed afterwards (lock zeroes the session's own mid-flight). */
async function withKeys<T>(keys: UnlockedKeys | null | undefined, fn: (k: UnlockedKeys) => Promise<T>): Promise<T> {
  if (!keys) throw new Error("Vault locked");
  const k = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
  if (k.userKey.every((b) => b === 0)) throw new Error("Vault locked");
  try { return await fn(k); } finally { k.userKey.fill(0); k.privateKey.fill(0); }
}

/** GET /me/agent-deposits, each opened (or refused) on this device. `enabled` false while the session is private-locked. */
export function useAgentInbox(enabled = true) {
  const { user, keys, generation } = useSession();
  const qc = useQueryClient();
  const key = [KEY, user?.id];
  return useQuery({
    queryKey: key, enabled: enabled && !!user && !!keys, retry: false, structuralSharing: false,
    queryFn: () => withKeys(keys, async (k) => {
      const gen = generation();
      const { deposits } = await api.get<{ deposits: DepositRow[] }>("/me/agent-deposits");
      const opened = await Promise.all(deposits.map((d) => openDeposit(d, user!.id, k)));
      // Locked meanwhile: lock already wiped the cache, so these keys would outlive it in a detached query.
      if (generation() !== gen) { zeroKeys(opened); throw new Error("Vault locked"); }
      zeroKeys(qc.getQueryData<OpenedDeposit[]>(key)); // the copies these replace
      return opened;
    }),
  });
}
const zeroKeys = (list: OpenedDeposit[] | undefined) => list?.forEach((d) => { if (d.ok) d.recordKey.fill(0); });

/** The inbox and the vault (a kept item, the sidebar's count) and My agents (item counts) are read again. */
function useAfter() {
  const qc = useQueryClient();
  return () => Promise.all([qc.invalidateQueries({ queryKey: [KEY] }), qc.invalidateQueries({ queryKey: ["vault"] }), qc.invalidateQueries({ queryKey: ["my-agents"] })]);
}

export class DepositChangedError extends Error { constructor() { super("The agent changed this item. Check it again."); } }

/**
 * Keep: the record key wrapped under my user key (AAD record-key:<id>) and, with `agent`, sealed to that agent as a grant
 * (its key attested by the pinned gateway and bound to me). `agentRow` false: kept, but the agent holds 200 items already (true without `agent`).
 */
export function useKeepDeposit() {
  const { user, keys } = useSession();
  const after = useAfter();
  return useMutation({
    mutationFn: async (v: { d: Extract<OpenedDeposit, { ok: true }>; folderId: string | null; agent?: MyAgent }) => {
      if (!user) throw new Error("Not signed in");
      const { d, agent } = v;
      if (agent && pinStatus(user.id, PERSONAL_SLOT, agent.id, agent.publicKey).status === "changed") throw new KeyChangedError(agent.id);
      const rk = d.recordKey.slice();
      let body: { revision: number; wrappedRecordKey: string; folderId: string | null; agentWrappedRecordKey?: string };
      try {
        body = await withKeys(keys, async (k) => {
          const wrappedRecordKey = await wrapKey(rk, k.userKey, `record-key:${d.id}`);
          if (!agent) return { revision: d.revision, wrappedRecordKey, folderId: v.folderId };
          await verifyPersonalAgentKey(user.id, agent, agent.owner, k.privateKey);
          const agentWrappedRecordKey = await sealPersonalAgentRecordKey(rk, { ownerUserId: user.id, agentId: agent.id, recordId: d.id }, b64url.decode(agent.publicKey));
          return { revision: d.revision, wrappedRecordKey, folderId: v.folderId, agentWrappedRecordKey };
        });
      } finally { rk.fill(0); }
      try {
        const r = await api.post<{ id: string; agentRow?: boolean }>(`/me/agent-deposits/${d.id}/keep`, body);
        if (agent) pinKey(user.id, PERSONAL_SLOT, agent.id, agent.publicKey);
        return { agentRow: r.agentRow !== false };
      } catch (e) {
        if (e instanceof ApiError && e.status === 409 && e.code === "conflict") throw new DepositChangedError();
        throw e;
      }
    },
    onSettled: after,
  });
}

export function useDeleteDeposit() {
  const after = useAfter();
  return useMutation({ mutationFn: (id: string) => api.del(`/me/agent-deposits/${id}`), onSettled: after });
}

/** Trust on first use for the personal gateway (refused when any existing pin differs): `pinnedNow` shows its fingerprint. */
export function usePinPersonalGateway() {
  const { user } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => ensureGatewayPinned(api, user!.id, PERSONAL_SLOT, "/me/agents/gateway"),
    onSuccess: () => qc.invalidateQueries({ queryKey: [KEY] }),
  });
}

const sameFile = (a: RecordBody, b: RecordBody) => (["project", "environment", "fileName"] as const).every((k) => (a.data?.[k] ?? "") === (b.data?.[k] ?? ""));
/** The owner's own, live, Personal envFile records; first the one whose project, environment and fileName all equal the deposit's (the most recently changed when several do), or null. */
export function envReplaceTargets(deposit: RecordBody, records: VaultRecord[]): { targets: VaultRecord[]; match: VaultRecord | null } {
  if (deposit.type !== "envFile") return { targets: [], match: null };
  const mine = records.filter((r) => r.permission === "owner" && !r.deleted && r.recordKey && r.body?.type === "envFile")
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const match = mine.find((r) => sameFile(r.body!, deposit)) ?? null;
  return { targets: match ? [match, ...mine.filter((r) => r !== match)] : mine, match };
}

/**
 * Saves `target` through the normal edit path (PUT /records/:id at its revision) with only data.content replaced by the deposit's,
 * then DELETE /me/agent-deposits/:id. A refused save (validator or 409) deletes nothing. The deposit's agentPolicy is not applied.
 */
export function useReplaceFromDeposit() {
  const { generation } = useSession();
  const after = useAfter();
  return useMutation({
    mutationFn: async (v: { d: Extract<OpenedDeposit, { ok: true }>; target: VaultRecord }) => {
      const t = v.target;
      if (!t.body || !t.recordKey) throw new Error("This item can't be opened");
      const body: RecordBody = { ...t.body, data: { ...t.body.data, content: v.d.body.data?.content ?? "" } };
      // The policy's env:<KEY> must still name an entry (Review Focus 7): refused here in the editor's words.
      const why = agentPolicyError(body.agentPolicy, body);
      if (why) throw new Error(why);
      const gen = generation();
      const rk = t.recordKey.slice();
      let encBody: string;
      try {
        if (rk.every((b) => b === 0)) throw new Error("Vault locked");
        encBody = await encryptRecordBody(t.id, body, rk);
        if (generation() !== gen) throw new Error("Vault locked");
      } finally { rk.fill(0); }
      try { await api.put(`/records/${t.id}`, { encBody, revision: t.revision, type: serverRecordType(body) }); }
      catch (e) { throw e instanceof ApiError && e.status === 409 && e.code !== "in_trash" ? new ConflictError() : e; }
      await api.del(`/me/agent-deposits/${v.d.id}`);
    },
    onSettled: after,
  });
}
