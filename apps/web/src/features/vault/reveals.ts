import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  agentRevealRequestMessage, b64url, revealFieldsOf, sealReveal, templateOf, validateRevealFields, verifyGatewayMessage, type RecordBody,
} from "@clane-vault/crypto";
import { api, ApiError, forOrg } from "@/lib/api";
import { PERSONAL_SLOT, pinnedGateway } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { decryptSync } from "./decrypt";
import type { SyncResponse, VaultRecord } from "./types";

/** A reveal request as GET /me/agent-reveals lists it (spec §5.3). `reason` is the agent's own words. */
export interface RevealRequest {
  id: string; agentId: string; agentName: string; app: string; recordId: string; fields: string[]; reason: string;
  requestPublicKey: string; signature: string; expiresAt: string; createdAt: string;
}
export interface PausedAgent { agentId: string; agentName: string; until: string }

const KEY = "agent-reveals";
/** Each unlocked session gets its own tag: a stopped poll (403, 404) starts again after a lock and unlock or another sign-in. */
const tags = new WeakMap<object, number>();
let nextTag = 0;
const tagOf = (o: object | null | undefined) => (o ? (tags.get(o) ?? (tags.set(o, ++nextTag), nextTag)) : 0);
const stops = (e: unknown) => e instanceof ApiError && (e.status === 404 || e.status === 403);

/** Polls GET /me/agent-reveals every 5 s while the session is unlocked; a 404 (feature off) or 403 (private-locked) stops it for this session (F13). */
export function useRevealRequests(): { requests: RevealRequest[]; paused: PausedAgent[] } {
  const { user, keys } = useSession();
  const tag = tagOf(keys);
  const q = useQuery({
    queryKey: [KEY, user?.id, tag], enabled: !!user && !!keys, retry: false,
    // A step-up refusal is not raised app-wide from here: this poll runs on every screen.
    queryFn: () => api.poll<{ requests: RevealRequest[]; paused: PausedAgent[] }>("/me/agent-reveals"),
    refetchInterval: (query) => (stops(query.state.error) ? false : 5000),
    refetchOnWindowFocus: (query) => !stops(query.state.error),
  });
  return { requests: q.data?.requests ?? [], paused: q.data?.paused ?? [] };
}

/**
 * The Personal vault, for checking and answering a request on any screen (the active space may be an organisation). Under
 * the "vault" key, so lock zeroes its record keys with the rest.
 */
export function usePersonalVault(enabled: boolean) {
  const { user, keys, generation } = useSession();
  return useQuery({
    queryKey: ["vault", "reveal", user?.id, tagOf(keys)], enabled: enabled && !!user && !!keys, retry: false, staleTime: 5000,
    queryFn: async () => {
      if (!keys) throw new Error("Vault locked");
      const gen = generation();
      const k = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
      try {
        const sync = await forOrg(null).get<SyncResponse>("/sync");
        const out = await decryptSync(sync, k, user!.id, null);
        if (generation() !== gen) { out.records.forEach((r) => r.recordKey?.fill(0)); throw new Error("Vault locked"); }
        return out;
      } finally { k.userKey.fill(0); k.privateKey.fill(0); }
    },
  });
}

export type RevealCheck = "ok" | "unpinned" | "unsigned" | "unknown_item" | "fields";

/**
 * "ok" only when the q1 signature verifies against pinnedGateway(me, PERSONAL_SLOT) over the message built from the request as
 * shown, the record is mine in the Personal space, and every asked field is in that agent's `agentGrants.reveal` for it and is
 * revealable in the body (never a seed, never a whole .env file). "unpinned": no personal gateway pinned on this device (F6).
 */
export async function checkRequest(r: RevealRequest, me: string, record: VaultRecord | undefined): Promise<RevealCheck> {
  const gw = pinnedGateway(me, PERSONAL_SLOT);
  if (!gw) return "unpinned";
  const message = agentRevealRequestMessage({ requestId: r.id, ownerUserId: me, agentId: r.agentId, recordId: r.recordId, fields: r.fields,
    requestPublicKey: r.requestPublicKey, expiresAt: r.expiresAt });
  if (!await verifyGatewayMessage(r.signature, "q1", message, gw)) return "unsigned";
  if (!record?.body || !record.recordKey || record.deleted || record.ownerId !== me || record.permission !== "owner" || record.sharedBy) return "unknown_item";
  const allowed = record.agentGrants?.find((g) => g.agentId === r.agentId)?.reveal ?? [];
  if (r.fields.some((f) => !allowed.includes(f))) return "fields";
  try { validateRevealFields(r.fields, record.body); } catch { return "fields"; }
  return "ok";
}

/** What the owner reads for a field reference: the record's own labels. */
export function revealFieldLabel(body: Pick<RecordBody, "type" | "fields">, ref: string): string {
  if (ref === "totp") return "Current one-time code";
  if (ref === "notes") return "Notes";
  if (ref.startsWith("env:")) return ref.slice(4);
  if (ref.startsWith("field:")) return body.fields?.find((f) => f.id === ref.slice(6))?.label ?? ref;
  const key = ref.startsWith("data.") ? ref.slice(5) : ref;
  return templateOf(body.type).find((f) => f.key === key)?.label ?? (ref === "username" ? "Username" : ref === "password" ? "Password" : ref === "url" ? "Website" : key);
}

/** Allow once: only the asked fields, sealed to the request's one-time key. Sends nothing when checkRequest is not "ok". */
export function useApproveReveal() {
  const { user } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { r: RevealRequest; record: VaultRecord | undefined }) => {
      if (!user) throw new Error("Not signed in");
      if (await checkRequest(v.r, user.id, v.record) !== "ok") throw new Error("This request can't be allowed.");
      const fields = await revealFieldsOf(v.record!.body!, v.r.fields);
      const sealed = await sealReveal(fields, { requestId: v.r.id, recordId: v.r.recordId, agentId: v.r.agentId }, b64url.decode(v.r.requestPublicKey));
      await api.post(`/me/agent-reveals/${v.r.id}/approve`, { sealed });
    },
    onSettled: () => qc.invalidateQueries({ queryKey: [KEY] }),
  });
}

export function useDenyReveal() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: (r: RevealRequest) => api.post(`/me/agent-reveals/${r.id}/deny`), onSettled: () => qc.invalidateQueries({ queryKey: [KEY] }) });
}

