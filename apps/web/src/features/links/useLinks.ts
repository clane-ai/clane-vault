import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { b64url, createLink, decryptLinkLabel, encryptLinkLabel, linkSnapshot, unwrapFileKey, type LinkAttachment } from "@clane-vault/crypto";
import type { FileRow } from "@/features/attachments/useAttachments";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope, useScopeOrg } from "@/lib/scope";
import type { VaultRecord } from "@/features/vault/types";
import { appUrl } from "@/lib/base";

export type LinkState = "active" | "expired" | "revoked" | "used_up";
export interface ShareLinkRow { id: string; recordId: string; expiresAt: string; maxOpens: number | null; opens: number; revokedAt: string | null; createdAt: string; labelEnc: string | null; createdByMe?: boolean; hasPassword: boolean; state: LinkState;
  /** Files the link carries. */ files?: number }
export interface ShareLink extends Omit<ShareLinkRow, "labelEnc"> { label: string }
export interface NewLinkInput { record: VaultRecord; label: string; expiresInHours: 1 | 24 | 168; maxOpens: 1 | 3 | null; password: string;
  /** Files to include (opt-in): their keys travel inside the link's encrypted payload (docs/attachments.md). */ files?: FileRow[] }

/** The link's copy of each file: its real key (unwrapped under the record key), nonce base and metadata. */
async function linkFiles(record: VaultRecord, files: FileRow[]): Promise<LinkAttachment[]> {
  if (!files.length) return [];
  if (!record.recordKey) throw new Error("This record can't be opened");
  const rk = record.recordKey.slice();
  try {
    return await Promise.all(files.map(async (f) => {
      if (!f.meta || !f.att.wrappedFileKey || !f.att.nonceBase) throw new Error("This file can't be opened");
      const k = await unwrapFileKey(record.id, f.att.id, f.att.wrappedFileKey, rk);
      try { return { fileId: f.att.id, fileKey: b64url.encode(k), nonceBase: f.att.nonceBase, meta: f.meta }; } finally { k.fill(0); }
    }));
  } finally { rk.fill(0); }
}

export const linkUrl = (id: string, fragment: string, origin = window.location.origin) => appUrl(`/s/${id}#${fragment}`, origin);

/** My one-time links (labels decrypted), plus create and revoke. With `recordId`, the links on that record instead
 * (all of them for the record owner, whoever created them). */
export function useLinks(recordId?: string) {
  const { keys, generation } = useSession();
  // The space's links only: an org's in an org, personal ones in Personal.
  const org = useScopeOrg();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const scope = useScope();
  const KEY = ["vault", scope, "links", ...(recordId ? [recordId] : [])];
  const ALL = ["vault", scope, "links"];

  async function withKey<T>(fn: (userKey: Uint8Array) => Promise<T>): Promise<T> {
    if (!keys) throw new Error("Vault locked");
    const gen = generation();
    const copy = keys.userKey.slice();
    if (copy.every((b) => b === 0)) throw new Error("Vault locked");
    try {
      const out = await fn(copy);
      if (generation() !== gen) throw new Error("Vault locked");
      return out;
    } finally { copy.fill(0); }
  }

  const q = useQuery({
    queryKey: KEY,
    enabled: !!keys,
    // Opens happen elsewhere (the recipient's browser), so always refresh when a list mounts.
    staleTime: 0, refetchOnMount: "always",
    queryFn: () => withKey(async (userKey) => {
      const { links } = await oapi.get<{ links: ShareLinkRow[] }>(recordId ? `/records/${recordId}/links` : org ? "/links?space=org" : "/links");
      return Promise.all(links.map(async ({ labelEnc, ...l }): Promise<ShareLink> => ({
        ...l, label: labelEnc ? await decryptLinkLabel(l.id, labelEnc, userKey).catch(() => "") : "",
      })));
    }),
  });

  const create = useMutation({
    mutationFn: async (v: NewLinkInput): Promise<{ id: string; url: string }> => {
      const b = v.record.body;
      if (!b) throw new Error("This record can't be opened");
      const id = crypto.randomUUID();
      // The record type, its fields and custom fields; never the 2FA secret or TOTP fields (crypto linkSnapshot).
      const files = await linkFiles(v.record, v.files ?? []);
      const snapshot = linkSnapshot(b, files);
      const l = await createLink(id, snapshot, v.password ? { password: v.password } : {});
      try {
        const labelEnc = v.label.trim() ? await withKey((k) => encryptLinkLabel(id, v.label.trim(), k)) : undefined;
        await oapi.post("/links", {
          id, recordId: v.record.id, encPayload: l.encPayload, expiresInHours: v.expiresInHours, maxOpens: v.maxOpens,
          ...(l.passwordSalt ? { passwordSalt: l.passwordSalt, accessHash: l.accessHash } : {}), ...(labelEnc ? { labelEnc } : {}),
          ...(files.length ? { attachmentIds: files.map((f) => f.fileId) } : {}),
        });
        return { id, url: linkUrl(id, l.fragment) };
      } finally { l.linkKey.fill(0); }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ALL }),
  });

  const revoke = useMutation({ mutationFn: (id: string) => oapi.del(`/links/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ALL }) });

  return {
    links: q.data ?? [], isLoading: q.isLoading, error: q.error,
    create: (v: NewLinkInput) => create.mutateAsync(v),
    revoke: (id: string) => revoke.mutateAsync(id),
  };
}

export function opensText(l: { maxOpens: number | null; opens: number }) {
  if (l.maxOpens == null) return `Opened ${l.opens} ${l.opens === 1 ? "time" : "times"} · until it expires`;
  return `Opened ${l.opens} of ${l.maxOpens}`;
}

export function stateLabel(s: LinkState) {
  return s === "active" ? "Active" : s === "used_up" ? "Used up" : s === "revoked" ? "Revoked" : "Expired";
}
