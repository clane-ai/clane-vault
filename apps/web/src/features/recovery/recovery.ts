import { useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgApi } from "@/lib/scope";
import { syncMembershipKeys } from "@/lib/orgKeys";
import type { VaultFolder } from "@/features/vault/types";

/** An admin who holds an escrow of my membership key in an org (they could restore my access there). */
export interface EscrowHolder { adminId: string; name: string; email: string; since: string }
export interface Security {
  recoveryKit: { createdAt: string } | null;
  adminRecoveryEnabled: boolean;
  /** Admin recovery is on and this user hasn't acknowledged it yet (in some org): no escrow there until they do. */
  adminRecoveryAckRequired?: boolean;
  /** Per organisation with admin recovery on (docs/design/2026-10-08-per-org-keypairs.md). */
  orgs?: { orgId: string; orgName: string; adminRecoveryEnabled: boolean; ackRequired: boolean; recoverable?: boolean; escrowHolders?: EscrowHolder[] }[];
  /** Left behind by an admin recovery (scoped reset): private items and other orgs the old kit or password can bring back. */
  keyArchive?: { id: string; archivedAt: string; privateItems: number; otherOrgs: number } | null;
}

export const securityKey = (userId: string) => ["security", userId] as const;

/** Recovery kit status, the organisations' admin-recovery policy and escrow holders for the signed-in user. */
export function useSecurity(opts: { enabled?: boolean } = {}) {
  const { user } = useSession();
  return useQuery({ queryKey: securityKey(user?.id ?? ""), queryFn: () => api.get<Security>("/me/security"), enabled: !!user && opts.enabled !== false, staleTime: 60_000 });
}

/** Whether "Ask an admin to reset my password" exists (public, organisation-wide). */
export function useRecoveryOptions() {
  return useQuery({ queryKey: ["recovery-options"], queryFn: () => api.get<{ adminRecoveryEnabled: boolean }>("/auth/recovery/options"), staleTime: 60_000, retry: false });
}

/**
 * The membership job for the active org, once per unlock (and again after an acknowledgement): create my membership
 * key, move my rows to it, rotate it after an admin opened its escrow, rebuild owner rows after a reset (with the
 * folder keys the vault holds) and escrow it to the org's admins while admin recovery is on. Online only.
 */
export function useMembershipSync(folders: VaultFolder[], ready: boolean) {
  const { user, keys, org, generation, offline } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const sec = useSecurity({ enabled: !!keys && !offline });
  const acked = sec.data?.orgs?.find((o) => o.orgId === org?.id)?.ackRequired === false;
  const done = useRef<string | null>(null);
  useEffect(() => {
    if (!user || !keys || !org || offline || !ready) return;
    const marker = `${user.id}:${org.id}:${generation()}:${acked}`;
    if (done.current === marker) return;
    done.current = marker;
    const gen = generation();
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    const copy = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
    const folderKeys = new Map(folders.filter((f) => f.folderKey).map((f) => [f.id, f.folderKey!.slice()] as [string, Uint8Array]));
    void syncMembershipKeys(oapi, org.id, user.id, copy, { folderKeys, assertOpen })
      .then(async (r) => {
        if (r.created || r.rotated || r.moved || r.repaired) await qc.invalidateQueries({ queryKey: ["vault"] });
        if (r.escrowed || r.created) await qc.invalidateQueries({ queryKey: securityKey(user.id) });
      })
      .catch(() => { /* tried again on the next unlock */ })
      .finally(() => { copy.userKey.fill(0); copy.privateKey.fill(0); for (const k of folderKeys.values()) k.fill(0); });
  }, [user, keys, org, offline, ready, acked, folders, oapi, qc, generation]);
}

/** The text of the downloadable recovery kit. */
export function kitText(p: { productName: string; email: string; code: string; createdAt: Date; url: string }): string {
  const date = p.createdAt.toISOString().slice(0, 10);
  return [
    `${p.productName} recovery kit`,
    "=".repeat(`${p.productName} recovery kit`.length),
    "",
    `Account:  ${p.email}`,
    `Created:  ${date}`,
    `Sign in:  ${p.url}`,
    "",
    "Recovery code:",
    "",
    `    ${p.code}`,
    "",
    "What it is",
    "  If you forget your master password, this code lets you set a new one without losing your vault.",
    "  You also need your two-step sign-in code (authenticator app) to use it.",
    "",
    "How to use it",
    `  1. Open ${p.url}/sign-in and choose Need help? → Forgot master password? Use your recovery kit.`,
    "  2. Enter your email, this code and your 6-digit authenticator code.",
    "  3. Choose a new master password. You'll get a new recovery kit straight away; this one stops working.",
    "",
    "Keep it safe",
    "  Print it or store it offline (a safe, a sealed envelope, a separate password manager).",
    "  Anyone with this code AND your authenticator can take over your vault. Never send it by email or chat.",
    "  Making a new kit (Settings → Security) makes this one useless.",
    "",
  ].join("\n");
}

/** Saves text as a file through a Blob URL (works under the app's CSP; nothing is uploaded). */
export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.rel = "noopener"; a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
