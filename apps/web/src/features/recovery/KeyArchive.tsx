import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { History } from "lucide-react";
import { toast } from "sonner";
import {
  b64url, deriveLoginKeys, keysFromUserKey, openRecoveryWrap, parseRecoveryCode, recoveryAuthFor, reencryptPrivateFolderName, rewrapOwnerRecordKey, unlockAccount,
  unlockMembershipKeys, wrapMembershipKeys, RecoveryCodeError, type AccountMaterial, type KdfParams, type SealKeys, type UnlockedKeys,
} from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, forOrg } from "@/lib/api";
import { useSession } from "@/lib/session";
import { syncMembershipKeys } from "@/lib/orgKeys";
import { securityKey, useSecurity } from "./recovery";

interface Archive {
  id: string; userKeyGen: number; kdfSalt: string; kdfParams: KdfParams; wrappedUserKey: string; publicKey: string; wrappedPrivateKey: string; recoveryWrap: string | null;
  membershipKeys: { orgId: string; publicKey: string; wrappedPrivateKey: string }[];
}

/**
 * Restoring what an admin recovery (a scoped reset) left behind: the old recovery kit or the old master password opens
 * the archived user key on this device, then private items, other organisations' keys and rows sealed to the old
 * account key are re-wrapped under the current keys (docs/design/2026-10-08-per-org-keypairs.md §6.4).
 */
export function KeyArchiveSection() {
  const { user, keys, orgs, generation } = useSession();
  const qc = useQueryClient();
  const a = useSecurity().data?.keyArchive;
  const [mode, setMode] = useState<"kit" | "password">("kit");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!a || !user) return null;
  const api0 = forOrg(null);

  async function restore(e: FormEvent) {
    e.preventDefault();
    if (!keys || !user) return;
    setBusy(true); setError(null);
    const gen = generation();
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    const now: UnlockedKeys = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
    let old: UnlockedKeys | null = null;
    let arch: Archive;
    try {
      // The server hands out the old key material only for proof of the old password or old kit (never for a session and
      // a 2FA code alone): the old KDF parameters come first, to derive the old auth key on this device.
      const { archives: list } = await api0.get<{ archives: { id: string; hasKit: boolean; kdfSalt: string; kdfParams: KdfParams }[] }>("/me/key-archive");
      const meta = list.find((x) => x.id === a!.id) ?? list[0];
      if (!meta) throw new Error("Nothing to restore");
      const wrong = mode === "kit" ? "That isn't the recovery kit from before the reset" : "That isn't your master password from before the reset";
      let rk: Uint8Array | null = null, wrapKey: Uint8Array | null = null;
      try {
        let proof: { authKey: string } | { recoveryAuth: string };
        if (mode === "kit") {
          if (!meta.hasKit) throw new Error("There was no recovery kit before the reset. Use your old master password.");
          rk = await parseRecoveryCode(secret);
          proof = { recoveryAuth: await recoveryAuthFor(rk) };
        } else {
          const derived = await deriveLoginKeys(secret, meta.kdfSalt, meta.kdfParams);
          wrapKey = derived.wrapKey;
          proof = { authKey: derived.authKey };
        }
        const opened = await api0.post<{ archives: Archive[] }>("/me/key-archive/open", { code, id: meta.id, ...proof })
          .catch((err: unknown) => { if (err instanceof ApiError && err.code === "invalid_credentials") throw new Error(wrong); throw err; });
        const arch0 = opened.archives[0];
        if (!arch0) throw new Error("Nothing to restore");
        arch = arch0;
        if (rk) {
          if (!arch.recoveryWrap) throw new Error("There was no recovery kit before the reset. Use your old master password.");
          const uk = await openRecoveryWrap(user.id, rk, arch.recoveryWrap).catch(() => { throw new Error(wrong); });
          old = await keysFromUserKey(uk, arch);
        } else {
          try { old = await unlockAccount(wrapKey!, arch as unknown as AccountMaterial); } catch { throw new Error(wrong); }
        }
      } finally { rk?.fill(0); wrapKey?.fill(0); }
      // Private items: owner rows and private folder names, from the old user key to the current one.
      let after: string | null = null;
      do {
        const page: { rows: { recordId: string; wrappedRecordKey: string }[]; after: string | null } = await api0.get(`/me/owner-rows${after ? `?after=${after}` : ""}`);
        const rows = [];
        for (const r of page.rows) { try { rows.push({ recordId: r.recordId, from: r.wrappedRecordKey, wrappedRecordKey: await rewrapOwnerRecordKey(r.recordId, r.wrappedRecordKey, old.userKey, now.userKey) }); } catch { /* already current */ } }
        assertOpen();
        if (rows.length) await api0.put("/me/owner-rows", { rows });
        after = page.after;
      } while (after);
      const { folders } = await api0.get<{ folders: { id: string; encName: string }[] }>("/me/private-folders");
      const names = [];
      for (const f of folders) { try { names.push({ folderId: f.id, from: f.encName, encName: await reencryptPrivateFolderName(f.id, f.encName, old.userKey, now.userKey) }); } catch { /* already current */ } }
      assertOpen();
      for (let i = 0; i < names.length; i += 200) await api0.put("/me/private-folders", { folders: names.slice(i, i + 200) });
      // Other organisations' membership keys.
      const back = [];
      for (const k of arch.membershipKeys) {
        try { const mk = await unlockMembershipKeys(old.userKey, { orgId: k.orgId, userId: user.id }, k); back.push({ orgId: k.orgId, ...(await wrapMembershipKeys(now.userKey, { orgId: k.orgId, userId: user.id }, mk)) }); mk.privateKey.fill(0); }
        catch { /* skipped */ }
      }
      assertOpen();
      if (back.length) await api0.post(`/me/key-archive/${arch.id}/memberships`, { keys: back });
      // Rows sealed to the old account key, in every organisation this session can reach.
      const oldAccounts = new Map<string, SealKeys>([[b64url.encode(old.publicKey), old]]);
      for (const o of orgs) { try { await syncMembershipKeys(forOrg(o.id), o.id, user.id, now, { oldAccounts, assertOpen }); } catch { /* that org later */ } }
      await api0.post(`/me/key-archive/${arch.id}/restored`);
      await Promise.all([qc.invalidateQueries({ queryKey: securityKey(user.id) }), qc.invalidateQueries({ queryKey: ["vault"] })]);
      toast.success("Restored what was locked from before your reset");
      setSecret(""); setCode("");
    } catch (err) {
      setError(err instanceof RecoveryCodeError ? "That isn't a recovery code. Check it and try again."
        : err instanceof ApiError ? (err.code === "totp_invalid" ? "That code didn't work. Wait for the next code and try again." : err.code === "totp_step_up_required" ? "Confirm your two-step code for this session first." : "Couldn't restore. Try again.")
        : (err as Error).message);
    } finally {
      now.userKey.fill(0); now.privateKey.fill(0); old?.userKey.fill(0); old?.privateKey.fill(0);
      setBusy(false);
    }
  }

  async function forget() {
    if (!window.confirm("Forget what's left from before your reset? Your old recovery kit and old master password will no longer open anything.")) return;
    try { await api0.del(`/me/key-archive/${a!.id}`); await qc.invalidateQueries({ queryKey: securityKey(user!.id) }); toast.success("Forgotten"); }
    catch { toast.error("Couldn't do that. Try again."); }
  }

  const lost = [a.privateItems ? `${a.privateItems} private ${a.privateItems === 1 ? "item" : "items"}` : null, a.otherOrgs ? `${a.otherOrgs} other ${a.otherOrgs === 1 ? "organisation" : "organisations"}` : null].filter(Boolean).join(" and ");
  return (
    <section aria-label="From before your reset" className="flex gap-3 rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]">
      <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><History className="size-4" /></span>
      <form onSubmit={restore} className="flex min-w-0 flex-1 flex-col gap-3">
        <div>
          <p className="text-[14px] font-medium text-text-primary">From before your password reset ({new Date(a.archivedAt).toLocaleDateString()})</p>
          <p className="text-[13px] leading-relaxed text-text-secondary">{lost ? `${lost} stayed locked: an admin can only restore their own organisation.` : "Nothing was left behind."} Your recovery kit or master password from before the reset brings everything back.</p>
        </div>
        <div className="flex gap-2 text-[13px]" role="radiogroup" aria-label="Restore with">
          <label className="flex items-center gap-1.5"><input type="radio" name="arch-mode" checked={mode === "kit"} onChange={() => setMode("kit")} />Old recovery kit</label>
          <label className="flex items-center gap-1.5"><input type="radio" name="arch-mode" checked={mode === "password"} onChange={() => setMode("password")} />Old master password</label>
        </div>
        <div className="flex flex-col gap-1.5"><Label htmlFor="arch-secret">{mode === "kit" ? "Recovery code from before the reset" : "Master password from before the reset"}</Label>
          <Input id="arch-secret" type={mode === "kit" ? "text" : "password"} autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} /></div>
        <div className="flex flex-col gap-1.5"><Label htmlFor="arch-code">6-digit code from your authenticator app</Label>
          <Input id="arch-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-[180px] font-mono tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></div>
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <div className="flex flex-wrap justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => void forget()}>Forget it</Button>
          <Button type="submit" disabled={busy || !secret || code.length !== 6 || !keys}>{busy ? "Restoring…" : "Restore"}</Button>
        </div>
      </form>
    </section>
  );
}
