import { useEffect, useId, useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Download, KeyRound, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { createRecoveryKit, lastRecoveryGroup, normalizeRecoveryCode, type RecoveryKit } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";
import { copySecret } from "@/lib/clipboard";
import { useSession } from "@/lib/session";
import { productName } from "@/brand";
import { downloadText, kitText, securityKey } from "./recovery";
import { appUrl } from "@/lib/base";

export type KitMode = "signup" | "recovery" | "create" | "regenerate";

const INTRO: Record<KitMode, string> = {
  signup: "If you ever forget your master password, this code lets you set a new one without losing your vault. It's shown once.",
  recovery: "Your old recovery kit was used up. Save this new one now; it's shown once.",
  create: "If you ever forget your master password, this code lets you set a new one without losing your vault. It's shown once.",
  regenerate: "Your current kit stops working as soon as you save this new one. It's shown once.",
};

/** Master password check before the kit can change (the server asks for proof too). */
function PasswordStep({ onProof, onCancel }: { onProof: (authKey: string) => void; onCancel?: () => void }) {
  const { proveMaster } = useSession();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try { onProof(await proveMaster(pw)); } catch (err) { setError(`${(err as Error).message}.`); } finally { setBusy(false); setPw(""); }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <p className="text-[14px] text-text-secondary">Enter your master password to continue.</p>
      <div className="flex flex-col gap-1.5"><Label htmlFor="kit-pw">Master password</Label>
        <Input id="kit-pw" type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      <div className="flex justify-end gap-2">
        {onCancel && <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>}
        <Button type="submit" disabled={busy || !pw}>{busy ? "Checking…" : "Continue"}</Button>
      </div>
    </form>
  );
}

/**
 * Creates (or replaces) the recovery kit: generates it on this device, shows the code once, asks the person to
 * confirm they saved it (type the last group or tick the box), and only then stores it on the server.
 */
export function RecoveryKitPanel({ mode, onDone, onCancel }: { mode: KitMode; onDone: () => void; onCancel?: () => void }) {
  const { user, keys, kitProof, kitCreated } = useSession();
  const qc = useQueryClient();
  const [proof, setProof] = useState<string | null>(() => kitProof());
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [createdAt] = useState(() => new Date());
  const [typed, setTyped] = useState("");
  const [ticked, setTicked] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tickId = useId();

  useEffect(() => {
    if (!proof || !user || !keys || kit) return;
    let live = true;
    void createRecoveryKit(user.id, keys.userKey).then((k) => { if (live) setKit(k); });
    return () => { live = false; };
  }, [proof, user, keys, kit]);

  if (!user || !keys) return null;
  if (!proof) return <PasswordStep onProof={setProof} onCancel={onCancel} />;
  if (!kit) return <p role="status" className="text-[14px] text-text-secondary">Creating your recovery kit…</p>;

  const last = lastRecoveryGroup(kit.code);
  const typedOk = normalizeRecoveryCode(typed) === last;
  const confirmed = typedOk || ticked;
  const fileName = `${productName.replace(/[^A-Za-z0-9]+/g, "-")}-recovery-kit.txt`;

  async function save() {
    if (!kit || !proof || !confirmed) return;
    setBusy(true); setError(null);
    try {
      await api.post("/me/recovery-kit", { authKey: proof, recoveryWrap: kit.recoveryWrap, recoveryAuth: kit.recoveryAuth });
      kitCreated();
      await qc.invalidateQueries({ queryKey: securityKey(user!.id) });
      toast.success(mode === "regenerate" ? "New recovery kit saved. The old one no longer works." : "Recovery kit saved");
      onDone();
    } catch (e) {
      if (e instanceof ApiError && e.code === "invalid_credentials") { setProof(null); setError(null); return; }
      if (e instanceof ApiError && e.code === "locked") { setError("Too many failed attempts. Try again later."); return; }
      setError("Couldn't save your recovery kit. Check your connection and try again.");
    } finally { setBusy(false); }
  }

  return (
    <div className="flex flex-col gap-5">
      <p className="text-[14px] leading-relaxed text-text-secondary">{INTRO[mode]}</p>
      <div className="flex flex-col gap-2 rounded-[12px] border border-border-default bg-well p-4" aria-label="Recovery code" role="group">
        <p className="flex items-center gap-2 font-mono text-[10.5px] tracking-[.1em] text-text-tertiary uppercase"><KeyRound className="size-3.5" />Recovery code · {user.email}</p>
        <code data-testid="recovery-code" className="font-mono text-[15px] leading-[1.9] tracking-[.06em] break-words text-text-primary select-all">{kit.code}</code>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" onClick={() => downloadText(fileName, kitText({ productName, email: user.email, code: kit.code, createdAt, url: appUrl() }))}>
          <Download className="size-4" />Download recovery kit
        </Button>
        <Button type="button" variant="ghost" onClick={async () => { try { await copySecret(kit.code, 60_000); setCopied(true); toast.success("Recovery code copied"); setTimeout(() => setCopied(false), 1500); } catch { toast.error("Couldn't copy"); } }}>
          {copied ? <Check className="size-4" /> : <Copy className="size-4" />}Copy code
        </Button>
      </div>
      <div className="rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[13px] leading-relaxed text-orange-ink">
        Print it or keep it offline. Anyone with this code and your authenticator can reset your master password. You also need your authenticator to use it.
      </div>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5"><Label htmlFor="kit-last">Type the last group of your code ({last.length} characters)</Label>
          <Input id="kit-last" autoComplete="off" spellCheck={false} maxLength={9} className="w-[160px] font-mono tracking-[.2em] uppercase" value={typed} onChange={(e) => setTyped(e.target.value)}
            aria-invalid={typed.length >= last.length && !typedOk ? true : undefined} />
        </div>
        <label htmlFor={tickId} className="flex items-center gap-2.5 text-[13.5px] text-text-primary">
          <input id={tickId} type="checkbox" className="size-4 accent-[var(--blue-500,#2563eb)]" checked={ticked} onChange={(e) => setTicked(e.target.checked)} />
          I saved my recovery kit somewhere safe
        </label>
      </div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      <div className="flex justify-end gap-2">
        {onCancel && <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>}
        <Button type="button" variant="cta" onClick={save} disabled={!confirmed || busy}><ShieldCheck className="size-4" />{busy ? "Saving…" : mode === "regenerate" ? "Replace my recovery kit" : "Save recovery kit"}</Button>
      </div>
    </div>
  );
}
