import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useParams } from "react-router";
import { Clock, Download, Eye, EyeOff, LinkIcon } from "lucide-react";
import { b64url, deriveLinkAccess, openLink, openPasswordLink, typeLabel, type LinkAttachment, type LinkBody } from "@clane-vault/crypto";
import { DamagedFileError, pickSaveTarget, saveFile } from "@/features/attachments/downloader";
import { fileIcon, formatBytes } from "@/features/attachments/format";
import { isExecutable } from "@/features/attachments/previewSinks";
import { Logo } from "@/components/brand/Logo";
import { productName } from "@/brand";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CopyButton } from "@/features/vault/CopyButton";
import { displayValue, isSecretField, last4, linkFields, lowerFirst } from "@/features/vault/recordKinds";
import { apiUrl } from "@/lib/base";
import { cn } from "@/lib/utils";

type Meta = { needsPassword: boolean; passwordSalt: string | null; expiresAt: string; opensLeft: number | null };
type Opened = { body: LinkBody; expiresAt: string; opensLeft: number | null; downloadToken?: string };
type Failure = "expired" | "revoked" | "used_up" | "not_found" | "incomplete" | "damaged" | "rate_limited" | "network";
type State = { kind: "loading" } | { kind: "ready"; meta: Meta } | { kind: "opened"; data: Opened } | { kind: "failed"; why: Failure };

const FAILURE: Record<Failure, [string, string]> = {
  expired: ["This link has expired", "Ask the person who sent it for a new one."],
  revoked: ["This link was revoked", "The person who sent it turned it off. Ask them for a new one if you still need it."],
  used_up: ["This link has been used up", "It could only be opened a set number of times. Ask the person who sent it for a new one."],
  not_found: ["This link doesn't exist", "Check that you copied the whole link, or ask for a new one."],
  incomplete: ["This link is incomplete", "The part after # is missing. Copy the whole link and try again."],
  damaged: ["This link can't be opened", "The key in the link doesn't match. Copy the whole link and try again."],
  rate_limited: ["Too many requests", "Too many requests — wait a minute and try again."],
  network: [`We couldn't reach ${productName}`, "Check your connection and reload the page."],
};

/** Plain fetch: this page runs without an account and must never send the URL fragment anywhere. */
async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<{ ok: true; data: T } | { ok: false; status: number; error: string }> {
  let res: Response;
  try {
    res = await fetch(apiUrl(`/public/links/${path}`), { method, credentials: "omit", referrerPolicy: "no-referrer", headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  } catch { return { ok: false, status: 0, error: "network" }; }
  const data = await res.json().catch(() => null) as (T & { error?: string }) | null;
  if (!res.ok) return { ok: false, status: res.status, error: data?.error ?? "server_error" };
  return { ok: true, data: data as T };
}

const toFailure = (status: number, error: string): Failure =>
  status === 410 && (error === "expired" || error === "revoked" || error === "used_up") ? error : status === 404 ? "not_found" : status === 429 ? "rate_limited" : "network";

/** Every link carries its 32-byte key after the #; anything else is an incomplete link. */
function validFragment(f: string): boolean {
  try { return b64url.decode(f).length === 32; } catch { return false; }
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <main className="grid min-h-full place-items-center bg-app px-4 py-10">
      <div className="flex w-full max-w-[480px] flex-col items-stretch gap-6">
        <div className="flex justify-center"><Logo size="lg" animated={false} /></div>
        <div className="flex flex-col gap-5 rounded-[14px] border border-border-default bg-card p-8 shadow-[var(--shadow-card)] max-[420px]:p-5">{children}</div>
        <p className="flex items-center justify-center gap-2 text-center font-mono text-[11.5px] text-text-tertiary">
          <span aria-hidden="true" className="size-1.5 rounded-full bg-green-600" />End-to-end encrypted · decrypted in your browser
        </p>
      </div>
    </main>
  );
}

/** One read-only field: secrets hidden until revealed (a card keeps its last four digits), Copy for every value. */
function Field({ label, value, shown: display, secret, multiline, mono = !multiline, card }: { label: string; value: string; shown?: string; secret?: boolean; multiline?: boolean; mono?: boolean; card?: boolean }) {
  const [reveal, setReveal] = useState(!secret);
  const l = lowerFirst(label);
  const mask = card ? `•••• •••• •••• ${last4(value)}` : "•".repeat(14);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2 border-b border-border-default px-4 py-2.5 last:border-b-0">
      <span className="col-span-2 text-[12px] text-text-secondary">{label}</span>
      <span aria-label={label} className={cn(multiline ? "whitespace-pre-wrap" : "", mono ? "font-mono break-all" : "break-words", multiline && mono ? "text-[12.5px]" : "text-[14px]", "max-h-[240px] overflow-y-auto text-text-primary")}>{reveal ? display ?? value : mask}</span>
      <span className="-mr-2 flex items-center gap-0.5 self-start">
        {secret && <Button variant="ghost" size="icon" aria-label={reveal ? `Hide ${l}` : `Show ${l}`} onClick={() => setReveal(!reveal)}>{reveal ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>}
        <CopyButton value={value} label={`Copy ${l}`} />
      </span>
    </div>
  );
}

/** A file the link carries: Download only (never a preview on this unauthenticated page), decrypted in the browser. */
function LinkFile({ linkId, file, token }: { linkId: string; file: LinkAttachment; token?: string }) {
  const [state, setState] = useState<{ busy: string | null; error: string | null; confirm: boolean }>({ busy: null, error: null, confirm: false });
  const Icon = fileIcon(file.meta.mime, file.meta.name);
  async function download() {
    if (!token) return setState({ busy: null, error: "Open the link again to download its files.", confirm: false });
    let target = null;
    try { target = await pickSaveTarget(file.meta.name); } catch (e) { if ((e as Error).name === "AbortError") return; }
    setState({ busy: "0 %", error: null, confirm: false });
    const key = b64url.decode(file.fileKey);
    try {
      await saveFile({ fileId: file.fileId, fileKey: key, nonceBase: b64url.decode(file.nonceBase), meta: file.meta,
        fetchChunk: async (i, signal) => {
          const res = await fetch(apiUrl(`/public/links/${linkId}/attachments/${file.fileId}/chunks/${i}`), { signal, credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer", headers: { authorization: `Bearer ${token}` } });
          if (!res.ok) throw new Error(res.status === 410 ? "revoked" : res.status === 401 ? "expired" : "failed");
          return new Uint8Array(await res.arrayBuffer());
        } }, target, { onProgress: (d) => setState((s) => ({ ...s, busy: `${file.meta.size ? Math.floor((100 * d) / file.meta.size) : 100} %` })) });
      setState({ busy: null, error: null, confirm: false });
    } catch (e) {
      const m = (e as Error).message;
      setState({ busy: null, confirm: false, error: e instanceof DamagedFileError ? e.message : m === "revoked" ? "The link was revoked: its files can't be downloaded any more."
        : m === "expired" ? "The time to download has run out. Ask the person who sent the link for a new one." : "Couldn't download the file. Try again." });
    } finally { key.fill(0); }
  }
  const exe = isExecutable(file.meta.name, file.meta.mime);
  return (
    <li className="flex flex-col gap-2 border-b border-border-default px-4 py-3 last:border-b-0" data-testid="link-file">
      <div className="flex items-center gap-3">
        <Icon className="size-4 shrink-0 text-text-secondary" />
        <span className="min-w-0 flex-1"><span className="block break-all text-[14px] text-text-primary">{file.meta.name}</span><span className="block text-[12px] text-text-secondary">{formatBytes(file.meta.size)}</span></span>
        {state.busy ? <span role="status" className="font-mono text-[11.5px] text-text-tertiary">{state.busy}</span>
          : <Button type="button" variant="outline" size="sm" aria-label={`Download ${file.meta.name}`} onClick={() => (exe ? setState((s) => ({ ...s, confirm: true })) : void download())}><Download className="size-3.5" />Download</Button>}
      </div>
      {state.confirm && (
        <div role="alert" className="flex flex-wrap items-center gap-2 rounded-[10px] border border-amber-500/40 bg-amber-500/10 px-3 py-2">
          <p className="min-w-0 flex-1 text-[12.5px] text-text-primary">{file.meta.name} is a program. Only open it if you expected it.</p>
          <Button type="button" variant="outline" size="sm" onClick={() => void download()}>Download anyway</Button>
        </div>
      )}
      {state.error && <p role="alert" className="text-[12.5px] text-red-500">{state.error}</p>}
    </li>
  );
}

function limitsLine(d: { expiresAt: string; opensLeft: number | null }) {
  const when = new Date(d.expiresAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  if (d.opensLeft == null) return `This link works until ${when}.`;
  if (d.opensLeft === 0) return "This link can't be opened again. Copy what you need now.";
  return `This link can be opened ${d.opensLeft} more ${d.opensLeft === 1 ? "time" : "times"}, until ${when}.`;
}

export default function PublicLinkPage() {
  const { id = "" } = useParams();
  // Read the key once; it stays in memory only. The fragment is never part of any request.
  const fragment = useRef(typeof window !== "undefined" ? window.location.hash.replace(/^#/, "") : "");
  const [state, setState] = useState<State>({ kind: "loading" });
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    if (!validFragment(fragment.current)) { setState({ kind: "failed", why: "incomplete" }); return; }
    void call<Meta>("GET", id).then((r) => {
      if (!alive) return;
      setState(r.ok ? { kind: "ready", meta: r.data } : { kind: "failed", why: toFailure(r.status, r.error) });
    });
    return () => { alive = false; };
  }, [id]);

  function opened(data: Opened) {
    setState({ kind: "opened", data });
    // Drop the key from the address bar and history once it has done its job.
    try { window.history.replaceState(window.history.state, "", window.location.pathname); } catch { /* ignore */ }
  }

  async function openPlain() {
    setBusy(true);
    const r = await call<{ encPayload: string; expiresAt: string; opensLeft: number | null; downloadToken?: string }>("POST", `${id}/open`, {});
    if (!r.ok) { setBusy(false); return setState({ kind: "failed", why: toFailure(r.status, r.error) }); }
    try { opened({ body: await openLink(id, r.data.encPayload, fragment.current), expiresAt: r.data.expiresAt, opensLeft: r.data.opensLeft, downloadToken: r.data.downloadToken }); }
    catch { setState({ kind: "failed", why: "damaged" }); }
    finally { setBusy(false); }
  }

  async function openWithPassword(e: FormEvent, meta: Meta) {
    e.preventDefault();
    if (!password) return setPwError("Enter the password you were given.");
    setBusy(true); setPwError(null);
    try {
      const k = await deriveLinkAccess(password, meta.passwordSalt!, fragment.current);
      try {
        const r = await call<{ encPayload: string; expiresAt: string; opensLeft: number | null; downloadToken?: string }>("POST", `${id}/open`, { accessHash: k.accessHash });
        if (!r.ok) {
          if (r.status === 403) { setPwError("That password isn't right."); return; }
          if (r.status === 429) { setPwError("Too many requests — wait a minute and try again."); return; }
          setState({ kind: "failed", why: toFailure(r.status, r.error) }); return;
        }
        setPassword("");
        opened({ body: await openPasswordLink(id, r.data.encPayload, k.wrapKey), expiresAt: r.data.expiresAt, opensLeft: r.data.opensLeft, downloadToken: r.data.downloadToken });
      } finally { k.wrapKey.fill(0); }
    } catch { setState({ kind: "failed", why: "damaged" }); }
    finally { setBusy(false); }
  }

  if (state.kind === "loading") return <Shell><p role="status" className="py-6 text-center text-[14px] text-text-secondary">Opening link…</p></Shell>;
  if (state.kind === "failed") {
    const [title, line] = FAILURE[state.why];
    return (
      <Shell>
        <div className="flex flex-col items-center gap-3 py-2 text-center" role="alert">
          <span className="grid size-12 place-items-center rounded-full bg-well text-text-tertiary"><Clock className="size-[22px]" /></span>
          <h1 className="text-[20px] leading-tight text-text-primary">{title}</h1>
          <p className="max-w-[340px] text-[14px] leading-relaxed text-text-secondary">{line}</p>
        </div>
      </Shell>
    );
  }
  if (state.kind === "ready") {
    const { meta } = state;
    const pw = meta.needsPassword;
    return (
      <Shell>
        <div className="flex flex-col gap-1.5">
          <h1 className="flex items-center gap-2 text-[22px] leading-tight text-text-primary"><LinkIcon className="size-5 text-blue-500" />Someone shared a record with you</h1>
          <p className="text-[14px] leading-relaxed text-text-secondary">{limitsLine(meta)}{meta.opensLeft != null && " Opening it uses one of them."}</p>
        </div>
        {pw ? (
          <form onSubmit={(e) => openWithPassword(e, meta)} className="flex flex-col gap-3" noValidate>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="pl-pw" className="text-[13px]">Password</Label>
              <Input id="pl-pw" type="password" autoComplete="off" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
              <p className="text-[12px] text-text-tertiary">The person who sent the link gave you this separately.</p>
            </div>
            {pwError && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{pwError}</p>}
            <Button type="submit" disabled={busy}>{busy ? "Checking…" : "Open"}</Button>
          </form>
        ) : (
          <Button type="button" disabled={busy} onClick={openPlain}>{busy ? "Opening…" : "Show the details"}</Button>
        )}
      </Shell>
    );
  }
  const { body, downloadToken, ...limits } = state.data;
  // TOTP fields never travel in a link (crypto drops them); everything else shows read-only.
  const fields = linkFields(body).filter((f) => f.kind !== "totp");
  return (
    <Shell>
      <div className="flex flex-col gap-1">
        <h1 className="text-[22px] leading-tight break-words text-text-primary">{body.title}</h1>
        <p className="text-[13.5px] text-text-secondary">{body.type && body.type !== "login" ? `${typeLabel(body.type)} · ` : ""}{limitsLine(limits)}</p>
      </div>
      {fields.length > 0 && (
        <div className="overflow-hidden rounded-[12px] border border-border-default">
          {fields.map((f) => (
            <Field key={f.id} label={f.label} value={f.value} shown={displayValue(f)} secret={isSecretField(f)} card={f.format === "cardNumber"}
              multiline={f.kind === "multiline" || f.kind === "hiddenMultiline"} mono={f.mono || !!f.format || f.kind === "hiddenMultiline"} />
          ))}
        </div>
      )}
      {body.notes && <div className="overflow-hidden rounded-[12px] border border-border-default"><Field label="Notes" value={body.notes} multiline /></div>}
      {!!body.attachments?.length && (
        <section aria-label="Files" className="flex flex-col gap-2">
          <h2 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Files · {body.attachments.length}</h2>
          <ul className="overflow-hidden rounded-[12px] border border-border-default">{body.attachments.map((f) => <LinkFile key={f.fileId} linkId={id} file={f} token={downloadToken} />)}</ul>
          <p className="text-[12px] text-text-tertiary">Files are decrypted in your browser. Download them within 30 minutes of opening the link.</p>
        </section>
      )}
      <p className="text-[12.5px] text-text-tertiary">Copied values clear from your clipboard after 30 seconds. Closing this page doesn't give the link back an open.</p>
    </Shell>
  );
}
