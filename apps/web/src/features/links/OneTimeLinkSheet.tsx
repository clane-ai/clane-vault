import { useState, type FormEvent } from "react";
import { Check, Copy, Eye, EyeOff, KeyRound, Link2, LockKeyhole, Paperclip } from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { copySecret } from "@/lib/clipboard";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import type { VaultRecord } from "@/features/vault/types";
import { opensText, stateLabel, useLinks, type ShareLink } from "./useLinks";
import { useOrgPolicies } from "@/lib/policies";
import { useAttachmentLimits, useFileRows, type FileRow } from "@/features/attachments/useAttachments";
import { formatBytes } from "@/features/attachments/format";

/** A link carries at most this much in files (the server checks it too). */
const LINK_FILES_MAX = 100 * 1024 * 1024;

/**
 * The files of a record a link may carry: every one off by default, with the total and what including them means.
 * Hidden when the org's policy keeps files out of links, or the record has none the creator can open.
 */
function LinkFilesPicker({ record, picked, onChange }: { record: VaultRecord; picked: Set<string>; onChange: (s: Set<string>) => void }) {
  const policy = useOrgPolicies();
  const limits = useAttachmentLimits();
  const allowed = policy.links.allowAttachments && limits.enabled;
  const rows = useFileRows(record).rows.filter((r) => r.meta && r.att.wrappedFileKey);
  if (!allowed || !rows.length) return null;
  const total = rows.filter((r) => picked.has(r.att.id)).reduce((s, r) => s + r.size, 0);
  const toggle = (id: string) => { const n = new Set(picked); n.has(id) ? n.delete(id) : n.add(id); onChange(n); };
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-2 flex w-full items-baseline justify-between text-[13px] font-medium text-text-primary">
        <span className="flex items-center gap-1.5"><Paperclip className="size-3.5" />Include files</span>
        {picked.size > 0 && <span className="font-mono text-[11.5px] font-normal text-text-tertiary">{picked.size} · {formatBytes(total)}</span>}
      </legend>
      <ul className="overflow-hidden rounded-[10px] border border-border-default bg-card">
        {rows.map((r) => (
          <li key={r.att.id} className="border-b border-border-default last:border-b-0">
            <label className="flex cursor-pointer items-center gap-3 px-3 py-2.5 text-[13.5px] text-text-primary">
              <input type="checkbox" className="size-4 accent-[var(--blue-500)]" checked={picked.has(r.att.id)} onChange={() => toggle(r.att.id)} aria-label={`Include ${r.meta!.name}`} />
              <span className="min-w-0 flex-1 truncate">{r.meta!.name}</span>
              <span className="font-mono text-[11.5px] text-text-tertiary">{formatBytes(r.size)}</span>
            </label>
          </li>
        ))}
      </ul>
      {picked.size > 0 && (
        <p className="flex items-start gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[12.5px] leading-snug text-orange-ink">
          <KeyRound className="mt-0.5 size-3.5 shrink-0" />The link carries the keys to these files. Anyone with the link can download them until it expires.
        </p>
      )}
      {total > LINK_FILES_MAX && <p role="alert" className="text-[12.5px] text-red-500">A link can carry at most {formatBytes(LINK_FILES_MAX)} of files.</p>}
    </fieldset>
  );
}

function Choice<T extends string | number | null>({ label, value, options, onChange }: { label: string; value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <fieldset className="flex min-w-0 flex-col">
      <legend className="mb-2 text-[13px] font-medium text-text-primary">{label}</legend>
      <div className="grid h-10 grid-cols-3 gap-1 rounded-[10px] border border-border-default bg-well p-[3px]" role="radiogroup" aria-label={label}>
        {options.map(([v, text]) => (
          <button key={String(v)} type="button" role="radio" aria-checked={value === v} onClick={() => onChange(v)}
            className={cn("min-w-0 truncate rounded-[7px] px-2 text-[13px] transition-[color,background-color,box-shadow] duration-150 outline-none focus-visible:ring-3 focus-visible:ring-ring/25",
              value === v ? "bg-card font-medium text-text-primary shadow-[var(--shadow-card)] ring-1 ring-border-default" : "text-text-secondary hover:text-text-primary")}>
            {text}
          </button>
        ))}
      </div>
    </fieldset>
  );
}

export function LinkRow({ l, title, onRevoke }: { l: ShareLink; title?: string; onRevoke: (l: ShareLink) => void }) {
  const active = l.state === "active";
  return (
    <li className="flex items-center gap-3 border-b border-border-default px-4 py-3 last:border-b-0">
      <span className={cn("grid size-8 shrink-0 place-items-center rounded-[8px]", active ? "bg-blue-tint text-blue-500" : "bg-well text-text-tertiary")}><Link2 className="size-4" /></span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[14px] font-medium text-text-primary">
          {title ? `${title}${l.label ? ` · for ${l.label}` : ""}` : (l.label ? `For ${l.label}` : l.createdByMe === false ? "Created by someone else" : "One-time link")}
          {l.hasPassword && <LockKeyhole className="ml-1.5 inline size-3.5 text-text-tertiary" aria-label="Password protected" />}
        </span>
        <span className="block text-[12.5px] leading-snug text-text-secondary">
          {active ? `Expires ${relativeTime(l.expiresAt)}` : stateLabel(l.state)} · {opensText(l)}
        </span>
      </span>
      {active
        ? <Button variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" aria-label={`Revoke link${l.label ? ` for ${l.label}` : ""}`} onClick={() => onRevoke(l)}>Revoke</Button>
        : <span className="rounded-[6px] bg-well px-1.5 py-px font-mono text-[11px] text-text-tertiary">{stateLabel(l.state)}</span>}
    </li>
  );
}

/**
 * The one-time link form for one record: create a link, then copy it; existing links for the record with Revoke.
 * Fills a sheet's body and sticky footer: the standalone One-time link sheet, or the Share sheet's "One-time link" tab (`inline`).
 */
export function OneTimeLinkForm({ record, inline, onClose }: { record: VaultRecord; inline?: boolean; onClose?: () => void }) {
  const { links, create, revoke } = useLinks(record.id);
  const [label, setLabel] = useState("");
  const [hours, setHours] = useState<1 | 24 | 168>(24);
  const [maxOpens, setMaxOpens] = useState<1 | 3 | null>(1);
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ url: string; hasPassword: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const fileRows = useFileRows(record).rows;
  const title = record.body?.title;

  const reset = () => { setLabel(""); setHours(24); setMaxOpens(1); setPassword(""); setShowPw(false); setCreated(null); setError(null); setCopied(false); setPicked(new Set()); };

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const files: FileRow[] = fileRows.filter((f) => picked.has(f.att.id));
      if (files.reduce((s, f) => s + f.size, 0) > LINK_FILES_MAX) { setError(`A link can carry at most ${formatBytes(LINK_FILES_MAX)} of files.`); return; }
      const r = await create({ record, label, expiresInHours: hours, maxOpens, password, files });
      setCreated({ url: r.url, hasPassword: !!password });
      setPassword("");
    } catch (err) {
      // The organisation's link policy (docs/policies.md), enforced by the server.
      const c = err instanceof ApiError ? err.code : "";
      const max = (err instanceof ApiError ? (err.body as { maxExpiryHours?: number } | null)?.maxExpiryHours : undefined) ?? 0;
      setError(c === "links_disabled" ? "Your organisation has turned one-time links off."
        : c === "link_password_required" ? "Your organisation requires a password on one-time links. Add one below."
        : c === "link_expiry_too_long" ? `Your organisation allows links for at most ${max === 1 ? "1 hour" : max === 24 ? "24 hours" : "7 days"}. Pick a shorter expiry.`
        : c === "link_attachments_disabled" ? "Your organisation doesn't allow files in one-time links. Untick the files."
        : c === "link_files_too_large" ? `A link can carry at most ${formatBytes(LINK_FILES_MAX)} of files.`
        : "Couldn't create the link. Try again.");
    }
    finally { setBusy(false); }
  }

  async function onRevoke(l: ShareLink) {
    try { await revoke(l.id); toast.success("Link revoked"); } catch { toast.error("Couldn't revoke the link. Try again."); }
  }

  const done = () => { onClose?.(); reset(); };
  const expiresText = hours === 1 ? "1 hour" : hours === 24 ? "24 hours" : "7 days";

  return created ? (
    <>
      <SheetBody className="gap-5 pt-5">
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[9px] bg-green-tint text-green-600"><Check className="size-4.5" /></span>
          <div className="min-w-0">
            <p className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Link ready</p>
            <p className="text-[13px] leading-snug text-text-secondary">
              It shows {title ?? "the record"} {maxOpens === 1 ? "once" : maxOpens === 3 ? "up to 3 times" : "until it expires"} and expires in {expiresText}.
            </p>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <span className="text-[13px] font-medium text-text-primary">Link to send</span>
          <div className="overflow-hidden rounded-[10px] border border-border-default bg-app">
            <code aria-label="Link to send" className="block max-h-28 overflow-y-auto px-3 py-2.5 font-mono text-[12.5px] leading-relaxed break-all text-text-primary select-all">{created.url}</code>
            <div className="flex items-center justify-between gap-2 border-t border-border-default bg-card px-3 py-2">
              <span className="flex min-w-0 items-center gap-1.5 text-[12px] text-text-tertiary">
                {created.hasPassword ? <><LockKeyhole className="size-3.5 shrink-0" />Password protected</> : <><Link2 className="size-3.5 shrink-0" />Anyone with the link</>}
              </span>
              <Button type="button" size="sm" variant={copied ? "outline" : "default"} className={cn("min-w-[104px]", copied && "text-green-600")}
                onClick={async () => { await copySecret(created.url); setCopied(true); toast.success("Link copied. Clipboard clears in 30 s"); }}>
                {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}{copied ? "Copied" : "Copy link"}
              </Button>
            </div>
          </div>
        </div>
        {created.hasPassword && (
          <p className="flex items-start gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5 text-[13px] leading-snug text-orange-ink">
            <KeyRound className="mt-0.5 size-3.5 shrink-0" />The link alone won't open it: send the password another way, for example by phone.
          </p>
        )}
        <p className="text-[12.5px] leading-snug text-text-tertiary">The key is in the part after #. It never reaches our server, so we can't show this link again.</p>
      </SheetBody>
      <SheetFooter>
        <Button type="button" variant="ghost" onClick={reset}>Create another</Button>
        <Button type="button" className="min-w-24" onClick={done}>Done</Button>
      </SheetFooter>
    </>
  ) : (
    <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col" noValidate>
      <SheetBody className="gap-5 pt-5">
        <p className="text-[13px] leading-snug text-text-secondary">Send {title ?? "this record"} to someone outside the team. They see its fields, not your vault, and the link stops working when it runs out.</p>
        <div className="flex flex-col gap-2">
          <Label htmlFor="ln-label" className="text-[13px] font-medium text-text-primary">Who it's for</Label>
          <Input id="ln-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Acme Ltd, Jane" maxLength={120} />
          <p className="text-[12px] text-text-tertiary">Only you see this, to recognise the link later.</p>
        </div>
        <Choice label="Expires" value={hours} onChange={setHours} options={[[1, "1 hour"], [24, "24 hours"], [168, "7 days"]]} />
        <Choice label="Can be opened" value={maxOpens} onChange={setMaxOpens} options={[[1, "Once"], [3, "3 times"], [null, "Until expiry"]]} />
        <div className="flex flex-col gap-2">
          <Label htmlFor="ln-pw" className="text-[13px] font-medium text-text-primary">Password (optional)</Label>
          <div className="relative">
            <Input id="ln-pw" type={showPw ? "text" : "password"} autoComplete="new-password" spellCheck={false} value={password} onChange={(e) => setPassword(e.target.value)} className="pr-11" />
            <Button type="button" variant="ghost" size="icon" aria-label={showPw ? "Hide link password" : "Show link password"} aria-pressed={showPw}
              className="absolute top-1 right-1" onClick={() => setShowPw((v) => !v)}>
              {showPw ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </Button>
          </div>
          <p className="text-[12px] leading-snug text-text-tertiary">They'll need the link and this password. Send the password another way, for example by phone.</p>
        </div>
        <LinkFilesPicker record={record} picked={picked} onChange={setPicked} />
        {error && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{error}</p>}
        {links.length > 0 && (
          <section aria-label="Links for this record" className="flex flex-col gap-2.5 border-t border-border-default pt-5">
            <div className="flex items-baseline justify-between">
              <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Links for this record</h3>
              <span className="font-mono text-[11px] text-text-tertiary">{links.length}</span>
            </div>
            <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">{links.map((l) => <LinkRow key={l.id} l={l} onRevoke={onRevoke} />)}</ul>
          </section>
        )}
      </SheetBody>
      <SheetFooter>
        <Button type="button" variant="ghost" onClick={() => onClose?.()}>{inline ? "Close" : "Cancel"}</Button>
        <Button type="submit" disabled={busy || !record.body} className="min-w-28">{busy ? (password ? "Securing…" : "Creating…") : "Create link"}</Button>
      </SheetFooter>
    </form>
  );
}

/** "One-time link" sheet for one record, for people who can edit it but not share it (record owners use the Share sheet's tab). */
export function OneTimeLinkSheet({ record, open, onOpenChange }: { record: VaultRecord; open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="data-[side=right]:w-full data-[side=right]:sm:max-w-[440px]">
        <SheetHeader><SheetTitle className="font-display text-[18px] font-semibold tracking-[-0.02em]">One-time link</SheetTitle><SheetCloseButton /></SheetHeader>
        {/* Remounts per open, so a reopened sheet starts with an empty form. */}
        {open && <OneTimeLinkForm record={record} onClose={() => onOpenChange(false)} />}
      </SheetContent>
    </Sheet>
  );
}
