/** `.env file` items (spec §10.4): the read-only entry list, the editor's Contents field, and the file in and out. */
import { useId, useRef, useState, type DragEvent } from "react";
import { Download, Eye, EyeOff, FileUp, Plus } from "lucide-react";
import { checkEnvContent, diffEnv, ENV_KEY, envEntries, envFileName, envKeys, envValue, MAX_ENV_BYTES, parseEnv, setEnvEntry } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { CopyButton } from "./CopyButton";

/* eslint-disable react-refresh/only-export-components */
export const TOO_LARGE = "This file is too large for a .env item (32 KB). Attach it to a Secure note instead.";
export const NOT_TEXT = "This file isn't UTF-8 text. Attach it to a Secure note instead.";
const TOO_MANY = "This file has more than 500 entries. Attach it to a Secure note instead.";
const BAD_KEY = "A key is letters, digits, _ . or -, at most 128 characters.";

/** checkEnvContent's refusal in the words the person sees; null when the text is fine. */
export function envContentError(text: string): string | null {
  try { checkEnvContent(text); return null; } catch (e) {
    const m = (e as Error).message;
    return /too large/.test(m) ? TOO_LARGE : /entries/.test(m) ? TOO_MANY : NOT_TEXT;
  }
}

/** Bytes → text, losslessly (the BOM is kept): refused before reading when too large, and when not strict UTF-8. */
export async function readEnvFile(file: File): Promise<string> {
  if (file.size > MAX_ENV_BYTES) throw new Error(TOO_LARGE);
  const bytes = await file.arrayBuffer();
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { throw new Error(NOT_TEXT); }
  const why = envContentError(text);
  if (why) throw new Error(why);
  return text;
}

/** `.env.production` and `production.env` → "production"; `.env` → "". */
export const environmentOf = (fileName: string): string => /^\.env\.(.+)$/.exec(fileName)?.[1] ?? /^(.+)\.env$/.exec(fileName)?.[1] ?? "";

/** A text area turns "\r\n" into "\n": put it back when the stored text used it. */
export const keepEol = (stored: string, edited: string): string => (stored.includes("\r\n") ? edited.replace(/\r?\n/g, "\r\n") : edited);

/** Saves exactly the stored text (as UTF-8) under the item's file name when that is a plain name, else `.env`. */
export function downloadEnv(content: string, fileName?: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = envFileName(fileName);
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const invalidText = (n: number) => (n === 1 ? "1 line isn't KEY=value. It is kept as it is." : `${n} lines aren't KEY=value. They are kept as they are.`);
function InvalidLines({ content }: { content: string }) {
  const n = parseEnv(content).filter((l) => l.kind === "invalid").length;
  return n ? <p className="text-[12px] leading-snug text-text-tertiary">{invalidText(n)}</p> : null;
}
const MASK = "•".repeat(14);
const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** Read-only rows: key, masked value, Show (absent with useOnly), Copy. Earlier duplicates carry "Overridden below". */
export function EnvEntries({ content, useOnly = false }: { content: string; useOnly?: boolean }) {
  const [shown, setShown] = useState<Set<number>>(new Set());
  const toggle = (i: number) => setShown((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n; });
  const entries = envEntries(content);
  return (
    <>
      {entries.length > 0 && (
        <ul aria-label="Entries" className="overflow-hidden rounded-[12px] border border-border-default">
          {entries.map((e, i) => {
            const open = shown.has(i) && !useOnly;
            return (
              <li key={i} className="grid min-h-[48px] grid-cols-[minmax(0,2fr)_minmax(0,3fr)_auto] items-center gap-x-3 border-b border-border-default px-4 py-2 last:border-b-0 max-[760px]:grid-cols-[minmax(0,1fr)_auto]">
                <span className="min-w-0 max-[760px]:col-span-2">
                  <span className="block font-mono text-[12.5px] break-all text-text-secondary">{e.key}</span>
                  {e.overridden && <span className="block text-[11.5px] text-text-tertiary">Overridden below</span>}
                </span>
                <span aria-label={`${e.key} value`} className="min-w-0 font-mono text-[13px] break-all whitespace-pre-wrap text-text-primary">
                  {open ? (e.value || <span className="text-text-tertiary">Empty</span>) : MASK}
                </span>
                <span className="-mr-2 flex items-center gap-0.5">
                  {!useOnly && <Button variant="ghost" size="icon" aria-label={open ? `Hide ${e.key}` : `Show ${e.key}`} aria-pressed={open} onClick={() => toggle(i)}>{open ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>}
                  <CopyButton value={e.value} label={`Copy ${e.key}`} />
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {useOnly && <p className="text-[12px] text-text-secondary">Use only: you can copy values, not view them.</p>}
      <InvalidLines content={content} />
    </>
  );
}

/** Keys only, never values: Added / Changed / Removed from `before` to `after`; a group with no key is left out. */
export function EnvDiff({ before, after }: { before: string; after: string }) {
  const d = diffEnv(before, after);
  const groups = ([["Added", d.added], ["Changed", d.changed], ["Removed", d.removed]] as const).filter(([, keys]) => keys.length);
  if (!groups.length) return <p className="text-[12.5px] text-text-secondary">No differences.</p>;
  return (
    <ul aria-label="Differences" className="flex flex-col gap-0.5 text-[12.5px] text-text-secondary">
      {groups.map(([label, keys]) => <li key={label}>{label}: <span className="font-mono break-all text-text-primary">{keys.join(", ")}</span></li>)}
    </ul>
  );
}

/** The panel's part for an env file: Copy all and Download above the entry list. */
export function EnvPanelSection({ content, fileName, useOnly }: { content: string; fileName?: string; useOnly: boolean }) {
  return (
    <section aria-label="Entries in this file" className="flex flex-col gap-2">
      <div className="flex items-center gap-1">
        <h3 className={cn(eyebrow, "mr-auto")}>Entries</h3>
        <span className="flex items-center gap-1 rounded-[8px] border border-border-default pl-2 text-[12.5px] text-text-secondary"><span aria-hidden="true">Copy all</span><CopyButton value={content} label="Copy all" /></span>
        {!useOnly && <Button variant="outline" size="sm" onClick={() => downloadEnv(content, fileName)}><Download className="size-3.5" />Download</Button>}
      </div>
      <EnvEntries content={content} useOnly={useOnly} />
    </section>
  );
}

/** The editor's Contents field: drop zone + Choose file, entries as masked inputs, Add entry, and Edit as text. */
export function EnvFileField({ value, onChange, onFile }: { value: string; onChange: (content: string) => void; onFile?: (name: string) => void }) {
  const uid = useId();
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [asText, setAsText] = useState(false);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const toggle = (k: string) => setRevealed((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  const take = async (files: File[]) => {
    const f = files[0];
    if (!f) return;
    try { const text = await readEnvFile(f); setError(null); onChange(text); onFile?.(f.name); } catch (e) { setError((e as Error).message); }
  };
  const set = (key: string, v: string) => {
    try { onChange(setEnvEntry(value, key, v)); setError(null); } catch { setError("That value can't be set here. Use Edit as text."); }
  };
  const add = () => {
    const k = newKey.trim();
    if (!ENV_KEY.test(k)) return setError(BAD_KEY);
    set(k, newValue);
    setNewKey(""); setNewValue("");
  };
  // A drop here is the file's contents, not an attachment: the editor sheet's own drop doesn't see it.
  const onDrop = (e: DragEvent) => { e.preventDefault(); e.stopPropagation(); void take([...e.dataTransfer.files]); };
  const keys = envKeys(value);
  return (
    <div role="group" aria-labelledby={`${uid}-label`} className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        {/* Names the group (aria-labelledby); there's no single control for it to point at. */}
        <label id={`${uid}-label`} className="mr-auto text-[13px] font-medium text-text-primary">Contents</label>
        <Button type="button" variant="ghost" size="sm" aria-pressed={asText} onClick={() => setAsText((x) => !x)}>Edit as text</Button>
      </div>
      <div data-testid="env-drop" onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); e.dataTransfer.dropEffect = "copy"; }} onDrop={onDrop}
        className="flex flex-wrap items-center gap-2 rounded-[12px] border border-dashed border-border-default bg-app px-3 py-2.5">
        <Button type="button" variant="outline" size="sm" onClick={() => input.current?.click()}><FileUp className="size-3.5" />Choose file</Button>
        <span className="text-[12px] text-text-tertiary">or drop a .env file here.</span>
        <input ref={input} type="file" hidden aria-hidden="true" tabIndex={-1} data-testid="env-input"
          onChange={(e) => { const files = [...(e.target.files ?? [])]; e.target.value = ""; void take(files); }} />
      </div>
      {asText ? (
        <div className="relative">
          <Textarea aria-label="File contents" rows={10} value={value} spellCheck={false} autoComplete="off" placeholder="KEY=value" data-masked={!revealed.has("") || undefined}
            onChange={(e) => onChange(keepEol(value, e.target.value))}
            className={cn("pr-11 font-mono text-[13px]", !revealed.has("") && "[-webkit-text-security:disc]")} />
          <span className="absolute top-1 right-1">
            <Button type="button" variant="ghost" size="icon" aria-label={revealed.has("") ? "Hide file contents" : "Show file contents"} onClick={() => toggle("")}>
              {revealed.has("") ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </Button>
          </span>
        </div>
      ) : (
        <>
          {keys.length > 0 && (
            <ul aria-label="Entries" className="flex flex-col gap-1.5">
              {keys.map((k, i) => {
                const v = envValue(value, k) ?? "";
                // An input can't hold a line break: a multi-line value is changed in Edit as text.
                const multi = /[\r\n]/.test(v);
                const id = `${uid}-e${i}`;
                return (
                  <li key={k} className="grid grid-cols-[minmax(0,2fr)_minmax(0,3fr)] items-center gap-2">
                    <label htmlFor={id} className="font-mono text-[12.5px] break-all text-text-secondary">{k}</label>
                    <div className="relative">
                      <Input id={id} type={revealed.has(k) ? "text" : "password"} autoComplete="off" spellCheck={false} value={v} readOnly={multi}
                        title={multi ? "Several lines: change it in Edit as text" : undefined} onChange={(e) => set(k, e.target.value)} className="pr-11 font-mono text-[13px]" />
                      <span className="absolute inset-y-0 right-1 flex items-center">
                        <Button type="button" variant="ghost" size="icon" aria-label={revealed.has(k) ? `Hide ${k}` : `Show ${k}`} onClick={() => toggle(k)}>
                          {revealed.has(k) ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                        </Button>
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,3fr)_auto] items-center gap-2">
            <Input aria-label="New key" placeholder="KEY" value={newKey} spellCheck={false} autoComplete="off" className="font-mono text-[13px]" onChange={(e) => setNewKey(e.target.value)} />
            <Input aria-label="New value" type="password" placeholder="value" value={newValue} autoComplete="off" className="font-mono text-[13px]" onChange={(e) => setNewValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} />
            <Button type="button" variant="outline" size="sm" onClick={add}><Plus className="size-3.5" />Add entry</Button>
          </div>
        </>
      )}
      <InvalidLines content={value} />
      {error && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{error}</p>}
    </div>
  );
}
