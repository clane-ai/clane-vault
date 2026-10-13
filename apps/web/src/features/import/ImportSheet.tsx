import { useRef, useState } from "react";
import { CheckCircle2, FileUp, Folder, FolderSync, Inbox } from "lucide-react";
import { typeLabel } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import type { VaultFolder } from "@/features/vault/types";
import { folderCounts, FORMAT_LABEL, guessMapping, ImportFormatError, MAPPED_FIELDS, parseImportFile, parseMappedCsv, SOURCES_HINT, UnrecognisedCsvError, type ColumnMapping, type ParseResult } from "./parsers";
import { typeCounts } from "./typed";
import { useImport, type ImportSummary } from "./useImport";

const NO_FOLDER = "__none__";
type Step = { kind: "choose" } | { kind: "map"; rows: string[][]; mapping: ColumnMapping } | { kind: "preview"; file: string; result: ParseResult } | { kind: "importing"; done: number; total: number } | { kind: "done"; summary: ImportSummary };

export function ImportPreview({ result }: { result: ParseResult }) {
  const counts = folderCounts(result.items);
  const types = typeCounts(result.items.map((it) => it.body));
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.1em] text-text-tertiary uppercase";
  const td = "max-w-0 truncate px-3 py-2 text-[13px] text-text-primary";
  return (
    <div className="flex flex-col gap-4">
      <p className="text-[14px] text-text-primary"><strong>{result.items.length}</strong> {result.items.length === 1 ? "record" : "records"} from {FORMAT_LABEL[result.format]}{result.skipped.length > 0 && <>, <strong>{result.skipped.length}</strong> skipped</>}.</p>
      {types.length > 1 && (
        <p className="-mt-2 text-[13px] text-text-secondary" aria-label="Record types">
          {types.map((t, i) => <span key={t.type}>{i > 0 && " · "}{t.label} <span className="font-mono text-text-primary tabular-nums">{t.count}</span></span>)}
        </p>
      )}
      <section aria-label="Folders" className="overflow-hidden rounded-[12px] border border-border-default">
        {counts.map((c) => (
          <div key={c.folder ?? "none"} className="flex items-center gap-2.5 border-b border-border-default px-3 py-2 last:border-b-0">
            {c.folder ? <Folder className="size-4 text-blue-500" /> : <Inbox className="size-4 text-text-tertiary" />}
            <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{c.folder ?? "No folder"}</span>
            <span className="rounded-[6px] border border-border-default bg-app px-1.5 py-px font-mono text-[11px] text-text-secondary tabular-nums">{c.count}</span>
          </div>
        ))}
      </section>
      {result.items.length > 0 && (
        <table className="w-full table-fixed overflow-hidden rounded-[12px] border border-border-default" aria-label="First records">
          <thead className="bg-app"><tr><th className={th}>Title</th><th className={th}>Type</th><th className={th}>Folder</th></tr></thead>
          <tbody>
            {result.items.slice(0, 5).map((it, i) => (
              <tr key={i} className="border-t border-border-default">
                <td className={td}>{it.body.title}</td><td className={cn(td, "text-text-secondary")}>{it.body.username ? <><span className="font-mono text-[12.5px] text-text-primary">{it.body.username}</span> · {typeLabel(it.body.type)}</> : typeLabel(it.body.type)}</td><td className={cn(td, "text-text-secondary")}>{it.folder ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {result.skipped.length > 0 && (
        <section aria-label="Skipped rows" className="flex flex-col gap-1.5">
          <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Skipped</h3>
          <ul className="flex flex-col gap-1 text-[13px] text-text-secondary">
            {result.skipped.slice(0, 20).map((s, i) => <li key={i}>Row {s.row}{s.title ? ` (${s.title})` : ""}: {s.reason}</li>)}
            {result.skipped.length > 20 && <li>…and {result.skipped.length - 20} more</li>}
          </ul>
        </section>
      )}
    </div>
  );
}

/** Generic CSV: one select per field (title, username...) naming the column it comes from, plus the first rows as mapped. */
export function ColumnMapper({ rows, mapping, onChange }: { rows: string[][]; mapping: ColumnMapping; onChange: (m: ColumnMapping) => void }) {
  const header = rows[0]!;
  const sample = rows.slice(1, 4);
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.1em] text-text-tertiary uppercase";
  const td = "max-w-0 truncate px-3 py-2 text-[13px] text-text-primary";
  const shown = MAPPED_FIELDS.filter(({ field }) => mapping[field] !== undefined && field !== "password" && field !== "totp");
  return (
    <section aria-label="Match columns" className="flex flex-col gap-4">
      <p className="text-[14px] text-text-secondary">We don't know this CSV layout. Tell us which column holds what; columns you leave out aren't imported.</p>
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
        {MAPPED_FIELDS.map(({ field, label }) => (
          <label key={field} className="flex flex-col gap-1 text-[12.5px] text-text-secondary">
            <span>{label}</span>
            <select aria-label={label} value={mapping[field] ?? ""} className="h-10 rounded-[9px] border border-border-default bg-card px-2.5 text-[13.5px] text-text-primary"
              onChange={(e) => { const m = { ...mapping }; if (e.target.value === "") delete m[field]; else m[field] = Number(e.target.value); onChange(m); }}>
              <option value="">Not imported</option>
              {header.map((h, i) => <option key={i} value={String(i)}>{h.trim() || `Column ${i + 1}`}</option>)}
            </select>
          </label>
        ))}
      </div>
      {shown.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full table-fixed overflow-hidden rounded-[12px] border border-border-default" aria-label="Mapped rows">
            <thead className="bg-app"><tr>{shown.map(({ field, label }) => <th key={field} className={th}>{label}</th>)}</tr></thead>
            <tbody>
              {sample.map((r, i) => (
                <tr key={i} className="border-t border-border-default">{shown.map(({ field }) => <td key={field} className={td}>{r[mapping[field]!] ?? ""}</td>)}</tr>
              ))}
            </tbody>
          </table>
          <p className="mt-1.5 text-[12px] text-text-tertiary">Passwords and 2FA secrets aren't shown in this preview.</p>
        </div>
      )}
    </section>
  );
}

/** + New → Import: choose a file, preview, choose folders, encrypt and upload. */
export function ImportSheet({ open, onOpenChange, folders, onBulkMigration }: { open: boolean; onOpenChange: (o: boolean) => void; folders: VaultFolder[];
  /** Admins: opens Migrate from Keeper (whole vault with shared folders and people). */ onBulkMigration?: () => void }) {
  const { run } = useImport();
  const [step, setStep] = useState<Step>({ kind: "choose" });
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"source" | "single">("source");
  const [single, setSingle] = useState<string>(NO_FOLDER);
  const input = useRef<HTMLInputElement>(null);
  const live = folders.filter((f) => !f.deleted && f.kind === "private");
  const busy = step.kind === "importing";

  const reset = () => { setStep({ kind: "choose" }); setError(null); setMode("source"); setSingle(NO_FOLDER); if (input.current) input.current.value = ""; };

  async function onFile(f: File | undefined) {
    if (!f) return;
    setError(null);
    if (f.size > 20 * 1024 * 1024) return setError("That file is too big to import (over 20 MB).");
    try {
      const result = parseImportFile(new Uint8Array(await f.arrayBuffer()));
      if (result.items.length === 0 && result.skipped.length === 0) return setError("There's nothing to import in that file.");
      setStep({ kind: "preview", file: f.name, result });
    } catch (e) {
      // A CSV we don't know: let the user say which column is which.
      if (e instanceof UnrecognisedCsvError) return setStep({ kind: "map", rows: e.rows, mapping: guessMapping(e.rows[0]!) });
      setError(e instanceof ImportFormatError ? e.message : "We couldn't read that file.");
    }
  }

  function applyMapping(rows: string[][], mapping: ColumnMapping) {
    setError(null);
    try {
      const result = parseMappedCsv(rows, mapping);
      if (result.items.length === 0 && result.skipped.length === 0) return setError("There's nothing to import in that file.");
      setStep({ kind: "preview", file: "", result });
    } catch (e) { setError(e instanceof ImportFormatError ? e.message : "We couldn't read that file."); }
  }

  async function start(result: ParseResult) {
    setStep({ kind: "importing", done: 0, total: result.items.length });
    try {
      const summary = await run(result.items, mode === "source" ? { kind: "source" } : { kind: "single", folderId: single === NO_FOLDER ? null : single }, folders,
        (done, total) => setStep({ kind: "importing", done, total }));
      setStep({ kind: "done", summary: { ...summary } });
    } catch (e) {
      setError((e as Error).message === "Vault locked" ? "The vault locked during the import. Unlock and import the rest again." : "The import stopped. Check your connection and try again.");
      setStep({ kind: "preview", file: "", result });
    }
  }

  return (
    <Sheet open={open} onOpenChange={(o) => { if (busy) return; onOpenChange(o); if (!o) reset(); }}>
      <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="w-full sm:max-w-[520px]">
        <SheetHeader><SheetTitle className="font-display text-[18px] font-semibold tracking-[-0.02em]">Import</SheetTitle>{!busy && <SheetCloseButton />}</SheetHeader>
        <SheetBody>
          {step.kind === "choose" && (
            <>
              <p className="text-[14px] text-text-secondary">Bring your passwords from Keeper, Bitwarden, 1Password, LastPass, Dashlane, Zoho Vault, Chrome, Edge or any CSV file. The file is read and encrypted on this device; it's never uploaded as is.</p>
              <label htmlFor="imp-file" className="flex cursor-pointer flex-col items-center gap-2 rounded-[12px] border border-dashed border-border-strong bg-app px-6 py-10 text-center transition-colors duration-150 hover:bg-well">
                <FileUp className="size-6 text-blue-500" />
                <span className="text-[14px] font-medium text-text-primary">Choose an export file</span>
                <span className="text-[12.5px] text-text-tertiary">{SOURCES_HINT}</span>
              </label>
              <input ref={input} id="imp-file" aria-label="Export file" type="file" accept=".json,.csv,.1pux,.data,application/json,text/csv,application/zip" className="sr-only" onChange={(e) => void onFile(e.target.files?.[0])} />
              <p className="text-[12.5px] text-text-tertiary">In your old app, look for Export (CSV, JSON or 1PUX). Delete the export file when you're done: it holds every password in plain text.</p>
              {onBulkMigration && (
                <button type="button" onClick={() => { reset(); onBulkMigration(); }} className="flex items-start gap-3 rounded-[12px] border border-border-default bg-card px-4 py-3 text-left transition-colors duration-150 hover:bg-well">
                  <FolderSync className="mt-0.5 size-5 shrink-0 text-blue-500" />
                  <span><span className="block text-[14px] font-medium text-text-primary">Bulk migration (admins)</span>
                    <span className="block text-[12.5px] text-text-secondary">Move a whole Keeper vault: shared folders become team folders with their people.</span></span>
                </button>
              )}
            </>
          )}
          {step.kind === "map" && <ColumnMapper rows={step.rows} mapping={step.mapping} onChange={(mapping) => setStep({ ...step, mapping })} />}
          {step.kind === "preview" && (
            <>
              <ImportPreview result={step.result} />
              {step.result.items.length > 0 && (
                <fieldset className="flex flex-col gap-2">
                  <legend className="mb-1 text-[13px] text-text-primary">Where should they go?</legend>
                  <label className="flex items-start gap-2.5 text-[13.5px] text-text-primary">
                    <input type="radio" name="imp-mode" className="mt-1 accent-blue-500" checked={mode === "source"} onChange={() => setMode("source")} />
                    <span>Keep their folders <span className="block text-[12.5px] text-text-tertiary">Creates private folders with the same names; reuses ones you already have.</span></span>
                  </label>
                  <label className="flex items-start gap-2.5 text-[13.5px] text-text-primary">
                    <input type="radio" name="imp-mode" className="mt-1 accent-blue-500" checked={mode === "single"} onChange={() => setMode("single")} />
                    <span>Put them all in one folder</span>
                  </label>
                  {mode === "single" && (
                    <div className="flex flex-col gap-1.5 pl-6">
                      <Label htmlFor="imp-folder" className="sr-only">Folder</Label>
                      <Select value={single} onValueChange={setSingle}>
                        <SelectTrigger id="imp-folder" aria-label="Folder" className="w-full"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NO_FOLDER}>No folder</SelectItem>
                          {live.length > 0 && <SelectSeparator />}
                          {live.map((f) => <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </fieldset>
              )}
            </>
          )}
          {step.kind === "importing" && (
            <div className="flex flex-col gap-3 py-6" role="status">
              <p className="text-[14px] text-text-primary">Encrypting and uploading… {step.done} of {step.total}</p>
              <div className="h-2 overflow-hidden rounded-full bg-well"><div className="h-full rounded-full bg-blue-500 transition-[width] duration-200" style={{ width: `${step.total ? (step.done / step.total) * 100 : 0}%` }} /></div>
              <p className="text-[12.5px] text-text-tertiary">Keep this page open until it finishes.</p>
            </div>
          )}
          {step.kind === "done" && (
            <div className="flex flex-col items-center gap-2 py-8 text-center" role="status">
              <CheckCircle2 className="size-10 text-green-600" />
              <p className="font-display text-[17px] font-semibold text-text-primary">Imported {step.summary.imported} {step.summary.imported === 1 ? "record" : "records"}</p>
              <p className="text-[13.5px] text-text-secondary">
                {step.summary.foldersCreated > 0 ? `${step.summary.foldersCreated} new ${step.summary.foldersCreated === 1 ? "folder" : "folders"}. ` : ""}
                {step.summary.failed > 0 ? `${step.summary.failed} couldn't be uploaded (too large or a connection problem).` : "Delete the export file from your computer now."}
              </p>
            </div>
          )}
          {error && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{error}</p>}
        </SheetBody>
        <SheetFooter>
          {step.kind === "map" && <>
            <Button type="button" variant="ghost" onClick={reset}>Choose another file</Button>
            <Button type="button" onClick={() => applyMapping(step.rows, step.mapping)}>Continue</Button>
          </>}
          {step.kind === "preview" && <>
            <Button type="button" variant="ghost" onClick={reset}>Choose another file</Button>
            <Button type="button" disabled={step.result.items.length === 0} onClick={() => void start(step.result)}>Import {step.result.items.length}</Button>
          </>}
          {step.kind === "done" && <Button type="button" onClick={() => { onOpenChange(false); reset(); }}>Done</Button>}
          {step.kind === "choose" && <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
