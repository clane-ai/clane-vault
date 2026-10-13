import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { Download, FileWarning, ZoomIn, ZoomOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { formatBytes } from "./format";
import { bytesMatch, previewKindOf, type PreviewKind } from "./previewSinks";
import { DamagedFileError } from "./downloader";
import type { FileRow } from "./useAttachments";

const PdfPreview = lazy(() => import("./PdfPreview"));

type View = { kind: "loading"; done: number } | { kind: "image"; url: string } | { kind: "text"; text: string } | { kind: "pdf"; data: Uint8Array } | { kind: "refused"; why: string };

const join = (parts: Uint8Array[]) => { const n = parts.reduce((s, p) => s + p.length, 0); const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

/**
 * A preview of one file (docs/attachments.md): the bytes are fetched and checked like a download, then shown only if
 * they really are what the allowlist accepts. Images go to <img src=blob:> (the object URL revoked once it loaded or
 * the sheet closed), text to a <pre>'s text, PDFs to pdf.js on canvases. Never a frame, a new window or innerHTML.
 */
export function PreviewSheet({ row, read, onDownload, onClose }: {
  row: FileRow | null; read: (row: FileRow, signal: AbortSignal, onProgress: (done: number) => void) => Promise<Uint8Array[]>;
  onDownload: (row: FileRow) => void; onClose: () => void;
}) {
  const [view, setView] = useState<View>({ kind: "loading", done: 0 });
  const [zoom, setZoom] = useState(1);
  useEffect(() => {
    if (!row?.meta) return;
    const meta = row.meta;
    const kind = previewKindOf(meta.mime, meta.size) as PreviewKind | null;
    const ctl = new AbortController();
    let url: string | null = null;
    setView({ kind: "loading", done: 0 }); setZoom(1);
    if (!kind) { setView({ kind: "refused", why: "This type of file can't be previewed. Download it instead." }); return; }
    void read(row, ctl.signal, (done) => setView((v) => (v.kind === "loading" ? { kind: "loading", done } : v))).then((parts) => {
      if (ctl.signal.aborted) return;
      const bytes = join(parts);
      parts.length = 0;
      // The encrypted type is only a claim: the bytes must agree before anything is shown.
      if (!bytesMatch(kind, meta.mime, bytes)) { bytes.fill(0); setView({ kind: "refused", why: "This file isn't what its type says, so it isn't previewed. Download it if you trust it." }); return; }
      if (kind === "image") { url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" })); setView({ kind: "image", url }); }
      else if (kind === "text") setView({ kind: "text", text: new TextDecoder().decode(bytes) });
      else setView({ kind: "pdf", data: bytes });
    }).catch((e: unknown) => {
      if (ctl.signal.aborted) return;
      setView({ kind: "refused", why: e instanceof DamagedFileError ? e.message : "Couldn't load the file. Check your connection and try again." });
    });
    return () => { ctl.abort(); if (url) URL.revokeObjectURL(url); };
  }, [row, read]);
  const revoke = useCallback(() => { if (view.kind === "image") URL.revokeObjectURL(view.url); }, [view]);
  const pdfFailed = useCallback(() => setView({ kind: "refused", why: "This PDF can't be shown here. Download it instead." }), []);
  const meta = row?.meta;
  return (
    <Sheet open={!!row} onOpenChange={(o) => { if (!o) onClose(); }}>
      {/* Escape closes the preview only, not the record panel behind it (the vault closes a record on Escape). */}
      <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} onEscapeKeyDown={(e) => e.stopPropagation()}
        className="data-[side=right]:w-full data-[side=right]:sm:max-w-[min(920px,92vw)]">
        <SheetHeader>
          <SheetTitle className="min-w-0 truncate text-[16px]">{meta?.name ?? "File"}</SheetTitle>
          <span className="flex shrink-0 items-center gap-1">
            {view.kind === "image" && <>
              <Button type="button" variant="ghost" size="icon" aria-label="Zoom out" disabled={zoom <= 0.5} onClick={() => setZoom((z) => Math.max(0.5, z / 1.5))}><ZoomOut className="size-4" /></Button>
              <Button type="button" variant="ghost" size="icon" aria-label="Zoom in" disabled={zoom >= 4} onClick={() => setZoom((z) => Math.min(4, z * 1.5))}><ZoomIn className="size-4" /></Button>
            </>}
            {row && <Button type="button" variant="outline" size="sm" onClick={() => onDownload(row)}><Download className="size-3.5" />Download</Button>}
            <SheetCloseButton />
          </span>
        </SheetHeader>
        <SheetBody className="bg-app">
          {view.kind === "loading" && <p role="status" className="py-16 text-center text-[13.5px] text-text-secondary">Decrypting… {meta ? `${formatBytes(view.done)} of ${formatBytes(meta.size)}` : ""}</p>}
          {view.kind === "refused" && (
            <div role="alert" className="flex flex-col items-center gap-3 py-12 text-center">
              <FileWarning className="size-8 text-text-tertiary" />
              <p className="max-w-[360px] text-[14px] text-text-secondary">{view.why}</p>
            </div>
          )}
          {view.kind === "image" && (
            <div className="overflow-auto touch-pan-x touch-pan-y">
              <img src={view.url} alt={meta?.name ?? ""} onLoad={revoke} data-testid="image-preview"
                className={cn("mx-auto block h-auto max-w-none rounded-[6px]", zoom === 1 && "max-w-full")} style={zoom === 1 ? undefined : { width: `${zoom * 100}%` }} />
            </div>
          )}
          {view.kind === "text" && <pre data-testid="text-preview" className="overflow-auto rounded-[10px] border border-border-default bg-card p-4 font-mono text-[12.5px] leading-relaxed whitespace-pre-wrap break-words text-text-primary">{view.text}</pre>}
          {view.kind === "pdf" && meta && <Suspense fallback={<p role="status" className="py-16 text-center text-[13.5px] text-text-secondary">Loading the PDF viewer…</p>}><PdfPreview data={view.data} name={meta.name} onError={pdfFailed} /></Suspense>}
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}
