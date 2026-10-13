import { useEffect, useRef, useState } from "react";
import { getDocument, GlobalWorkerOptions, type PDFDocumentProxy } from "pdfjs-dist";
// The worker is a separate module served from this app's own origin ('self' under the CSP's worker-src).
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";

GlobalWorkerOptions.workerSrc = workerUrl;

/** Pages rendered at most (bigger documents: download to read the rest). */
export const PDF_MAX_PAGES = 30;

/**
 * A PDF rendered by pdf.js onto canvases (docs/attachments.md, spec §6.4): never the browser's own viewer, never a
 * frame or a navigation. Scripting, XFA forms and eval are off; pdf.js runs under the app's CSP (no eval, worker from
 * 'self'). Annotations and links are not rendered at all (only the page canvas).
 */
export default function PdfPreview({ data, name, onError }: { data: Uint8Array; name: string; onError: () => void }) {
  const host = useRef<HTMLDivElement>(null);
  const [pages, setPages] = useState<{ shown: number; total: number } | null>(null);
  useEffect(() => {
    const el = host.current;
    let doc: PDFDocumentProxy | null = null;
    let cancelled = false;
    // pdf.js takes ownership of the buffer it is given: hand it a copy.
    const task = getDocument({ data: data.slice(), isEvalSupported: false, enableXfa: false, disableFontFace: false, stopAtErrors: false,
      useSystemFonts: false, disableAutoFetch: true, disableStream: true } as Parameters<typeof getDocument>[0]);
    void (async () => {
      try {
        doc = await task.promise;
        const total = doc.numPages, shown = Math.min(total, PDF_MAX_PAGES);
        const width = Math.max(320, (el?.clientWidth ?? 800) - 2);
        for (let n = 1; n <= shown && !cancelled; n++) {
          const page = await doc.getPage(n);
          const base = page.getViewport({ scale: 1 });
          const scale = Math.min(2, width / base.width);
          const dpr = Math.min(2, window.devicePixelRatio || 1);
          const vp = page.getViewport({ scale: scale * dpr });
          const canvas = document.createElement("canvas");
          canvas.width = Math.floor(vp.width); canvas.height = Math.floor(vp.height);
          canvas.style.width = `${Math.floor(vp.width / dpr)}px`;
          canvas.className = "mx-auto block max-w-full rounded-[6px] border border-border-default bg-white shadow-[var(--shadow-card)]";
          canvas.setAttribute("aria-label", `${name}, page ${n} of ${total}`);
          canvas.setAttribute("role", "img");
          await page.render({ canvas, viewport: vp, annotationMode: 0 } as Parameters<typeof page.render>[0]).promise;
          if (cancelled) break;
          el?.appendChild(canvas);
          setPages({ shown: n, total });
        }
      } catch { if (!cancelled) onError(); }
    })();
    return () => { cancelled = true; void task.destroy(); el?.replaceChildren(); };
  }, [data, name, onError]);
  return (
    <div className="flex flex-col gap-3">
      <div ref={host} data-testid="pdf-pages" className="flex flex-col gap-3" />
      {!pages && <p role="status" className="py-8 text-center text-[13px] text-text-secondary">Rendering…</p>}
      {pages && pages.total > PDF_MAX_PAGES && pages.shown === PDF_MAX_PAGES && (
        <p className="text-center text-[12.5px] text-text-tertiary">Showing the first {PDF_MAX_PAGES} of {pages.total} pages. Download the file to read the rest.</p>
      )}
    </div>
  );
}
