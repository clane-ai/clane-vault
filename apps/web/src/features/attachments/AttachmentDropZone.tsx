import { useCallback, useRef, useState, type DragEvent, type ReactNode } from "react";
import { Paperclip, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const hasFiles = (e: DragEvent) => [...(e.dataTransfer?.types ?? [])].includes("Files");

/**
 * Drag & drop of files onto a whole panel (the record panel or the editor): an overlay says what dropping does, or
 * that this person can't add files here. Returns the handlers to spread on the panel and the overlay to render in it.
 */
export function useFileDrop(o: { canDrop: boolean; title?: string; onFiles: (files: File[]) => void; disabled?: boolean }) {
  const [over, setOver] = useState(false);
  const depth = useRef(0);
  const reset = () => { depth.current = 0; setOver(false); };
  const handlers = o.disabled ? {} : {
    onDragEnter: (e: DragEvent) => { if (!hasFiles(e)) return; e.preventDefault(); depth.current++; setOver(true); },
    onDragOver: (e: DragEvent) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = o.canDrop ? "copy" : "none"; },
    onDragLeave: (e: DragEvent) => { if (!hasFiles(e)) return; depth.current = Math.max(0, depth.current - 1); if (depth.current === 0) setOver(false); },
    onDrop: (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      reset();
      if (o.canDrop) o.onFiles([...e.dataTransfer.files]);
    },
  };
  const overlay = over ? (
    <div data-testid="drop-overlay" aria-live="polite"
      className={cn("pointer-events-none absolute inset-2 z-20 grid place-items-center rounded-[14px] border-2 border-dashed backdrop-blur-[2px]",
        o.canDrop ? "border-blue-500/70 bg-blue-tint/80" : "border-border-strong bg-well/85")}>
      <p className="flex items-center gap-2 px-6 text-center text-[14px] font-medium text-text-primary">
        <Upload className="size-4 shrink-0" />{o.canDrop ? `Drop to attach to ${o.title ?? "this record"}` : "You can't add files here"}
      </p>
    </div>
  ) : null;
  return { handlers, overlay };
}

/** "Attach file": the native file picker (several files at once). */
export function AttachButton({ onFiles, disabled, children, size = "sm" }: { onFiles: (files: File[]) => void; disabled?: boolean; children?: ReactNode; size?: "sm" | "default" }) {
  const input = useRef<HTMLInputElement>(null);
  const pick = useCallback(() => input.current?.click(), []);
  return (
    <>
      <Button type="button" variant="outline" size={size} disabled={disabled} onClick={pick}><Paperclip className="size-3.5" />{children ?? "Attach file"}</Button>
      <input ref={input} type="file" multiple hidden aria-hidden="true" tabIndex={-1} data-testid="attach-input"
        onChange={(e) => { const files = [...(e.target.files ?? [])]; e.target.value = ""; if (files.length) onFiles(files); }} />
    </>
  );
}

/** The dashed drop target at the bottom of the editor (also a button that opens the picker). */
export function DropTarget({ onFiles, hint }: { onFiles: (files: File[]) => void; hint?: string }) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      {/* Named "Attach files" only: the hint stays out of the button's name, so "Save" or "Cancel" never match it. */}
      <button type="button" onClick={() => input.current?.click()} data-testid="drop-target" aria-label="Attach files"
        className="flex w-full flex-col items-center gap-1 rounded-[12px] border border-dashed border-border-default bg-app px-4 py-4 text-center transition-colors duration-150 hover:border-border-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40">
        <span className="flex items-center gap-2 text-[13.5px] font-medium text-text-primary"><Paperclip className="size-4" />Attach files</span>
        <span className="text-[12px] text-text-tertiary">{hint ?? "Drop files here or choose them. They're encrypted on this device first."}</span>
      </button>
      <input ref={input} type="file" multiple hidden aria-hidden="true" tabIndex={-1} data-testid="attach-input" onChange={(e) => { const files = [...(e.target.files ?? [])]; e.target.value = ""; if (files.length) onFiles(files); }} />
    </>
  );
}
