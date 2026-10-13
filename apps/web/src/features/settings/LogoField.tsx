import { useRef, useState, type ReactNode } from "react";
import { ImageUp, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";

/** What the server accepts (docs/branding.md); it checks again from the bytes. Never SVG. */
export const LOGO_TYPES = ["image/png", "image/jpeg", "image/webp"];
export const LOGO_MAX_BYTES = 256 * 1024;
export const LOGO_HINT = "PNG, JPEG or WebP, up to 256 KB and 1024 × 1024 pixels.";

export function logoErrorText(code: string): string {
  return code === "unsupported_type" ? "Use a PNG, JPEG or WebP image (SVG isn't accepted)."
    : code === "too_large" ? "That file is over 256 KB. Use a smaller image."
    : code === "too_many_pixels" ? "That image is larger than 1024 × 1024 pixels. Use a smaller one."
    : code === "bad_image" || code === "empty" ? "That file isn't a readable image."
    : code === "forbidden" ? "Only owners and admins can change the logo."
    : "Couldn't upload the logo. Try again.";
}

/** A logo picker: preview (or `fallback`), upload or replace, remove. Checks type and size before uploading. */
export function LogoField({ id, label, url, fallback, onUpload, onRemove }: {
  id: string; label: string; url: string | null; fallback: ReactNode;
  onUpload: (file: File) => Promise<void>; onRemove: () => Promise<void>;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function pick(file: File | undefined) {
    if (input.current) input.current.value = "";
    if (!file) return;
    setError(null);
    if (!LOGO_TYPES.includes(file.type)) return setError(logoErrorText("unsupported_type"));
    if (file.size > LOGO_MAX_BYTES) return setError(logoErrorText("too_large"));
    setBusy(true);
    try { await onUpload(file); toast.success("Logo updated"); }
    catch (e) { setError(logoErrorText(e instanceof ApiError ? e.code : "")); }
    finally { setBusy(false); }
  }
  async function remove() {
    setBusy(true); setError(null);
    try { await onRemove(); toast.success("Logo removed"); }
    catch { setError("Couldn't remove the logo. Try again."); }
    finally { setBusy(false); }
  }

  return (
    <div className="flex flex-col gap-2" role="group" aria-labelledby={`${id}-label`}>
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid size-14 shrink-0 place-items-center overflow-hidden rounded-[12px] border border-border-default bg-well">
          {url ? <img src={url} alt={`Current ${label.toLowerCase()}`} className="size-full object-contain" /> : fallback}
        </span>
        <div className="min-w-0 flex-1">
          <p id={`${id}-label`} className="text-[14px] font-medium text-text-primary">{label}</p>
          <p className="text-[12.5px] text-text-secondary">{LOGO_HINT}</p>
        </div>
        <div className="flex gap-2">
          <input ref={input} id={id} type="file" accept={LOGO_TYPES.join(",")} className="sr-only" aria-label={`Upload ${label.toLowerCase()}`} tabIndex={-1}
            onChange={(e) => void pick(e.target.files?.[0])} />
          <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => input.current?.click()}><ImageUp className="size-3.5" />{url ? "Replace" : "Upload"}</Button>
          {url && <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => void remove()} className="text-red-500 hover:bg-red-tint hover:text-red-500"><Trash2 className="size-3.5" />Remove</Button>}
        </div>
      </div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </div>
  );
}
