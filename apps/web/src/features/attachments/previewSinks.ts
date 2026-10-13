import { safeFilename } from "@clane-vault/crypto";
/**
 * Which files may be previewed, and how (docs/attachments.md, spec 2026-10-12-attachments.md §6.4, §7.5). Only an
 * allowlist, only after the decrypted bytes' magic numbers agree with the encrypted type, and only into safe sinks:
 * <img src=blob:> for raster images, pdf.js on a canvas for PDFs, textContent of a <pre> for plain text. Everything
 * else (HTML, SVG, XML, Office files, archives, executables…) is download-only. SVG is never an image here.
 */
export type PreviewKind = "image" | "pdf" | "text";

const IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
/** Text previews stop at 1 MiB (bigger files download). */
export const TEXT_PREVIEW_MAX = 1024 * 1024;
/** Anything bigger is download-only: a preview keeps the whole file in memory. */
export const PREVIEW_MAX = 50 * 1024 * 1024;

/** The sink a file's (encrypted, so untrusted) type would go to, or null: download only. */
export function previewKindOf(mime: string, size: number): PreviewKind | null {
  const m = mime.toLowerCase();
  if (size > PREVIEW_MAX) return null;
  if (IMAGE_TYPES.has(m)) return "image";
  if (m === "application/pdf") return "pdf";
  if (m === "text/plain" && size <= TEXT_PREVIEW_MAX) return "text";
  return null;
}

const startsWith = (b: Uint8Array, sig: number[], at = 0) => b.length >= at + sig.length && sig.every((x, i) => b[at + i] === x);
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));

/** The image type the bytes really are (by magic number), or null. */
export function sniffImage(b: Uint8Array): string | null {
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (startsWith(b, [0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith(b, ascii("GIF87a")) || startsWith(b, ascii("GIF89a"))) return "image/gif";
  if (startsWith(b, ascii("RIFF")) && startsWith(b, ascii("WEBP"), 8)) return "image/webp";
  return null;
}

/** Whether the decrypted bytes may go to the sink `kind` for a file whose metadata says `mime`. */
export function bytesMatch(kind: PreviewKind, mime: string, b: Uint8Array): boolean {
  if (kind === "image") return sniffImage(b) === mime.toLowerCase();
  if (kind === "pdf") return startsWith(b, ascii("%PDF-"));
  // Plain text: valid UTF-8 without NUL bytes (a binary file with a text type stays download-only).
  if (b.length > TEXT_PREVIEW_MAX || b.includes(0)) return false;
  try { new TextDecoder("utf-8", { fatal: true }).decode(b); return true; } catch { return false; }
}

const EXECUTABLE = /\.(exe|msi|bat|cmd|com|scr|ps1|vbs|js|jse|wsf|hta|jar|app|dmg|pkg|sh|apk|lnk|reg|dll|iso)$/i;
/** Files that run when opened: the download warns who added them. Judged on the name the file is saved under. */
export const isExecutable = (name: string, mime = "") => EXECUTABLE.test(safeFilename(name)) || /x-msdownload|x-msdos-program|x-executable|x-sh|java-archive|vnd\.microsoft\.portable-executable/.test(mime);
