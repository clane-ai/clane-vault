import { File, FileArchive, FileCode, FileImage, FileSpreadsheet, FileText, FileVideo, FileAudio, type LucideIcon } from "lucide-react";

const UNITS = ["B", "KB", "MB", "GB"] as const;
/** 1536 → "1.5 KB"; binary multiples, one decimal under 10. */
export function formatBytes(n: number): string {
  let v = n, u = 0;
  while (v >= 1024 && u < UNITS.length - 1) { v /= 1024; u++; }
  return `${u === 0 ? v : v < 10 ? v.toFixed(1) : Math.round(v)} ${UNITS[u]}`;
}

/** An icon by the (decrypted) type: only ever a picture, never a decision about what is safe. */
export function fileIcon(mime: string, name = ""): LucideIcon {
  const m = mime.toLowerCase();
  if (m.startsWith("image/")) return FileImage;
  if (m.startsWith("video/")) return FileVideo;
  if (m.startsWith("audio/")) return FileAudio;
  if (m === "application/pdf" || m.startsWith("text/") || /word|opendocument\.text|rtf/.test(m)) return FileText;
  if (/sheet|excel|csv/.test(m) || /\.(xlsx?|csv|ods)$/i.test(name)) return FileSpreadsheet;
  if (/zip|tar|gzip|7z|rar|compressed/.test(m)) return FileArchive;
  if (/json|xml|javascript|x-sh|x-python/.test(m)) return FileCode;
  return File;
}

/** Plaintext size from the ciphertext size the server lists (16 bytes of tag per chunk). */
export const plainSize = (a: { size: number; chunkCount: number }) => Math.max(0, a.size - 16 * a.chunkCount);
