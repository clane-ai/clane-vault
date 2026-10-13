import { createHash } from "node:crypto";

/**
 * Logo uploads (docs/branding.md): PNG, JPEG or WebP only, recognised by their magic bytes (the declared content type
 * is ignored), at most 256 KB and 1024×1024 pixels, read from the image header. SVG is never accepted: it can carry
 * script.
 */
export const LOGO_MAX_BYTES = 256 * 1024;
export const LOGO_MAX_PX = 1024;

export type LogoMime = "image/png" | "image/jpeg" | "image/webp";
export interface LogoImage { mime: LogoMime; width: number; height: number; sha256: string }
export type LogoProblem = "empty" | "too_large" | "unsupported_type" | "bad_image" | "too_many_pixels";

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const ascii = (b: Buffer, at: number, len: number) => (b.length >= at + len ? b.toString("latin1", at, at + len) : "");

function png(b: Buffer): { width: number; height: number } | null {
  // Signature, then the IHDR chunk first: length (13), "IHDR", width, height (big-endian).
  if (b.length < 24 || ascii(b, 12, 4) !== "IHDR") return null;
  return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
}

function jpeg(b: Buffer): { width: number; height: number } | null {
  let i = 2;
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) return null;
    const marker = b[i + 1]!;
    if (marker === 0xff) { i++; continue; } // fill byte
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; } // no length
    if (marker === 0xd9 || marker === 0xda) return null; // end of image or scan data before a frame header
    const len = b.readUInt16BE(i + 2);
    if (len < 2) return null;
    // Start of frame: SOF0–SOF15 except DHT (C4), JPG (C8) and DAC (CC).
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      if (i + 9 > b.length) return null;
      return { height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) };
    }
    i += 2 + len;
  }
  return null;
}

function webp(b: Buffer): { width: number; height: number } | null {
  const chunk = ascii(b, 12, 4);
  if (chunk === "VP8 " && b.length >= 30) {
    // Key frame start code 9d 01 2a, then 14-bit width and height (little-endian).
    if (b[23] !== 0x9d || b[24] !== 0x01 || b[25] !== 0x2a) return null;
    return { width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === "VP8L" && b.length >= 25) {
    if (b[20] !== 0x2f) return null;
    const b1 = b[21]!, b2 = b[22]!, b3 = b[23]!, b4 = b[24]!;
    return { width: 1 + (((b2 & 0x3f) << 8) | b1), height: 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6)) };
  }
  if (chunk === "VP8X" && b.length >= 30) return { width: 1 + b.readUIntLE(24, 3), height: 1 + b.readUIntLE(27, 3) };
  return null;
}

/** Recognises the image by its bytes and reads its size; a problem when it isn't an accepted logo. */
export function inspectLogo(b: Buffer): LogoImage | LogoProblem {
  if (!b.length) return "empty";
  if (b.length > LOGO_MAX_BYTES) return "too_large";
  let mime: LogoMime;
  let dim: { width: number; height: number } | null;
  if (PNG_SIG.every((x, i) => b[i] === x)) { mime = "image/png"; dim = png(b); }
  else if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) { mime = "image/jpeg"; dim = jpeg(b); }
  else if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WEBP") { mime = "image/webp"; dim = webp(b); }
  else return "unsupported_type";
  if (!dim || dim.width < 1 || dim.height < 1) return "bad_image";
  if (dim.width > LOGO_MAX_PX || dim.height > LOGO_MAX_PX) return "too_many_pixels";
  return { mime, ...dim, sha256: createHash("sha256").update(b).digest("hex") };
}

/** The short version clients put in the logo URL (?v=…): changes with the bytes. */
export const logoVersion = (sha256: string | null | undefined): string | null => (sha256 ? sha256.slice(0, 16) : null);

const EXT: Record<string, string> = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp" };

/**
 * Headers for serving a stored logo: its real type, never sniffed, shown inline, sandboxed (no script even if opened
 * directly), cached against its version.
 */
export function logoHeaders(mime: string, sha256: string, visibility: "public" | "private"): Record<string, string> {
  return {
    "content-type": mime,
    "x-content-type-options": "nosniff",
    "content-disposition": `inline; filename="logo.${EXT[mime] ?? "bin"}"`,
    "content-security-policy": "default-src 'none'; sandbox",
    "cross-origin-resource-policy": "same-origin",
    etag: `"${sha256}"`,
    // The URL carries the version, so a cached copy is never stale; private: only the member's browser keeps it.
    "cache-control": `${visibility}, max-age=86400`,
  };
}
