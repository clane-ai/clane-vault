import { z } from "zod";

/** Longest organisation or person name shown to other people (and put into emails). */
export const NAME_MAX = 60;

// Links and addresses in a name turn invite emails and the app into a phishing channel ("Acme — reset at evil.example").
const LINKY = /(https?:|www\.|[^\s@]+@[^\s@]+|\b[a-z0-9-]+\.(?:com|net|org|io|co|ai|app|dev|xyz|info|biz|me|ly|link|click|top|site|online|ru|cn|uk|de|eu|us|tk|ml|ga|gq|cf)\b)/i;

/** Strips control/format characters and newlines, collapses whitespace, trims. */
export function cleanName(raw: string): string {
  return raw.normalize("NFKC").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").replace(/\s+/g, " ").trim();
}

/** Why a name is refused, or null. */
export function nameProblem(name: string): "empty" | "too_long" | "link" | null {
  if (!name) return "empty";
  if (name.length > NAME_MAX) return "too_long";
  if (LINKY.test(name)) return "link";
  return null;
}

/** A display name for orgs and people: cleaned, 1–60 characters, no links or email addresses (400 invalid_request otherwise). */
export const displayName = z.string().max(500).transform(cleanName).refine((s) => nameProblem(s) === null, { message: "invalid_name" });
