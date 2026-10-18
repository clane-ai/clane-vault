export const REDACTED = "[clane:redacted]";

const uEsc = (upper: boolean) => (c: string) => { const h = c.charCodeAt(0).toString(16).padStart(4, "0"); return `\\u${upper ? h.toUpperCase() : h}`; };
const lowerPct = (s: string) => s.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());

/** v and its JSON string escapes: plain, non-ASCII and DEL as \uXXXX (Python ensure_ascii; lower and upper hex), Go's <>& escapes, each also with "\/" (PHP). */
function jsonForms(v: string): string[] {
  const j = JSON.stringify(v).slice(1, -1);
  const out = [v, j, j.replace(/[^\x00-\x7e]/g, uEsc(false)), j.replace(/[^\x00-\x7e]/g, uEsc(true)), j.replace(/[<>&]|\p{Zl}|\p{Zp}/gu, uEsc(false))];
  return [...out, ...out.map((x) => x.replaceAll("/", "\\/"))];
}

/**
 * Every form a secret is likely to be echoed in: raw, base64, base64url (unpadded), encodeURIComponent (upper and lower %xx),
 * hex lower/upper, the form-urlencoded form (what `searchParams.set` sends), base64(`user:secret`); each also in every
 * JSON string escape (jsonForms), since upstreams echo all of these inside JSON.
 */
export function variantsOf(secret: string, basicUser?: string): string[] {
  if (!secret) return [];
  const b = Buffer.from(secret, "utf8");
  const hex = b.toString("hex");
  const uri = encodeURIComponent(secret), form = new URLSearchParams({ s: secret }).toString().slice(2);
  const base = [secret, b.toString("base64"), b.toString("base64url"), uri, lowerPct(uri), hex, hex.toUpperCase(), form, lowerPct(form)];
  if (basicUser !== undefined) base.push(Buffer.from(`${basicUser}:${secret}`, "utf8").toString("base64"));
  return [...new Set(base.flatMap(jsonForms))];
}

const esc = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Replaces every variant in one pass of a single alternation, longest first so a shorter one never splits a longer match. */
export function scrub(text: string, variants: string[]): { text: string; hits: number } {
  const vs = [...new Set(variants.filter(Boolean))].sort((a, b) => b.length - a.length);
  if (!vs.length) return { text, hits: 0 };
  let hits = 0;
  text = text.replace(new RegExp(vs.map(esc).join("|"), "g"), () => (hits++, REDACTED));
  return { text, hits };
}
