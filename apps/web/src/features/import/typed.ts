import {
  base32Decode, coreKeysOf, dataKeysOf, MAX_CUSTOM_FIELDS, MAX_FIELD_LABEL, templateOf, typeLabel,
  type CustomField, type FieldKind, type RecordBody, type RecordType,
} from "@clane-vault/crypto";

/**
 * Turning an exporter's loosely-typed item into a record of one of our types (docs/record-types.md). Importers fill a
 * Draft; buildBody puts each value where the type's template wants it, and anything the template has no place for
 * becomes a custom field (never a "Label: value" line in the notes).
 */
export interface DraftField { label: string; value: string; kind?: FieldKind }
export interface Draft {
  type: RecordType; title: string;
  username?: string; password?: string; url?: string;
  /** A TOTP secret or otpauth:// URI: the login's 2FA secret, a TOTP custom field elsewhere. */ totp?: string;
  notes?: string; data?: Record<string, string | undefined>; custom?: DraftField[];
}

/** Pulls a base32 TOTP secret out of an otpauth:// URI or a bare secret. Returns null when it is not usable. */
export function totpSecretFrom(v: string | undefined | null): string | null {
  if (!v) return null;
  let secret = v.trim();
  if (/^otpauth:\/\//i.test(secret)) {
    try { secret = new URL(secret).searchParams.get("secret") ?? ""; } catch { return null; }
  }
  secret = secret.replace(/[\s-]/g, "").toUpperCase();
  try { return base32Decode(secret).length >= 10 ? secret : null; } catch { return null; }
}

const noteJoin = (...parts: (string | undefined)[]) => parts.filter((p) => p && p.trim()).join("\n\n");
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SECRET_LABEL = /\b(pass(word|phrase|code)?|pwd|secret|pin|token|cvv|cvc|security code|answer|private key|api key|licen[cs]e key|recovery codes?)\b/i;

/** A custom field kind from its label and value, when the exporter doesn't say. */
export function guessKind(label: string, value: string): FieldKind {
  const v = value.trim();
  if (/^otpauth:\/\//i.test(v) && totpSecretFrom(v)) return "totp";
  if (/-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----/.test(v)) return "hiddenMultiline";
  if (SECRET_LABEL.test(label)) return value.includes("\n") ? "hiddenMultiline" : "secret";
  if (value.includes("\n")) return "multiline";
  if (/^https?:\/\/\S+$/i.test(v)) return "url";
  if (EMAIL.test(v)) return "email";
  if (/\b(phone|mobile|tel|fax)\b/i.test(label) && /^[+\d][\d\s().-]{4,}$/.test(v)) return "phone";
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return "date";
  return "text";
}

/** Epoch milliseconds (or seconds), "YYYY-MM-DD…" → "YYYY-MM-DD"; null when it isn't a date we can read. */
export function isoDate(v: unknown): string | null {
  if (typeof v === "number" || (typeof v === "string" && /^\d{9,14}$/.test(v.trim()))) {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) return null;
    const d = new Date(n < 1e11 ? n * 1000 : n);
    return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  const us = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(s);
  if (us) return `${us[3]}-${us[1]!.padStart(2, "0")}-${us[2]!.padStart(2, "0")}`;
  const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
  // LastPass: "June,15,2030" or "June,2030".
  const lp = /^([A-Za-z]+),\s*(?:(\d{1,2}),\s*)?(\d{4})$/.exec(s);
  if (lp) {
    const mi = MONTHS.indexOf(lp[1]!.toLowerCase());
    if (mi >= 0) return `${lp[3]}-${String(mi + 1).padStart(2, "0")}-${(lp[2] ?? "1").padStart(2, "0")}`;
  }
  return null;
}

/** A card expiry as "MM/YY": "12/2030", "12/30", "2030-12", "203012" (1Password), "June,2030" (LastPass), month + year parts. */
export function expiryMMYY(v: unknown, year?: unknown): string | null {
  const two = (m: string | number) => String(m).padStart(2, "0");
  const ok = (m: number, y: number) => (m >= 1 && m <= 12 && y >= 0 ? `${two(m)}/${two(y % 100)}` : null);
  if (year !== undefined) {
    const m = Number(String(v ?? "").trim()), y = Number(String(year ?? "").trim());
    return String(v ?? "").trim() && String(year ?? "").trim() && Number.isInteger(m) && Number.isInteger(y) ? ok(m, y) : null;
  }
  const s = typeof v === "number" ? String(v) : typeof v === "string" ? v.trim() : "";
  if (!s) return null;
  let m: RegExpExecArray | null;
  if ((m = /^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/.exec(s))) return ok(Number(m[1]), Number(m[2]));
  if ((m = /^(\d{4})-(\d{1,2})(-\d{1,2})?$/.exec(s))) return ok(Number(m[2]), Number(m[1]));
  if ((m = /^(\d{4})(\d{2})$/.exec(s))) return ok(Number(m[2]), Number(m[1]));
  const iso = isoDate(s);
  return iso ? ok(Number(iso.slice(5, 7)), Number(iso.slice(0, 4))) : null;
}

/** Normalises a database type to the template's options where it is one of them; anything else is kept as written. */
export function dbTypeOf(v: string): string {
  const s = v.trim().toLowerCase();
  if (/postgres/.test(s)) return "postgresql";
  if (/mysql|maria/.test(s)) return "mysql";
  if (/sql ?server|mssql|microsoft/.test(s)) return "sqlserver";
  if (/oracle/.test(s)) return "oracle";
  if (/mongo/.test(s)) return "mongodb";
  if (/redis/.test(s)) return "redis";
  return v.trim();
}
/** Normalises a Wi-Fi security name to the template's options where it is one of them. */
export function wifiSecurityOf(v: string): string {
  const s = v.trim().toLowerCase().replace(/[\s_-]+/g, "");
  if (/enterprise|802\.1x|eap/.test(s)) return "wpa2-enterprise";
  if (s.includes("wpa3")) return "wpa3";
  if (s.includes("wpa2")) return "wpa2";
  if (s.includes("wpa")) return "wpa";
  if (s.includes("wep")) return "wep";
  if (s === "none" || s === "open") return "open";
  return v.trim();
}

/** "Label" from an exporter's field name; never empty, at most 100 characters. */
const fieldLabel = (l: string) => (l.trim() || "Field").slice(0, MAX_FIELD_LABEL);

/**
 * Builds a record body from a draft, or returns why it can't be imported. Values the type has no template slot for
 * become custom fields; past 64 custom fields, the rest go into the notes.
 */
export function buildBody(d: Draft): RecordBody | string {
  const title = d.title.trim();
  if (!title) return "No title";
  const core = new Set<string>(coreKeysOf(d.type));
  const dataKeys = new Set(dataKeysOf(d.type));
  const label = (k: string) => templateOf(d.type).find((f) => f.key === k)?.label;
  const custom: DraftField[] = [];
  const body: RecordBody = { type: d.type, title };
  let notes = d.notes ?? "";

  const put = (k: "username" | "password" | "url", v: string | undefined, fallback: DraftField) => {
    const val = k === "password" ? v ?? "" : (v ?? "").trim();
    if (!val.trim()) return;
    if (core.has(k)) body[k] = val; else custom.push({ ...fallback, value: val });
  };
  put("username", d.username, { label: "Username", kind: "text", value: "" });
  put("password", d.password, { label: "Password", kind: "secret", value: "" });
  put("url", d.url, { label: "Website", kind: "url", value: "" });
  if (d.totp?.trim()) {
    const s = totpSecretFrom(d.totp);
    if (s && core.has("totpSecret")) body.totpSecret = s;
    else if (s) custom.push({ label: "One-time code", kind: "totp", value: s });
    else notes = noteJoin(notes, `2FA (not recognised): ${d.totp.trim()}`);
  }
  const data: Record<string, string> = {};
  for (const [k, v] of Object.entries(d.data ?? {})) {
    if (v === undefined || !v.trim()) continue;
    if (dataKeys.has(k)) data[k] = v; else custom.push({ label: label(k) ?? k, value: v });
  }
  if (Object.keys(data).length) body.data = data;
  custom.push(...(d.custom ?? []));

  const fields: CustomField[] = [];
  const overflow: string[] = [];
  for (const f of custom) {
    if (!f.value.trim()) continue;
    const l = fieldLabel(f.label);
    let kind = f.kind ?? guessKind(l, f.value);
    let value = f.value;
    if (kind === "totp") { const s = totpSecretFrom(value); if (s) value = s; else kind = "text"; }
    if (fields.length >= MAX_CUSTOM_FIELDS) { overflow.push(`${l}: ${value}`); continue; }
    fields.push({ id: `f${fields.length + 1}`, label: l, kind, value });
  }
  if (fields.length) body.fields = fields;
  if (overflow.length) notes = noteJoin(notes, overflow.join("\n"));
  if (notes.trim()) body.notes = notes;

  const hasContent = body.username || body.password || body.url || body.totpSecret || body.data || body.fields || body.notes;
  if (!hasContent) return "Nothing to import";
  // Records are limited to 64 KB of ciphertext on the server.
  if (JSON.stringify(body).length > 40_000) return "Too large to import";
  return body;
}

/** Records per type ("Login" → 12, …), for previews and reports. Never looks at values. */
export function typeCounts(bodies: { type: RecordType }[]): { type: RecordType; label: string; count: number }[] {
  const m = new Map<RecordType, number>();
  for (const b of bodies) m.set(b.type, (m.get(b.type) ?? 0) + 1);
  return [...m.entries()].map(([type, count]) => ({ type, label: typeLabel(type), count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** A name object ({ first, middle, last }) or text as one line. */
export function nameLine(v: unknown): string {
  if (typeof v === "string") return v.trim();
  if (!v || typeof v !== "object") return "";
  const o = v as Record<string, unknown>;
  return ["first", "middle", "last"].map((k) => (typeof o[k] === "string" ? (o[k] as string).trim() : "")).filter(Boolean).join(" ");
}
