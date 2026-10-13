import {
  Contact, CreditCard, Database, FileBadge, IdCard, KeyRound, KeySquare, Landmark, MapPin, Server, SquareTerminal, StickyNote, Ticket, Wifi, type LucideIcon,
} from "lucide-react";
import {
  CORE_KEYS, IDENTITY_DOCS, RECORD_TYPE_DEFS, isSecretKind, optionLabel, templateOf, typeLabel,
  type CustomField, type FieldKind, type LinkBody, type RecordBody, type RecordType, type TemplateField,
} from "@clane-vault/crypto";

/** A record type's icon (lucide), used in the picker, the list, the panel and the type filter. */
export const TYPE_ICON: Record<RecordType, LucideIcon> = {
  login: KeyRound, note: StickyNote, card: CreditCard, bankAccount: Landmark, server: Server, database: Database, sshKey: SquareTerminal,
  apiKey: KeySquare, wifi: Wifi, softwareLicence: FileBadge, identity: IdCard, address: MapPin, contact: Contact, membership: Ticket,
};

/** "Payment card" → "payment card" (for "New payment card"); names like "SSH key" or "Wi-Fi" keep their case. */
export const lowerFirst = (s: string) => (/^[A-Z][a-z]+(\s|$)/.test(s) ? s[0]!.toLowerCase() + s.slice(1) : s);

/** One field as the panel and the link page show it: a template field with a value, or a custom field. */
export interface ShownField {
  id: string; label: string; kind: FieldKind; value: string;
  /** Template key (core or data); absent for custom fields. */ key?: string; core?: boolean;
  format?: TemplateField["format"]; options?: TemplateField["options"]; mono?: boolean; custom?: boolean;
}

const CORE_LABEL: Record<string, string> = { username: "Username", password: "Password", url: "Website", totpSecret: "2FA secret" };
const CORE_KIND: Record<string, FieldKind> = { username: "text", password: "secret", url: "url", totpSecret: "totp" };

type BodyLike = Pick<RecordBody, "username" | "password" | "url" | "totpSecret" | "data" | "fields"> & { type?: RecordType };
const coreValue = (b: BodyLike, k: string) => (b as Record<string, unknown>)[k] as string | undefined;

/**
 * The fields a record shows, in template order, then core fields its template doesn't have (v1 bodies), then custom
 * fields. Blank values are left out.
 */
export function shownFields(b: BodyLike): ShownField[] {
  const type = b.type ?? "login";
  const out: ShownField[] = [];
  const tpl = templateOf(type);
  for (const f of tpl) {
    const v = f.core ? coreValue(b, f.key) : b.data?.[f.key];
    if (v) out.push({ id: `t:${f.key}`, key: f.key, core: f.core, label: f.label, kind: f.kind, value: v, format: f.format, options: f.options, mono: f.mono });
  }
  for (const k of CORE_KEYS) {
    const v = coreValue(b, k);
    if (v && !tpl.some((f) => f.core && f.key === k)) out.push({ id: `t:${k}`, key: k, core: true, label: CORE_LABEL[k]!, kind: CORE_KIND[k]!, value: v, mono: k !== "url" });
  }
  for (const f of b.fields ?? []) out.push({ id: `c:${f.id}`, label: f.label, kind: f.kind, value: f.value, custom: true, mono: f.kind === "secret" || f.kind === "hiddenMultiline" || f.kind === "totp" });
  return out;
}

/** Any field a "Use only" holder must never see (they may still copy, as with a password). */
export const isSecretField = (f: Pick<ShownField, "kind">) => isSecretKind(f.kind);

const digits = (s: string) => s.replace(/\D/g, "");
export const last4 = (s: string) => digits(s).slice(-4);
/** "4242424242424242" → "4242 4242 4242 4242" (Amex: 4-6-5). */
export function groupCardNumber(s: string): string {
  const d = digits(s).slice(0, 19);
  if (/^3[47]/.test(d)) return [d.slice(0, 4), d.slice(4, 10), d.slice(10, 15)].filter(Boolean).join(" ");
  return d.replace(/(.{4})/g, "$1 ").trim();
}
export const maskedCard = (s: string) => `•••• ${last4(s)}`;

/** A field value as text for display (option labels, dates); secrets are the caller's to mask. */
export function displayValue(f: Pick<ShownField, "kind" | "value" | "options" | "format">): string {
  if (f.options) return optionLabel({ options: f.options } as TemplateField, f.value);
  if (f.format === "cardNumber") return groupCardNumber(f.value);
  if (f.kind === "date" && /^\d{4}-\d{2}-\d{2}$/.test(f.value)) {
    const d = new Date(`${f.value}T00:00:00`);
    if (!Number.isNaN(d.getTime())) return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  return f.value;
}

const stripUrl = (u: string) => u.replace(/^https?:\/\//i, "").replace(/^www\./i, "");
const join = (...xs: (string | undefined | false)[]) => xs.filter((x): x is string => !!x && !!x.trim()).join(" · ");

/** The list's second line: never a secret (a card shows only its last four digits). */
export function recordSubtitle(b: RecordBody | null | undefined): string {
  if (!b) return "";
  const d = b.data ?? {};
  const host = (h?: string, p?: string) => (h ? (p ? `${h}:${p}` : h) : "");
  switch (b.type) {
    case "login": return b.username || (b.url ? stripUrl(b.url) : "");
    case "note": return "Secure note";
    case "card": return join(d.number ? maskedCard(d.number) : "", d.cardholder) || typeLabel("card");
    case "bankAccount": return join(d.bank, d.accountNumber ? `•••• ${d.accountNumber.replace(/\s/g, "").slice(-4)}` : "") || typeLabel("bankAccount");
    case "server": return join(b.username && d.hostname ? `${b.username}@${host(d.hostname, d.port)}` : host(d.hostname, d.port) || b.username) || typeLabel("server");
    case "database": return join(d.dbType ? optionLabel(RECORD_TYPE_DEFS.database.fields[0]!, d.dbType) : "", host(d.host, d.port) + (d.database ? `/${d.database}` : "")) || typeLabel("database");
    case "sshKey": return (b.username && d.host ? `${b.username}@${d.host}` : d.host || b.username) || typeLabel("sshKey");
    case "apiKey": return d.service || (d.endpoint ? stripUrl(d.endpoint) : "") || typeLabel("apiKey");
    case "wifi": return d.ssid || typeLabel("wifi");
    case "softwareLicence": return join(d.product, d.version) || typeLabel("softwareLicence");
    case "identity": return join(d.docType ? IDENTITY_DOCS.find((o) => o.value === d.docType)?.label ?? d.docType : "", d.fullName) || typeLabel("identity");
    case "address": return join(d.street1, d.city, d.country) || typeLabel("address");
    case "contact": return join(d.name, d.company) || d.email || typeLabel("contact");
    case "membership": return join(d.organisation, d.memberId) || typeLabel("membership");
    default: return "";
  }
}

/** What search looks in: the title and every non-secret field (labels of options too); never a secret, never notes. */
export function searchableText(b: RecordBody | null | undefined): string[] {
  if (!b) return [];
  const out = [b.title];
  for (const f of shownFields(b)) {
    if (isSecretField(f)) continue;
    out.push(f.value);
    if (f.options) out.push(displayValue(f));
  }
  return out;
}

/** A link snapshot shown like a record (links made before record types are logins). */
export const linkFields = (b: LinkBody) => shownFields({ ...b, type: b.type ?? "login" });

/** A new custom field id (stable across edits). */
export const newFieldId = () => `f${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
export const emptyField = (): CustomField => ({ id: newFieldId(), label: "", kind: "text", value: "" });

export const KIND_LABEL: Record<FieldKind, string> = {
  text: "Text", secret: "Secret (hidden)", multiline: "Multi-line text", url: "Website / URL", email: "Email", phone: "Phone", date: "Date", totp: "2FA code (TOTP)",
  hiddenMultiline: "Hidden multi-line (keys, certificates)",
};

/** Title placeholders per type. */
export const PLACEHOLDER: Record<RecordType, string> = {
  login: "AWS root account", note: "VPN runbook", card: "Company Visa", bankAccount: "Operating account", server: "Build server", database: "Production Postgres",
  sshKey: "Deploy key", apiKey: "Stripe live key", wifi: "Office Wi-Fi", softwareLicence: "Adobe Acrobat", identity: "Passport", address: "Head office",
  contact: "IT support desk", membership: "Gym membership",
};
