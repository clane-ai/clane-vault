import { strFromU8, unzipSync } from "fflate";
import { IDENTITY_DOCS, type RecordBody, type RecordType } from "@clane-vault/crypto";
import { keeperDraft } from "./keeperRecord";
import { buildBody, dbTypeOf, expiryMMYY, isoDate, totpSecretFrom, wifiSecurityOf, type Draft, type DraftField } from "./typed";

export { totpSecretFrom } from "./typed";

export type ImportFormat = "keeper-json" | "keeper-csv" | "bitwarden-json" | "bitwarden-csv" | "chrome-csv" | "lastpass-csv" | "zoho-csv"
  | "1password-1pux" | "1password-csv" | "dashlane-csv" | "generic-csv";
export const FORMAT_LABEL: Record<ImportFormat, string> = {
  "keeper-json": "Keeper (JSON)", "keeper-csv": "Keeper (CSV)", "bitwarden-json": "Bitwarden (JSON)", "bitwarden-csv": "Bitwarden (CSV)", "chrome-csv": "Chrome / Edge (CSV)",
  "lastpass-csv": "LastPass (CSV)", "zoho-csv": "Zoho Vault (CSV)", "1password-1pux": "1Password (1PUX)", "1password-csv": "1Password (CSV)", "dashlane-csv": "Dashlane (CSV)",
  "generic-csv": "CSV (mapped columns)",
};
/** Every source, for the file picker hint. */
export const SOURCES_HINT = "Keeper · Bitwarden · 1Password (1PUX or CSV) · LastPass · Dashlane · Zoho Vault · Chrome / Edge · any CSV";

export interface ImportItem { folder: string | null; body: RecordBody }
export interface SkippedRow { row: number; title?: string; reason: string }
export interface ParseResult { format: ImportFormat; items: ImportItem[]; skipped: SkippedRow[] }

export class ImportFormatError extends Error {}
const UNRECOGNISED = "Unrecognised format. Use an export from Keeper, Bitwarden, 1Password, LastPass, Dashlane, Zoho Vault, Chrome or Edge, or a CSV file with a header row.";
/** A CSV file with a header row we don't know: the import sheet lets the user map its columns (parseMappedCsv). */
export class UnrecognisedCsvError extends ImportFormatError {
  constructor(public rows: string[][]) { super(UNRECOGNISED); }
}

/** RFC 4180 CSV: quoted fields, doubled quotes, CRLF/LF, newlines inside quotes. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], field = "", q = false;
  const s = text.replace(/^﻿/, "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"' && field === "") q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
    } else field += c;
  }
  if (q) throw new ImportFormatError("The CSV file has an unclosed quote.");
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim() !== ""));
}

/** Any JSON value as text: strings as is, numbers and booleans converted, objects and arrays ignored. */
const text = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "");
const str = (v: unknown) => text(v).trim();
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const noteJoin = (...parts: (string | undefined)[]) => parts.filter((p) => p && p.trim()).join("\n\n");

interface Raw {
  title: string; username?: string; password?: string; url?: string; totp?: string; notes?: string;
  /** "Label: value" pairs the source has no column for: custom fields (kind guessed). */ extra?: [string, string][];
  folder?: string; forceNote?: boolean; skip?: string;
  /** A typed item: its type, template data and custom fields (else a login, or a note when nothing signs in). */
  type?: RecordType; data?: Record<string, string | undefined>; custom?: DraftField[];
}

/** Turns loosely-typed source fields into a valid record body, or a reason to skip. */
function toItem(r: Raw): ImportItem | string {
  if (r.skip) return r.skip;
  const title = str(r.title) || str(r.url).replace(/^https?:\/\//, "").split("/")[0] || "";
  if (!title) return "No title";
  const username = str(r.username), password = text(r.password), url = str(r.url);
  const custom: DraftField[] = [...(r.custom ?? []), ...(r.extra ?? []).filter(([k, v]) => k.trim() || v.trim()).map(([k, v]) => ({ label: k.trim() || "Field", value: v }))];
  const type = r.type ?? (r.forceNote || (!username && !password && !url && !totpSecretFrom(r.totp)) ? "note" : "login");
  const body = buildBody({ type, title, username, password, url, totp: str(r.totp) || undefined, notes: text(r.notes), data: r.data, custom });
  return typeof body === "string" ? body : { folder: str(r.folder) || null, body };
}

/** Puts a source value where a type's template wants it ("username", "password", "url", "data.key"), converting dates, expiries and menus. */
/** A draft being filled field by field. */
type Fill = Partial<Draft> & { data: Record<string, string>; custom: DraftField[] };
function assign(d: Fill, target: string, value: string, label: string) {
  const v = value;
  if (!v.trim()) return;
  if (target === "username" || target === "password" || target === "url") {
    if (d[target]) d.custom.push({ label, value: v }); else d[target] = target === "password" ? v : v.trim();
    return;
  }
  const key = target.slice(5);
  let out: string | null = v.trim();
  if (key === "expiry") out = expiryMMYY(v);
  else if (/Date$/.test(key)) out = isoDate(v);
  else if (key === "dbType") out = dbTypeOf(v);
  else if (key === "security") out = wifiSecurityOf(v);
  else if (key === "number" && d.type === "card") out = v.replace(/[\s-]/g, "");
  else if (key === "privateKey" || key === "publicKey" || key === "billingAddress") out = v;
  if (out === null || d.data[key]) d.custom.push({ label, value: v });
  else d.data[key] = out;
}

function collect(format: ImportFormat, raws: { raw: Raw | string; row: number }[]): ParseResult {
  const items: ImportItem[] = [], skipped: SkippedRow[] = [];
  for (const { raw, row } of raws) {
    if (typeof raw === "string") { skipped.push({ row, reason: raw }); continue; }
    let it: ImportItem | string;
    try { it = toItem(raw); } catch { it = "Couldn't read this row"; }
    if (typeof it === "string") skipped.push({ row, ...(raw.title ? { title: raw.title } : {}), reason: it });
    else items.push(it);
  }
  return { format, items, skipped };
}

// ---------- Keeper JSON ----------
interface KeeperFolder { folder?: string; shared_folder?: string }

function keeperFolderName(f: unknown): string | undefined {
  const o = obj(f);
  if (!o) return typeof f === "string" ? str(f) || undefined : undefined;
  return [str(o.shared_folder), str(o.folder)].filter(Boolean).join(" / ") || undefined;
}

/** A Keeper record (typed: card, server, SSH key… see keeperRecord) as a Raw. */
function keeperRaw(keeperType: string, title: string, login: string, password: string, url: string, notes: string, custom: [string, unknown][], folder?: string): Raw {
  const { draft } = keeperDraft({ keeperType, title, login, password, url, notes, custom });
  return { ...draft, title: draft.title, folder, type: draft.type, forceNote: draft.type === "note" };
}

function parseKeeperJson(data: { records: unknown[] }): ParseResult {
  return collect("keeper-json", data.records.map((x, i) => {
    const r = obj(x);
    if (!r) return { raw: "Not a record", row: i + 1 };
    return { raw: keeperRaw(str(r.$type) || str(r.type), str(r.title), str(r.login), text(r.password), str(r.login_url), text(r.notes),
      Object.entries(obj(r.custom_fields) ?? {}), keeperFolderName(arr(r.folders as KeeperFolder[] | undefined)[0])), row: i + 1 };
  }));
}

// ---------- Bitwarden JSON ----------
interface BwItem {
  type?: number; name?: string; notes?: string | null; folderId?: string | null;
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: { uri?: string | null }[] | null };
  fields?: { name?: string | null; value?: string | null; type?: number }[] | null;
  card?: Record<string, unknown> | null; identity?: Record<string, unknown> | null; sshKey?: Record<string, unknown> | null;
}

/** Bitwarden custom fields: 0 text, 1 hidden (secret), 2 boolean (text), 3 linked (nothing to carry over). */
function bwFields(fields: unknown): DraftField[] {
  return arr(fields).map(obj).filter((f): f is Record<string, unknown> => !!f && f.type !== 3)
    .map((f) => ({ label: str(f.name) || "Field", value: text(f.value), ...(f.type === 1 ? { kind: "secret" as const } : {}) }));
}

/** A Bitwarden identity: an identity document when it has a passport, licence or SSN number; else a contact; else an address. */
function bwIdentity(id: Record<string, unknown>): Pick<Raw, "type" | "data" | "custom"> {
  const g = (k: string) => str(id[k]);
  const fullName = [g("firstName"), g("middleName"), g("lastName")].filter(Boolean).join(" ");
  const address = { street1: g("address1"), street2: [g("address2"), g("address3")].filter(Boolean).join(", "), city: g("city"), region: g("state"), postcode: g("postalCode"), country: g("country") };
  const addressText = [address.street1, address.street2, [address.city, address.region, address.postcode].filter(Boolean).join(" "), address.country].filter(Boolean).join("\n");
  const custom: DraftField[] = [];
  const add = (label: string, value: string, kind?: DraftField["kind"]) => { if (value) custom.push({ label, value, ...(kind ? { kind } : {}) }); };
  const doc = g("passportNumber") ? "passport" : g("licenseNumber") ? "drivingLicence" : g("ssn") ? "other" : null;
  if (doc) {
    const number = g("passportNumber") || g("licenseNumber") || g("ssn");
    if (g("passportNumber") && g("licenseNumber")) add("Licence number", g("licenseNumber"), "secret");
    if (g("ssn") && number !== g("ssn")) add("Social security number", g("ssn"), "secret");
    add("Email", g("email"), "email"); add("Phone", g("phone"), "phone"); add("Company", g("company")); add("Username", g("username")); add("Address", addressText, "multiline");
    return { type: "identity", data: { docType: doc, fullName, number }, custom };
  }
  if (fullName || g("company") || g("email") || g("phone")) {
    add("Username", g("username")); add("Address", addressText, "multiline");
    return { type: "contact", data: { name: fullName, company: g("company"), email: g("email"), phone: g("phone") }, custom };
  }
  add("Username", g("username"));
  return { type: "address", data: address, custom };
}

function parseBitwardenJson(data: { encrypted?: boolean; folders?: unknown; items: unknown[] }): ParseResult {
  if (data.encrypted) throw new ImportFormatError("This Bitwarden export is encrypted. Export again as unencrypted JSON or CSV.");
  const folders = new Map(arr(data.folders).map(obj).filter((f): f is Record<string, unknown> => !!f && typeof f.id === "string").map((f) => [f.id as string, str(f.name)]));
  return collect("bitwarden-json", data.items.map((x, i) => {
    const it = obj(x) as BwItem | null;
    if (!it) return { raw: "Not an item", row: i + 1 };
    const base = { title: str(it.name), notes: text(it.notes), folder: typeof it.folderId === "string" ? folders.get(it.folderId) : undefined, custom: bwFields(it.fields) };
    if (it.type === 3) {
      const c = obj(it.card) ?? {};
      return { raw: { ...base, type: "card" as const, data: { cardholder: str(c.cardholderName), number: str(c.number).replace(/[\s-]/g, ""), expiry: expiryMMYY(c.expMonth, c.expYear) ?? undefined, cvv: str(c.code) } }, row: i + 1 };
    }
    if (it.type === 4) {
      const t = bwIdentity(obj(it.identity) ?? {});
      return { raw: { ...base, ...t, custom: [...(t.custom ?? []), ...base.custom] }, row: i + 1 };
    }
    if (it.type === 5) {
      const k = obj(it.sshKey) ?? {};
      const fp = str(k.keyFingerprint);
      return { raw: { ...base, type: "sshKey" as const, data: { privateKey: text(k.privateKey), publicKey: text(k.publicKey) }, custom: [...(fp ? [{ label: "Fingerprint", value: fp, kind: "text" as const }] : []), ...base.custom] }, row: i + 1 };
    }
    if (it.type !== 1 && it.type !== 2) return { raw: "Unsupported item type", row: i + 1 };
    const login = obj(it.login) as BwItem["login"] | null;
    const uris = arr(login?.uris).map((u) => str(obj(u)?.uri)).filter(Boolean);
    return { raw: {
      ...base, username: str(login?.username), password: text(login?.password), url: uris[0], totp: str(login?.totp) || undefined,
      custom: [...uris.slice(1).map((u) => ({ label: "Website", value: u, kind: "url" as const })), ...base.custom], forceNote: it.type === 2,
    }, row: i + 1 };
  }));
}

// ---------- CSV formats ----------
const norm = (h: string) => h.trim().toLowerCase().replace(/\s+/g, "_");
const has = (header: string[], cols: string[]) => cols.every((c) => header.includes(c));

function byHeader(rows: string[][]) {
  const header = rows[0]!.map(norm);
  return rows.slice(1).map((r, i) => ({ get: (k: string) => { const j = header.indexOf(k); return j >= 0 ? (r[j] ?? "") : ""; }, row: i + 2 }));
}

function parseBitwardenCsv(rows: string[][]): ParseResult {
  return collect("bitwarden-csv", byHeader(rows).map(({ get, row }) => {
    const type = get("type").toLowerCase();
    // Bitwarden's CSV export has no columns for cards, identities or SSH keys; its JSON export does.
    if (type && type !== "login" && type !== "note") return { raw: `${type[0]!.toUpperCase()}${type.slice(1)} items aren't in Bitwarden's CSV export: export as JSON to import them`, row };
    // Bitwarden CSV custom fields: one "name: value" per line.
    const extra = get("fields").split(/\r?\n/).filter((l) => l.trim()).map((l) => { const j = l.indexOf(": "); return (j >= 0 ? [l.slice(0, j), l.slice(j + 2)] : ["", l]) as [string, string]; });
    return { raw: { title: get("name"), username: get("login_username"), password: get("login_password"), url: get("login_uri"), totp: get("login_totp"), notes: get("notes"), extra, folder: get("folder"), forceNote: type === "note" }, row };
  }));
}

function parseChromeCsv(rows: string[][]): ParseResult {
  return collect("chrome-csv", byHeader(rows).map(({ get, row }) => ({ raw: { title: get("name"), username: get("username"), password: get("password"), url: get("url"), notes: get("note") || get("notes") }, row })));
}

const KEEPER_HEADER = ["folder", "title", "login", "password"];
/**
 * Keeper CSV: folder, title, login, password, website, notes, [shared folder], then custom field name/value pairs.
 * Keeper writes no header row; a header row matching those names is accepted and skipped.
 */
function parseKeeperCsv(rows: string[][]): ParseResult {
  const first = rows[0]!.map(norm);
  const start = has(first, KEEPER_HEADER) ? 1 : 0;
  return collect("keeper-csv", rows.slice(start).map((r, i) => {
    const row = i + 1 + start;
    const rest = r.slice(6);
    let sharedFolder = "";
    if (rest.length % 2 === 1) sharedFolder = rest.shift() ?? "";
    // Custom field pairs; a "$type" pair (Keeper v3 records) says the record type.
    let keeperType = "";
    const custom: [string, unknown][] = [];
    for (let j = 0; j + 1 < rest.length; j += 2) {
      if (rest[j]!.trim() === "$type") keeperType = rest[j + 1]!.trim(); else custom.push([rest[j]!, rest[j + 1]!]);
    }
    const folder = [sharedFolder.trim(), (r[0] ?? "").trim()].filter(Boolean).join(" / ");
    return { raw: keeperRaw(keeperType, r[1] ?? "", r[2] ?? "", r[3] ?? "", r[4] ?? "", r[5] ?? "", custom, folder), row };
  }));
}

// ---------- LastPass CSV ----------
/** LastPass secure note types we map ("NoteType:Credit Card" …): source key (lower case) → where it goes. */
const LP_TYPES: Record<string, { type: RecordType; doc?: string; map: Record<string, string> }> = {
  "credit card": { type: "card", map: { "name on card": "data.cardholder", number: "data.number", "security code": "data.cvv", "expiration date": "data.expiry", pin: "data.pin" } },
  "bank account": { type: "bankAccount", map: { "bank name": "data.bank", "account number": "data.accountNumber", "iban number": "data.accountNumber", "routing number": "data.routing", "swift code": "data.routing" } },
  server: { type: "server", map: { hostname: "data.hostname", username: "username", password: "password" } },
  database: { type: "database", map: { type: "data.dbType", hostname: "data.host", port: "data.port", database: "data.database", username: "username", password: "password" } },
  "wi-fi password": { type: "wifi", map: { ssid: "data.ssid", password: "password", authentication: "data.security" } },
  "software license": { type: "softwareLicence", map: { "license key": "data.licenceKey", licensee: "data.licensedTo", version: "data.version", "purchase date": "data.purchaseDate", "expiration date": "data.expiryDate" } },
  passport: { type: "identity", doc: "passport", map: { name: "data.fullName", number: "data.number", nationality: "data.nationality", "issuing authority": "data.authority", "issued date": "data.issueDate", "expiration date": "data.expiryDate" } },
  "driver's license": { type: "identity", doc: "drivingLicence", map: { name: "data.fullName", number: "data.number", "expiration date": "data.expiryDate" } },
  "ssh key": { type: "sshKey", map: { passphrase: "data.passphrase", "private key": "data.privateKey", "public key": "data.publicKey", hostname: "data.host" } },
  membership: { type: "membership", map: { organization: "data.organisation", "membership number": "data.memberId", password: "password", "expiration date": "data.expiryDate" } },
  address: { type: "address", map: { "address 1": "data.street1", "address 2": "data.street2", "city / town": "data.city", state: "data.region", "zip / postal code": "data.postcode", country: "data.country" } },
};

/** A LastPass secure note's "Key:Value" lines as a typed item; null for note types we don't map (kept as a plain note). */
function lastPassTyped(extra: string): Pick<Raw, "type" | "data" | "custom" | "notes" | "username" | "password"> | null {
  const lines = extra.split(/\r?\n/);
  const m = /^NoteType:(.+)$/.exec(lines[0] ?? "");
  const def = m ? LP_TYPES[m[1]!.trim().toLowerCase()] : undefined;
  if (!def) return null;
  const pairs: [string, string][] = [];
  let notes = "";
  for (let i = 1; i < lines.length; i++) {
    const kv = /^([^:]{1,60}):(.*)$/.exec(lines[i]!);
    if (kv && kv[1]!.trim() === "Notes") { notes = [kv[2]!, ...lines.slice(i + 1)].join("\n"); break; }
    if (kv) pairs.push([kv[1]!.trim(), kv[2]!]);
    else if (pairs.length) pairs[pairs.length - 1]![1] += `\n${lines[i]}`;
  }
  const d: Fill = { type: def.type, data: {}, custom: [] };
  if (def.doc) d.data.docType = def.doc;
  for (const [k, v] of pairs) {
    // LastPass writes an empty month/year date as ",".
    if (k === "Language" || !v.trim() || /^[\s,]+$/.test(v)) continue;
    const target = Object.hasOwn(def.map, k.toLowerCase()) ? def.map[k.toLowerCase()] : undefined;
    if (target) assign(d, target, v, k); else d.custom.push({ label: k, value: v });
  }
  return { type: def.type, data: d.data, custom: d.custom, notes, username: d.username, password: d.password };
}

/** url,username,password,totp,extra,name,grouping,fav. Secure notes have the url "http://sn"; groups nest with "\". */
function parseLastPassCsv(rows: string[][]): ParseResult {
  return collect("lastpass-csv", byHeader(rows).map(({ get, row }) => {
    const note = get("url").trim() === "http://sn";
    const g = get("grouping").trim();
    const folder = g === "(none)" ? "" : g.split("\\").map((x) => x.trim()).filter(Boolean).join(" / ");
    const typed = note ? lastPassTyped(get("extra")) : null;
    if (typed) return { raw: { title: get("name"), folder, ...typed }, row };
    return { raw: { title: get("name"), username: get("username"), password: get("password"), url: note ? "" : get("url"), totp: get("totp"), notes: get("extra"), folder, forceNote: note }, row };
  }));
}

// ---------- Zoho Vault CSV ----------
const USER_KEYS = new Set(["username", "user name", "user", "login", "login name", "email", "email address", "user id", "userid"]);
const PASS_KEYS = new Set(["password", "pass", "passwd"]);
/** Zoho Vault: "Password Name", "Password URL", "Folder Name", TOTP, and SecretData / CustomData as "Field:value" lines. */
function parseZohoCsv(rows: string[][]): ParseResult {
  return collect("zoho-csv", byHeader(rows).map(({ get, row }) => {
    let username = "", password = "";
    const extra: [string, string][] = [];
    for (const line of [...get("secretdata").split(/\r?\n/), ...get("customdata").split(/\r?\n/)]) {
      const j = line.indexOf(":");
      if (j < 0) continue;
      const k = line.slice(0, j).trim(), v = line.slice(j + 1);
      if (!k || !v.trim() || k === "SecretType") continue;
      if (!username && USER_KEYS.has(k.toLowerCase())) username = v.trim();
      else if (!password && PASS_KEYS.has(k.toLowerCase())) password = v;
      else extra.push([k, v.trim()]);
    }
    return { raw: { title: get("password_name") || get("secret_name"), username, password, url: get("password_url") || get("secret_url"), totp: get("totp") || get("login_totp"),
      notes: noteJoin(get("description"), get("notes")), extra, folder: get("folder_name") || get("chambername") }, row };
  }));
}

// ---------- Dashlane CSV ----------
/** Credentials: username,username2,username3,title,password,note,url,category,otpSecret|otpUrl. Secure notes: title,note. */
function parseDashlaneCsv(rows: string[][]): ParseResult {
  return collect("dashlane-csv", byHeader(rows).map(({ get, row }) => {
    const extra = ([["Other username", get("username2")], ["Other username", get("username3")]] as [string, string][]).filter(([, v]) => v.trim());
    return { raw: { title: get("title"), username: get("username"), password: get("password"), url: get("url"), totp: get("otpurl") || get("otpsecret"), notes: get("note"), extra, folder: get("category") }, row };
  }));
}

/** Dashlane payments.csv: payment cards and bank accounts. */
function parseDashlanePayments(rows: string[][]): ParseResult {
  return collect("dashlane-csv", byHeader(rows).map(({ get, row }) => {
    const card = get("cc_number").trim() !== "" || /card/i.test(get("type"));
    const base = { notes: get("note"), extra: (get("country") ? [["Country", get("country")]] : []) as [string, string][] };
    if (card) return { raw: { ...base, type: "card" as const, title: get("account_name") || get("name") || "Payment card",
      data: { cardholder: get("account_holder"), number: get("cc_number").replace(/[\s-]/g, ""), cvv: get("code"), expiry: expiryMMYY(get("expiration_month"), get("expiration_year")) ?? undefined } }, row };
    return { raw: { ...base, type: "bankAccount" as const, title: get("account_name") || get("issuing_bank") || "Bank account",
      data: { accountName: get("account_holder"), bank: get("issuing_bank"), accountNumber: get("account_number"), routing: get("routing_number") } }, row };
  }));
}

const DASHLANE_DOC: Record<string, string> = { passport: "passport", driver_license: "drivingLicence", driving_licence: "drivingLicence", id_card: "idCard", identity_card: "idCard" };
/** Dashlane ids.csv: passports, driving licences, ID cards, social security numbers. */
function parseDashlaneIds(rows: string[][]): ParseResult {
  return collect("dashlane-csv", byHeader(rows).map(({ get, row }) => {
    const kind = get("type").trim().toLowerCase();
    const docType = Object.hasOwn(DASHLANE_DOC, kind) ? DASHLANE_DOC[kind]! : "other";
    const docLabel = IDENTITY_DOCS.find((d) => d.value === docType)!.label;
    const d: Fill = { type: "identity", data: { docType, fullName: get("name"), number: get("number"), authority: get("place_of_issue") }, custom: [] };
    assign(d, "data.issueDate", get("issue_date"), "Issue date");
    assign(d, "data.expiryDate", get("expiration_date"), "Expiry date");
    if (get("state")) d.custom.push({ label: "State", value: get("state") });
    if (docType === "other" && kind) d.custom.push({ label: "Document", value: get("type") });
    return { raw: { title: get("name") ? `${docLabel} · ${get("name")}` : docLabel, type: "identity" as const, data: d.data, custom: d.custom }, row };
  }));
}

// ---------- 1Password ----------
/** 1Password 8 CSV: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes (older versions: website, one-time password). */
function parseOnePasswordCsv(rows: string[][]): ParseResult {
  return collect("1password-csv", byHeader(rows).map(({ get, row }) => ({ raw: {
    title: get("title"), username: get("username"), password: get("password"), url: get("url") || get("website"), totp: get("otpauth") || get("one-time_password"), notes: get("notes"),
  }, row })));
}

const OP_CATEGORY: Record<string, string> = {
  "002": "Credit cards", "004": "Identities", "006": "Documents", "100": "Software licences", "101": "Bank accounts", "102": "Databases", "103": "Driver licences",
  "104": "Outdoor licences", "105": "Memberships", "106": "Passports", "107": "Reward programmes", "108": "Social security numbers", "109": "Wireless routers",
  "110": "Servers", "111": "Email accounts", "112": "API credentials", "113": "Medical records", "114": "SSH keys", "115": "Crypto wallets",
};
/**
 * 1Password categories we map to a record type: section field id → where it goes (first value wins; the rest become
 * custom fields). Logins (001), secure notes (003) and passwords (005) are read as before.
 */
const OP_TYPES: Record<string, { type: RecordType; doc?: string; map: Record<string, string> }> = {
  "002": { type: "card", map: { cardholder: "data.cardholder", ccnum: "data.number", cvv: "data.cvv", expiry: "data.expiry", pin: "data.pin" } },
  "101": { type: "bankAccount", map: { bankname: "data.bank", owner: "data.accountName", iban: "data.accountNumber", accountno: "data.accountNumber", swift: "data.routing", routingno: "data.routing" } },
  "110": { type: "server", map: { url: "data.hostname", username: "username", password: "password" } },
  "102": { type: "database", map: { database_type: "data.dbType", hostname: "data.host", port: "data.port", database: "data.database", username: "username", password: "password" } },
  "109": { type: "wifi", map: { network_name: "data.ssid", wireless_password: "password", wireless_security: "data.security" } },
  "100": { type: "softwareLicence", map: { reg_code: "data.licenceKey", reg_name: "data.licensedTo", product_version: "data.version", order_date: "data.purchaseDate", expiry_date: "data.expiryDate" } },
  "106": { type: "identity", doc: "passport", map: { fullname: "data.fullName", number: "data.number", nationality: "data.nationality", issuing_authority: "data.authority", issue_date: "data.issueDate", expiry_date: "data.expiryDate" } },
  "103": { type: "identity", doc: "drivingLicence", map: { fullname: "data.fullName", number: "data.number", expiry_date: "data.expiryDate" } },
  "112": { type: "apiKey", map: { credential: "data.secret", username: "data.keyId", hostname: "data.endpoint" } },
  "114": { type: "sshKey", map: { private_key: "data.privateKey" } },
  "105": { type: "membership", map: { org_name: "data.organisation", membership_no: "data.memberId", expiry_date: "data.expiryDate" } },
  "004": { type: "contact", map: { company: "data.company", email: "data.email", defphone: "data.phone", cellphone: "data.phone", homephone: "data.phone", busphone: "data.phone" } },
};

type OpField = { value: string; kind?: DraftField["kind"]; publicKey?: string } | null;
/** A 1Password section field value with the kind it says it is (concealed, email, phone, url, date, month-year, address, SSH key…). */
function opField(v: unknown): OpField {
  for (const [k, x] of Object.entries(obj(v) ?? {})) {
    if (k === "totp" || k === "reference" || k === "file") continue;
    const o = obj(x);
    if (k === "email") return o && typeof o.email_address === "string" ? { value: o.email_address, kind: "email" } : typeof x === "string" ? { value: x, kind: "email" } : null;
    if (k === "address" && o) return { value: [str(o.street), [str(o.city), str(o.state), str(o.zip)].filter(Boolean).join(" "), str(o.country)].filter(Boolean).join("\n"), kind: "multiline" };
    if (k === "sshKey" && o) return { value: text(o.privateKey), kind: "hiddenMultiline", publicKey: str(obj(o.metadata)?.publicKey) };
    if (k === "monthYear") { const n = String(x); return /^\d{6}$/.test(n) ? { value: `${n.slice(4)}/${n.slice(0, 4)}`, kind: "text" } : null; }
    if (k === "date") { const d = isoDate(x); return d ? { value: d, kind: "date" } : null; }
    if (typeof x !== "string" && typeof x !== "number") continue;
    const s = String(x);
    const kind = k === "concealed" || k === "creditCardNumber" ? "secret" : k === "phone" ? "phone" : k === "url" ? "url" : undefined;
    return { value: s, ...(kind ? { kind } : {}) };
  }
  return null;
}
/** The export.data JSON inside a .1pux zip: accounts → vaults → items. Vaults become folders. */
function parseOnePux(data: { accounts: unknown[] }): ParseResult {
  const raws: { raw: Raw | string; row: number }[] = [];
  let row = 0;
  for (const acc of arr(data.accounts).map(obj)) for (const vault of arr(acc?.vaults).map(obj)) {
    const folder = str(obj(vault?.attrs)?.name);
    for (const x of arr(vault?.items)) {
      row++;
      const it = obj(x);
      if (!it) { raws.push({ raw: "Not an item", row }); continue; }
      const ov = obj(it.overview) ?? {}, d = obj(it.details) ?? {};
      const title = str(ov.title), cat = str(it.categoryUuid);
      const skip = (reason: string) => raws.push({ raw: { title, skip: reason }, row });
      const def = Object.hasOwn(OP_TYPES, cat) ? OP_TYPES[cat] : undefined;
      if (cat !== "001" && cat !== "003" && cat !== "005" && !def) { skip(`${(Object.hasOwn(OP_CATEGORY, cat) ? OP_CATEGORY[cat] : null) ?? "These items"} aren't supported`); continue; }
      if (it.state === "archived") { skip("Archived"); continue; }
      if (it.trashed === true) { skip("In the trash"); continue; }
      const fields = arr(d.loginFields).map(obj);
      const by = (des: string) => text(fields.find((f) => f?.designation === des)?.value);
      const fill: Fill = { type: def?.type, data: {}, custom: [], username: by("username") || undefined, password: by("password") || text(d.password) || undefined };
      if (def?.doc) fill.data.docType = def.doc;
      let totp: string | undefined;
      const name: string[] = [];
      for (const sec of arr(d.sections).map(obj)) for (const f of arr(sec?.fields).map(obj)) {
        const t = str(obj(f?.value)?.totp);
        if (t) { if (totp === undefined) totp = t; else fill.custom.push({ label: str(f?.title) || "One-time code", value: t, kind: "totp" }); continue; }
        const v = opField(f?.value);
        if (!v || !v.value.trim()) continue;
        const id = str(f?.id).toLowerCase(), label = str(f?.title) || "Field";
        if (cat === "004" && (id === "firstname" || id === "initial" || id === "lastname")) { name.push(v.value.trim()); continue; }
        const target = def && Object.hasOwn(def.map, id) ? def.map[id] : undefined;
        if (target === "data.privateKey") { assign(fill, target, v.value, label); if (v.publicKey) assign(fill, "data.publicKey", v.publicKey, "Public key"); continue; }
        if (target) {
          // A month-year expiry for a date field: the first of that month.
          const value = /Date$/.test(target) && /^\d{2}\/\d{4}$/.test(v.value) ? `${v.value.slice(3)}-${v.value.slice(0, 2)}-01` : v.value;
          assign(fill, target, value, label);
          continue;
        }
        fill.custom.push({ label, value: v.value, ...(v.kind ? { kind: v.kind } : {}) });
      }
      if (name.length) fill.data.name = name.join(" ");
      if (def?.type === "card" && fill.data.cardholder === undefined && str(ov.subtitle) && !/\d/.test(str(ov.subtitle))) fill.data.cardholder = str(ov.subtitle);
      const url = str(ov.url) || str(obj(arr(ov.urls)[0])?.url);
      raws.push({ row, raw: def
        ? { title, type: def.type, username: fill.username, password: fill.password, url, totp, notes: text(d.notesPlain), data: fill.data, custom: fill.custom, folder }
        : { title, username: fill.username, password: fill.password, url, totp, notes: text(d.notesPlain), custom: fill.custom, folder, forceNote: cat === "003" } });
    }
  }
  return collect("1password-1pux", raws);
}

// ---------- Generic CSV ----------
export type MappedField = "title" | "username" | "password" | "url" | "totp" | "notes" | "folder";
export const MAPPED_FIELDS: { field: MappedField; label: string }[] = [
  { field: "title", label: "Title" }, { field: "username", label: "Username" }, { field: "password", label: "Password" }, { field: "url", label: "Website" },
  { field: "totp", label: "2FA secret" }, { field: "notes", label: "Notes" }, { field: "folder", label: "Folder" },
];
/** Column index per field; a field without a column isn't imported. */
export type ColumnMapping = Partial<Record<MappedField, number>>;
const GUESS: Record<MappedField, RegExp> = {
  title: /^(title|name|account|account_name|item|item_name|entry|service|site_name|password_name)$/,
  username: /^(username|user|user_name|login|login_name|email|e-mail|user_id|userid)$/,
  password: /^(password|pass|passwd|pwd|login_password)$/,
  url: /^(url|uri|website|web_site|site|address|login_url|link|hostname|host)$/,
  totp: /^(totp|otp|otpauth|2fa|mfa|one-time_password|authenticator|otp_secret|totp_secret)$/,
  notes: /^(notes|note|comment|comments|description|extra|remarks)$/,
  folder: /^(folder|group|grouping|category|collection|vault|path|folder_name)$/,
};
/** Picks a column for each field from the header names (one column per field). */
export function guessMapping(header: string[]): ColumnMapping {
  const m: ColumnMapping = {};
  const used = new Set<number>();
  for (const { field } of MAPPED_FIELDS) {
    const i = header.findIndex((h, j) => !used.has(j) && GUESS[field].test(norm(h)));
    if (i >= 0) { m[field] = i; used.add(i); }
  }
  return m;
}
/** Parses CSV rows (the first is the header) with the user's column mapping. */
export function parseMappedCsv(rows: string[][], mapping: ColumnMapping): ParseResult {
  if (mapping.title === undefined && mapping.password === undefined && mapping.url === undefined) throw new ImportFormatError("Choose at least the title, password or website column.");
  const cell = (r: string[], f: MappedField) => (mapping[f] === undefined ? "" : r[mapping[f]!] ?? "");
  return collect("generic-csv", rows.slice(1).map((r, i) => ({ raw: {
    title: cell(r, "title"), username: cell(r, "username"), password: cell(r, "password"), url: cell(r, "url"), totp: cell(r, "totp"), notes: cell(r, "notes"), folder: cell(r, "folder"),
  }, row: i + 2 })));
}

const HEADER_WORDS = new Set(["name", "title", "url", "uri", "website", "username", "user", "login", "email", "password", "pass", "notes", "note", "folder", "group", "type", "totp", "otp", "extra", "grouping", "fav", "favorite", "login_uri", "login_username", "login_password"]);
/** Two or more cells that are typical column names means a header row from some other exporter. */
const looksLikeHeader = (cells: string[]) => cells.filter((c) => HEADER_WORDS.has(c)).length >= 2;

/** Detects the format from JSON shape or CSV header and parses it. Never sends anything anywhere. */
export function parseImport(text: string): ParseResult {
  const t = text.replace(/^﻿/, "").trim();
  if (!t) throw new ImportFormatError("The file is empty.");
  if (t.startsWith("{") || t.startsWith("[")) {
    let data: unknown;
    try { data = JSON.parse(t); } catch { throw new ImportFormatError("The file looks like JSON but can't be read."); }
    const d = data as Record<string, unknown>;
    if (d && Array.isArray(d.records)) return parseKeeperJson(d as { records: unknown[] });
    if (d && Array.isArray(d.items)) return parseBitwardenJson(d as { items: unknown[]; folders?: unknown; encrypted?: boolean });
    if (d && d.encrypted === true) return parseBitwardenJson({ encrypted: true, items: [] });
    if (d && Array.isArray(d.accounts)) return parseOnePux(d as { accounts: unknown[] });
    throw new ImportFormatError("This JSON file isn't a Keeper, Bitwarden or 1Password export.");
  }
  const rows = parseCsv(t);
  if (!rows.length) throw new ImportFormatError("The file is empty.");
  const header = rows[0]!.map(norm);
  if (has(header, ["name", "login_uri", "login_username", "login_password"])) return parseBitwardenCsv(rows);
  if (header.includes("secretdata") && (header.includes("password_name") || header.includes("secret_name"))) return parseZohoCsv(rows);
  if (has(header, ["url", "username", "password", "extra", "name", "grouping"])) return parseLastPassCsv(rows);
  if (has(header, ["username", "title", "password", "note", "url"]) || (header[0] === "title" && header[1] === "note")) return parseDashlaneCsv(rows);
  if (has(header, ["type", "account_name", "account_holder", "cc_number"])) return parseDashlanePayments(rows);
  if (has(header, ["type", "number", "name", "issue_date", "expiration_date"])) return parseDashlaneIds(rows);
  if (has(header, ["title", "username", "password"]) && (header.includes("url") || header.includes("website"))) return parseOnePasswordCsv(rows);
  if (has(header, ["name", "url", "username", "password"])) return parseChromeCsv(rows);
  if (has(header, KEEPER_HEADER)) return parseKeeperCsv(rows);
  // Keeper writes no header row. Only fall back to that layout when the first row doesn't look like some other header.
  if (!looksLikeHeader(header) && rows.every((r) => r.length >= 4)) return parseKeeperCsv(rows);
  // Any other CSV with a header row and data: the import sheet offers a column mapping.
  if (rows.length >= 2 && rows[0]!.length >= 2) throw new UnrecognisedCsvError(rows);
  throw new ImportFormatError(UNRECOGNISED);
}

/** The largest export.data we inflate from a .1pux (a zip bomb would otherwise exhaust the tab's memory). */
export const MAX_1PUX_DATA = 64 * 1024 * 1024;

/** A file's bytes: a zip (1Password .1pux) is opened here, anything else is read as UTF-8 text. */
export function parseImportFile(bytes: Uint8Array): ParseResult {
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    let files: Record<string, Uint8Array>;
    let tooBig = false;
    // fflate inflates into a buffer of the declared size, so refusing a large declared size bounds the memory used.
    const want = (f: { name: string; originalSize: number }) => f.name === "export.data" && !(tooBig = f.originalSize > MAX_1PUX_DATA);
    try { files = unzipSync(bytes, { filter: want }); }
    catch { throw new ImportFormatError("The zip file can't be read."); }
    if (tooBig) throw new ImportFormatError("The 1Password export is too large to import.");
    const data = files["export.data"];
    if (!data) throw new ImportFormatError("This zip file isn't a 1Password export (.1pux).");
    let parsed: unknown;
    try { parsed = JSON.parse(strFromU8(data)); } catch { throw new ImportFormatError("The 1Password export can't be read."); }
    if (!Array.isArray(obj(parsed)?.accounts)) throw new ImportFormatError("The 1Password export can't be read.");
    return parseOnePux(parsed as { accounts: unknown[] });
  }
  return parseImport(new TextDecoder().decode(bytes));
}

/** Folder name → number of records, for the preview. */
export function folderCounts(items: ImportItem[]): { folder: string | null; count: number }[] {
  const m = new Map<string | null, number>();
  for (const it of items) m.set(it.folder, (m.get(it.folder) ?? 0) + 1);
  return [...m.entries()].map(([folder, count]) => ({ folder, count })).sort((a, b) => (a.folder === null ? 1 : b.folder === null ? -1 : a.folder.localeCompare(b.folder)));
}
