import type { RecordType } from "@clane-vault/crypto";
import { dbTypeOf, expiryMMYY, guessKind, isoDate, nameLine, totpSecretFrom, wifiSecurityOf, type Draft, type DraftField } from "./typed";

/**
 * One Keeper record (web vault JSON, Commander JSON or CSV) as a typed draft. Keeper v3 record types map onto ours
 * (docs/record-types.md); whatever a type has no slot for becomes a custom field.
 */
export interface KeeperRaw { keeperType: string; title: string; login: string; password: string; url: string; notes: string; custom: [string, unknown][] }

const text = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "");
const str = (v: unknown) => text(v).trim();
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null);

const LABELS: Record<string, string> = {
  url: "URL", oneTimeCode: "One-time code", otp: "One-time code", pinCode: "PIN", paymentCard: "Payment card", cardNumber: "Card number",
  cardExpirationDate: "Expires", cardSecurityCode: "Security code", keyPair: "Key pair", publicKey: "Public key", privateKey: "Private key",
  hostName: "Host", accountNumber: "Account number", routingNumber: "Routing number", bankAccount: "Bank account", accountType: "Account type",
  street1: "Street", street2: "Street 2", zip: "Postal code", licenseNumber: "License number", secret: "Secret", phone: "Phone", email: "Email",
  login: "Login", password: "Password", text: "Text", multiline: "Text", note: "Note", name: "Name", first: "First name", middle: "Middle name", last: "Last name",
  securityQuestion: "Security question", question: "Question", answer: "Answer", date: "Date", expirationDate: "Expires", birthDate: "Birth date",
  passphrase: "Passphrase", host: "Host", port: "Port", region: "Region", type: "Type", number: "Number", ext: "Extension", fileRef: "File",
};
/** "cardNumber" → "Card number"; known names get their label. */
export const humanize = (k: string) => LABELS[k] ?? (k.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase()) || "Field");

interface Entry { type: string | null; raw: string; label: string; value: unknown; used?: boolean }

/** A custom field key: legacy "Label", v3 "$type", "$type:Label", each optionally with "::n". */
function parseKey(key: string): Omit<Entry, "value"> {
  const k = key.replace(/::\d+$/, "");
  if (/^TFC:/i.test(k)) return { type: "oneTimeCode", raw: "", label: "One-time code" };
  if (!k.startsWith("$")) return { type: null, raw: k.trim(), label: k.trim() || "Field" };
  const [type, ...rest] = k.slice(1).split(":");
  const raw = rest.join(":").trim();
  // Keeper's own labels are camelCase names ("cardholderName"); people's labels ("Account ID") are kept as typed.
  return { type: type!, raw, label: !raw ? humanize(type!) : /^[a-z][a-zA-Z0-9]*$/.test(raw) ? humanize(raw) : raw };
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const SECRET_TYPES = new Set(["secret", "password", "pinCode", "cardSecurityCode", "licenseNumber", "accountNumber"]);
const DATE_TYPES = new Set(["date", "birthDate", "expirationDate"]);

export const addressLines = (v: unknown): string => {
  const o = obj(v);
  if (!o) return str(v);
  return [str(o.street1), str(o.street2), [str(o.city), str(o.state), str(o.zip)].filter(Boolean).join(" "), str(o.country)].filter(Boolean).join("\n");
};
const hostLine = (o: Record<string, unknown>) => [str(o.hostName), str(o.port)].filter(Boolean).join(":");

/** Fields from a value Keeper has no slot for, with a sensible kind. */
function leftover(e: Entry): DraftField[] {
  const { type, label, value } = e;
  if (value == null) return [];
  if (Array.isArray(value)) return value.flatMap((x) => leftover({ ...e, value: x }));
  const o = obj(value);
  if (o) {
    if (type === "securityQuestion") return [{ label: str(o.question) ? "Security question" : label, value: str(o.question), kind: "text" }, { label: "Answer", value: text(o.answer), kind: "secret" }];
    if (type === "phone") return [{ label, value: [str(o.number), str(o.ext) && `ext. ${str(o.ext)}`].filter(Boolean).join(" "), kind: "phone" }];
    if (type === "name") return [{ label, value: nameLine(o), kind: "text" }];
    if (type === "address") return [{ label, value: addressLines(o), kind: "multiline" }];
    if (type === "host") return [{ label, value: hostLine(o), kind: "text" }];
    if (type === "keyPair") return [{ label: "Private key", value: text(o.privateKey), kind: "hiddenMultiline" }, { label: "Public key", value: text(o.publicKey), kind: "multiline" }];
    if (type === "paymentCard") return [
      { label: "Card number", value: str(o.cardNumber), kind: "secret" }, { label: "Expires", value: str(o.cardExpirationDate), kind: "text" },
      { label: "Security code", value: str(o.cardSecurityCode), kind: "secret" }];
    return Object.entries(o).flatMap(([k, x]) => leftover({ type: k, raw: k, label: humanize(k) === label ? label : `${label} · ${humanize(k)}`, value: x }));
  }
  const s = text(value);
  if (!s.trim()) return [];
  if (type && DATE_TYPES.has(type)) { const d = isoDate(value); return [d ? { label, value: d, kind: "date" } : { label, value: s, kind: "text" }]; }
  if (type && SECRET_TYPES.has(type)) return [{ label, value: s, kind: s.includes("\n") ? "hiddenMultiline" : "secret" }];
  if (type === "multiline" || type === "note") return [{ label, value: s, kind: "multiline" }];
  if (type === "email" && /@/.test(s)) return [{ label, value: s.trim(), kind: "email" }];
  return [{ label, value: s, kind: guessKind(label, s) }];
}

/** Keeper record types → ours. Anything else (encryptedNotes, files, photos…) becomes a secure note. */
const TYPE_MAP: Record<string, RecordType> = {
  "": "login", login: "login", general: "login", bankCard: "card", bankAccount: "bankAccount", serverCredentials: "server", databaseCredentials: "database",
  sshKeys: "sshKey", wifiCredentials: "wifi", softwareLicense: "softwareLicence", passport: "identity", driverLicense: "identity", ssnCard: "identity",
  birthCertificate: "identity", address: "address", contact: "contact", membership: "membership",
};
const DOC_TYPE: Record<string, string> = { passport: "passport", driverLicense: "drivingLicence", ssnCard: "other", birthCertificate: "other" };

export function keeperDraft(r: KeeperRaw): { draft: Draft; attachments: number } {
  const entries: Entry[] = r.custom.map(([k, value]) => ({ ...parseKey(k), value }));
  const urls: string[] = [];
  const pushUrl = (u: string) => { const x = u.trim(); if (x && !urls.includes(x)) urls.push(x); };
  pushUrl(r.url);
  const totps: string[] = [];
  let attachments = 0;
  for (const e of entries) {
    const values = (Array.isArray(e.value) ? e.value : [e.value]);
    if (e.type === "oneTimeCode" || e.type === "otp" || values.some((v) => /^otpauth:\/\//i.test(str(v)))) { totps.push(...values.map(str).filter(Boolean)); e.used = true; }
    else if (e.type === "url") { values.map(str).forEach(pushUrl); e.used = true; }
    else if (e.type === "fileRef") { attachments += Array.isArray(e.value) ? e.value.length : str(e.value) ? 1 : 0; e.used = true; }
    else if (e.type === "addressRef" || e.type === "cardRef") e.used = true; // references to other Keeper records: nothing to carry over
  }
  /** The first unused entry of a field type (and, when given, one of the labels), marked used. */
  const take = (types: string[], labels?: string[]) => {
    const e = entries.find((x) => !x.used && x.type !== null && types.includes(x.type) && (!labels || labels.includes(norm(x.raw))));
    if (e) e.used = true;
    return e?.value;
  };
  const textOf = (v: unknown) => (Array.isArray(v) ? str(v[0]) : str(v));
  const custom: DraftField[] = [];
  const data: Record<string, string> = {};
  /** A template date: ISO when Keeper's value reads as one, else kept as a custom text field. */
  const dateInto = (key: string, label: string, v: unknown) => {
    const x = Array.isArray(v) ? v[0] : v;
    if (x == null || text(x).trim() === "") return;
    const d = isoDate(x);
    if (d) data[key] = d; else custom.push({ label, value: text(x), kind: "text" });
  };

  const mapped = TYPE_MAP[r.keeperType];
  let type: RecordType = mapped ?? "note";
  let username: string | undefined = r.login, password: string | undefined = r.password;
  switch (type) {
    case "card": {
      const pc = obj(take(["paymentCard"])) ?? {};
      data.number = str(pc.cardNumber).replace(/[\s-]/g, "");
      const exp = str(pc.cardExpirationDate);
      if (exp) { const e = expiryMMYY(exp); if (e) data.expiry = e; else custom.push({ label: "Expires", value: exp, kind: "text" }); }
      data.cvv = str(pc.cardSecurityCode);
      data.cardholder = textOf(take(["text"], ["cardholdername", "cardholder", "nameoncard", ""])) || nameLine(take(["name"]));
      data.pin = textOf(take(["pinCode"]));
      const addr = take(["address"]);
      if (addr) data.billingAddress = addressLines(Array.isArray(addr) ? addr[0] : addr);
      break;
    }
    case "bankAccount": {
      const ba = obj(take(["bankAccount"])) ?? {};
      data.accountNumber = str(ba.accountNumber);
      data.routing = str(ba.routingNumber);
      if (str(ba.accountType)) custom.push({ label: "Account type", value: str(ba.accountType), kind: "text" });
      data.accountName = nameLine(take(["name"])) || textOf(take(["text"], ["accountname", "accountholder"]));
      data.bank = textOf(take(["text"], ["bank", "bankname"]));
      break;
    }
    case "server": case "database": {
      const h = obj(take(["host"])) ?? {};
      data[type === "server" ? "hostname" : "host"] = str(h.hostName);
      data.port = str(h.port);
      if (type === "database") {
        const t = textOf(take(["text"], ["type", "databasetype", "dbtype"]));
        if (t) data.dbType = dbTypeOf(t);
        data.database = textOf(take(["text"], ["database", "databasename", "dbname"]));
      }
      break;
    }
    case "sshKey": {
      const kp = obj(take(["keyPair"])) ?? {};
      data.privateKey = text(kp.privateKey);
      data.publicKey = text(kp.publicKey);
      const h = obj(take(["host"])) ?? {};
      data.host = str(h.hostName);
      if (str(h.port)) custom.push({ label: "Port", value: str(h.port), kind: "text" });
      // An SSH key record's password is the key's passphrase.
      data.passphrase = password ?? ""; password = undefined;
      break;
    }
    case "wifi": {
      data.ssid = textOf(take(["text"], ["ssid", "networkname", "network"]));
      const sec = textOf(take(["text"], ["security", "securitytype", "encryption", "authentication"]));
      if (sec) data.security = wifiSecurityOf(sec);
      break;
    }
    case "softwareLicence": {
      data.licenceKey = textOf(take(["licenseNumber"]));
      dateInto("expiryDate", "Expiry date", take(["expirationDate"]));
      dateInto("purchaseDate", "Purchase date", take(["date"]));
      data.product = textOf(take(["text"], ["product", "productname"]));
      data.version = textOf(take(["text"], ["version", "productversion"]));
      data.licensedTo = textOf(take(["text"], ["licensedto", "licensee"])) || nameLine(take(["name"]));
      break;
    }
    case "identity": {
      data.docType = DOC_TYPE[r.keeperType] ?? "other";
      data.fullName = nameLine(take(["name"]));
      data.number = textOf(take(["accountNumber", "licenseNumber"])) || textOf(take(["text"], ["number", "documentnumber", "identitynumber"]));
      dateInto("expiryDate", "Expiry date", take(["expirationDate"]));
      dateInto("issueDate", "Issue date", take(["date"], ["dateissued", "issuedate", "issued", ""]));
      data.nationality = textOf(take(["text"], ["nationality", "country"]));
      data.authority = textOf(take(["text"], ["issuingauthority", "authority", "placeofissue"]));
      break;
    }
    case "address": {
      const a = obj(take(["address"])) ?? {};
      Object.assign(data, { street1: str(a.street1), street2: str(a.street2), city: str(a.city), region: str(a.state), postcode: str(a.zip), country: str(a.country) });
      break;
    }
    case "contact": {
      data.name = nameLine(take(["name"]));
      data.company = textOf(take(["text"], ["company", "organization", "organisation"]));
      data.email = textOf(take(["email"]));
      const ph = take(["phone"]);
      const p0 = Array.isArray(ph) ? ph[0] : ph;
      data.phone = obj(p0) ? str(obj(p0)!.number) : str(p0);
      break;
    }
    case "membership": {
      data.memberId = textOf(take(["accountNumber"]));
      data.organisation = textOf(take(["text"], ["organization", "organisation", "company", ""])) || nameLine(take(["name"]));
      dateInto("expiryDate", "Expiry date", take(["expirationDate"]));
      break;
    }
    default: break;
  }
  for (const e of entries) if (!e.used) custom.push(...leftover(e));
  // A login with nothing to sign in with is a secure note (its fields are kept as custom fields).
  if (type === "login" && !str(username) && !text(password) && !urls.length && !totps.some((t) => totpSecretFrom(t))) type = "note";
  const [firstTotp, ...otherTotps] = totps;
  if (type === "login") {
    custom.push(...urls.slice(1).map((u) => ({ label: "Website", value: u, kind: "url" as const })));
  } else {
    custom.unshift(...urls.map((u) => ({ label: "Website", value: u, kind: "url" as const })));
  }
  custom.push(...otherTotps.map((t) => ({ label: "One-time code", value: t, kind: totpSecretFrom(t) ? "totp" as const : "text" as const })));
  return {
    draft: {
      type, title: r.title, username, password, url: type === "login" ? urls[0] : undefined, notes: r.notes,
      // A first one-time code that isn't usable is kept as text rather than lost.
      totp: firstTotp && totpSecretFrom(firstTotp) ? firstTotp : undefined,
      data, custom: firstTotp && !totpSecretFrom(firstTotp) ? [...custom, { label: "One-time code", value: firstTotp, kind: "text" }] : custom,
    },
    attachments,
  };
}
