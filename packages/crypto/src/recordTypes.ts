/**
 * Record types and their field templates (docs/record-types.md). Shared by the web app, the extension and the record
 * validator, so a template is the single source of what a type holds.
 *
 * A template field is either a core field (`core: true`: username, password, url, totpSecret, stored at the top of the
 * body, as v1 logins always did) or a typed data field (stored in `body.data[key]`). The core `password` is the one
 * password-like credential password health looks at; card numbers, CVVs, PINs, licence keys and SSH keys are data fields.
 */

export const RECORD_TYPES = [
  "login", "note", "card", "bankAccount", "server", "database", "sshKey", "apiKey", "wifi", "softwareLicence", "identity", "address", "contact", "membership",
] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

/** Field kinds, for template fields and custom fields alike. */
export const FIELD_KINDS = ["text", "secret", "multiline", "url", "email", "phone", "date", "totp", "hiddenMultiline"] as const;
export type FieldKind = (typeof FIELD_KINDS)[number];
/** Kinds that are hidden until revealed, never shown to "Use only" holders and never searched. */
export const SECRET_KINDS: ReadonlySet<FieldKind> = new Set<FieldKind>(["secret", "totp", "hiddenMultiline"]);
export const isSecretKind = (k: FieldKind) => SECRET_KINDS.has(k);

export const CORE_KEYS = ["username", "password", "url", "totpSecret"] as const;
export type CoreKey = (typeof CORE_KEYS)[number];

export type RecordTypeGroup = "access" | "finance" | "identity" | "other";
export const GROUP_LABEL: Record<RecordTypeGroup, string> = { access: "Logins & access", finance: "Payments & finance", identity: "Identity", other: "Other" };

export interface TemplateField {
  key: string; label: string; kind: FieldKind;
  /** Stored at the top of the body (username, password, url, totpSecret) rather than in `data`. */ core?: true;
  /** Input and display helpers: digits in groups of four with a Luhn hint, MM/YY, a port number. */ format?: "cardNumber" | "expiry" | "port";
  /** A closed list (stored as the option's value). */ options?: readonly { value: string; label: string }[];
  placeholder?: string;
  /** Shown in a monospace face (keys, numbers, hosts). */ mono?: boolean;
}
export interface RecordTypeDef { id: RecordType; label: string; group: RecordTypeGroup; fields: readonly TemplateField[] }

const opts = (...xs: [string, string][]) => xs.map(([value, label]) => ({ value, label }));
const USERNAME: TemplateField = { key: "username", label: "Username", kind: "text", core: true, mono: true };
const PASSWORD: TemplateField = { key: "password", label: "Password", kind: "secret", core: true, mono: true };

export const IDENTITY_DOCS = opts(["passport", "Passport"], ["drivingLicence", "Driving licence"], ["idCard", "ID card"], ["other", "Other"]);

const DEFS: readonly RecordTypeDef[] = [
  { id: "login", label: "Login", group: "access", fields: [
    USERNAME, PASSWORD, { key: "url", label: "Website", kind: "url", core: true, placeholder: "example.com" },
    { key: "totpSecret", label: "2FA secret", kind: "totp", core: true, mono: true, placeholder: "JBSW Y3DP EHPK 3PXP" },
  ] },
  { id: "server", label: "Server credentials", group: "access", fields: [
    { key: "hostname", label: "Hostname or IP", kind: "text", mono: true, placeholder: "srv-01.example.net" },
    { key: "port", label: "Port", kind: "text", format: "port", mono: true, placeholder: "22" },
    { key: "protocol", label: "Protocol", kind: "text", options: opts(["ssh", "SSH"], ["rdp", "RDP"], ["vnc", "VNC"], ["https", "HTTPS"], ["telnet", "Telnet"], ["other", "Other"]) },
    USERNAME, PASSWORD,
  ] },
  { id: "database", label: "Database credentials", group: "access", fields: [
    { key: "dbType", label: "Type", kind: "text", options: opts(["postgresql", "PostgreSQL"], ["mysql", "MySQL / MariaDB"], ["sqlserver", "SQL Server"], ["oracle", "Oracle"], ["mongodb", "MongoDB"], ["redis", "Redis"], ["other", "Other"]) },
    { key: "host", label: "Host", kind: "text", mono: true, placeholder: "db.internal" },
    { key: "port", label: "Port", kind: "text", format: "port", mono: true, placeholder: "5432" },
    { key: "database", label: "Database", kind: "text", mono: true },
    USERNAME, PASSWORD,
    { key: "connectionString", label: "Connection string", kind: "secret", mono: true },
  ] },
  { id: "sshKey", label: "SSH key", group: "access", fields: [
    USERNAME,
    { key: "host", label: "Host", kind: "text", mono: true },
    { key: "privateKey", label: "Private key", kind: "hiddenMultiline", mono: true, placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----" },
    { key: "publicKey", label: "Public key", kind: "multiline", mono: true, placeholder: "ssh-ed25519 AAAA…" },
    { key: "passphrase", label: "Passphrase", kind: "secret", mono: true },
  ] },
  { id: "apiKey", label: "API key / secret", group: "access", fields: [
    { key: "service", label: "Service", kind: "text" },
    { key: "keyId", label: "Key ID", kind: "text", mono: true },
    { key: "secret", label: "Secret", kind: "secret", mono: true },
    { key: "endpoint", label: "Endpoint", kind: "url", placeholder: "https://api.example.com" },
  ] },
  { id: "wifi", label: "Wi-Fi", group: "access", fields: [
    { key: "ssid", label: "Network name (SSID)", kind: "text" },
    PASSWORD,
    { key: "security", label: "Security", kind: "text", options: opts(["wpa3", "WPA3"], ["wpa2", "WPA2"], ["wpa", "WPA"], ["wpa2-enterprise", "WPA2/3 Enterprise"], ["wep", "WEP"], ["open", "Open"]) },
  ] },
  { id: "card", label: "Payment card", group: "finance", fields: [
    { key: "cardholder", label: "Cardholder", kind: "text" },
    { key: "number", label: "Card number", kind: "secret", format: "cardNumber", mono: true, placeholder: "4242 4242 4242 4242" },
    { key: "expiry", label: "Expiry", kind: "text", format: "expiry", mono: true, placeholder: "MM/YY" },
    { key: "cvv", label: "Security code", kind: "secret", mono: true },
    { key: "pin", label: "PIN", kind: "secret", mono: true },
    { key: "billingAddress", label: "Billing address", kind: "multiline" },
  ] },
  { id: "bankAccount", label: "Bank account", group: "finance", fields: [
    { key: "accountName", label: "Account name", kind: "text" },
    { key: "bank", label: "Bank", kind: "text" },
    { key: "accountNumber", label: "IBAN / account number", kind: "text", mono: true },
    { key: "routing", label: "BIC / sort code / routing", kind: "text", mono: true },
    { ...USERNAME, label: "Online banking login" }, PASSWORD,
  ] },
  { id: "identity", label: "Identity document", group: "identity", fields: [
    { key: "docType", label: "Document type", kind: "text", options: IDENTITY_DOCS },
    { key: "fullName", label: "Full name", kind: "text" },
    { key: "number", label: "Document number", kind: "secret", mono: true },
    { key: "nationality", label: "Nationality", kind: "text" },
    { key: "issueDate", label: "Issue date", kind: "date" },
    { key: "expiryDate", label: "Expiry date", kind: "date" },
    { key: "authority", label: "Issuing authority", kind: "text" },
  ] },
  { id: "contact", label: "Contact", group: "identity", fields: [
    { key: "name", label: "Name", kind: "text" },
    { key: "company", label: "Company", kind: "text" },
    { key: "email", label: "Email", kind: "email" },
    { key: "phone", label: "Phone", kind: "phone" },
  ] },
  { id: "address", label: "Address", group: "identity", fields: [
    { key: "street1", label: "Street", kind: "text" },
    { key: "street2", label: "Street line 2", kind: "text" },
    { key: "city", label: "City", kind: "text" },
    { key: "region", label: "County / state", kind: "text" },
    { key: "postcode", label: "Postcode", kind: "text" },
    { key: "country", label: "Country", kind: "text" },
  ] },
  { id: "membership", label: "Membership", group: "identity", fields: [
    { key: "organisation", label: "Organisation", kind: "text" },
    { key: "memberId", label: "Member ID", kind: "text", mono: true },
    PASSWORD,
    { key: "expiryDate", label: "Expiry date", kind: "date" },
  ] },
  { id: "note", label: "Secure note", group: "other", fields: [] },
  { id: "softwareLicence", label: "Software licence", group: "other", fields: [
    { key: "product", label: "Product", kind: "text" },
    { key: "licenceKey", label: "Licence key", kind: "secret", mono: true },
    { key: "licensedTo", label: "Licensed to", kind: "text" },
    { key: "version", label: "Version", kind: "text" },
    { key: "purchaseDate", label: "Purchase date", kind: "date" },
    { key: "expiryDate", label: "Expiry date", kind: "date" },
  ] },
];

export const RECORD_TYPE_DEFS: Readonly<Record<RecordType, RecordTypeDef>> = Object.fromEntries(DEFS.map((d) => [d.id, d])) as Record<RecordType, RecordTypeDef>;
/** Types in picker order, grouped. */
export const RECORD_TYPE_GROUPS: { group: RecordTypeGroup; label: string; types: RecordTypeDef[] }[] = (["access", "finance", "identity", "other"] as const)
  .map((g) => ({ group: g, label: GROUP_LABEL[g], types: DEFS.filter((d) => d.group === g) }));

export const isRecordType = (t: unknown): t is RecordType => typeof t === "string" && (RECORD_TYPES as readonly string[]).includes(t);
export const typeLabel = (t: RecordType) => RECORD_TYPE_DEFS[t]?.label ?? "Record";
export const templateOf = (t: RecordType): readonly TemplateField[] => RECORD_TYPE_DEFS[t]?.fields ?? [];
export const dataKeysOf = (t: RecordType) => templateOf(t).filter((f) => !f.core).map((f) => f.key);
export const coreKeysOf = (t: RecordType) => templateOf(t).filter((f) => f.core).map((f) => f.key as CoreKey);
/** An option's label, or the stored value when it isn't one of the options (imports). */
export const optionLabel = (f: TemplateField, v: string) => f.options?.find((o) => o.value === v)?.label ?? v;

/**
 * The server only learns a coarse type (docs/record-types.md): "login" when the record is a login the extension may
 * fill, "item" for everything else. The real type is inside the encrypted body.
 */
export type ServerRecordType = "login" | "item";
export const serverRecordType = (body: { type: RecordType }): ServerRecordType => (body.type === "login" ? "login" : "item");

/** Luhn check for a card number (digits only; spaces and dashes ignored). */
export function luhnValid(number: string): boolean {
  const d = number.replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}
/** Card brand from the number's prefix (display only). */
export function cardBrand(number: string): string | null {
  const d = number.replace(/\D/g, "");
  if (/^4/.test(d)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(d)) return "Mastercard";
  if (/^3[47]/.test(d)) return "Amex";
  if (/^(6011|65|64[4-9])/.test(d)) return "Discover";
  return null;
}
/** "MM/YY" with a real month. */
export const expiryValid = (v: string) => /^(0[1-9]|1[0-2])\/\d{2}$/.test(v.trim());
