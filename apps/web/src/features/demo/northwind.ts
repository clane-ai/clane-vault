/**
 * Northwind: the made-up company of the public demo's sandboxes (docs/demo.md) and of the flyer screenshots
 * (e2e/showcase/flyer.spec.ts imports this file). Every name, address, key and secret here is invented: example.com
 * people, test card numbers, fake keys that belong to nothing.
 *
 * Records are written the way a person fills the editor: the record type's label and each field's label (and, for
 * closed lists, the option's label). The flyer types them into the UI; the demo maps them to the record templates
 * (seed.ts). No imports, so the e2e runner can load it as it is.
 */

export interface NorthwindPerson { name: string; email: string }
export type NorthwindPermission = "Can edit" | "Can view" | "Use only";
/** A field the user added (docs/record-types.md): any label, one of the field kinds. */
export interface NorthwindCustomField { label: string; kind: "text" | "secret" | "url" | "email" | "phone" | "date" | "multiline"; value: string }
export interface NorthwindRecord {
  /** The record type's label, e.g. "Server credentials". */ type: string;
  title: string;
  /** Field label → value. */ fields?: Record<string, string>;
  /** Closed-list field label → option label. */ options?: Record<string, string>;
  notes?: string;
  /** Custom fields (the demo adds them; the flyer leaves them out). */ custom?: NorthwindCustomField[];
}
export interface NorthwindFolder { name: string; people: [NorthwindPerson, NorthwindPermission][]; records: NorthwindRecord[] }

export const SARA: NorthwindPerson = { name: "Sara Okafor", email: "sara@example.com" };
export const BEA: NorthwindPerson = { name: "Bea Lindqvist", email: "bea@example.com" };
export const PRIYA: NorthwindPerson = { name: "Priya Nair", email: "priya@example.com" };
export const TOM: NorthwindPerson = { name: "Tom Reyes", email: "tom@example.com" };
export const LIAM: NorthwindPerson = { name: "Liam Chen", email: "liam@example.com" };
export const MAYA: NorthwindPerson = { name: "Maya Haddad", email: "maya@example.com" };

/** FNV-1a: a 32-bit seed from a string. */
function seedOf(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}

/** Deterministic made-up base64 (fake keys and certificates: they belong to nothing). Same seed, same text. */
export function fakeB64(seed: string, bytes: number): string {
  // mulberry32: a small, fast, deterministic generator; not for anything secret.
  let a = seedOf(seed);
  let bin = "";
  for (let i = 0; i < bytes; i++) {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    bin += String.fromCharCode(((t ^ (t >>> 14)) >>> 0) & 0xff);
  }
  return btoa(bin);
}
const wrap = (s: string, n = 64) => s.match(new RegExp(`.{1,${n}}`, "g"))!.join("\n");

export const PRIVATE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrap(fakeB64("northwind deploy key", 300), 70)}\n-----END OPENSSH PRIVATE KEY-----`;
export const PUBLIC_KEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${fakeB64("northwind deploy pub", 32).replace(/=+$/, "")} deploy@northwind`;
/** The TLS certificate file (PEM text) attached to the production server. */
export const CERT_PEM = `-----BEGIN CERTIFICATE-----\n${wrap(fakeB64("northwind wildcard cert", 900))}\n-----END CERTIFICATE-----\n`;

export const AGREEMENT_PDF_NAME = "maintenance-agreement.pdf";
export const CERT_NAME = "wildcard-example-com.pem";

/** A one-page A4 PDF (about 1.5 KB): a made-up maintenance agreement. */
export function agreementPdf(): Uint8Array {
  const esc = (s: string) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const lines: [number, number, string][] = [
    [20, 790, "Server maintenance agreement"],
    [11, 762, "Northwind Ltd  and  Harbour Hosting Ltd (example.com)"],
    [10, 720, "1. Scope"],
    [10, 702, "Harbour Hosting maintains the production web server (deploy@10.20.0.5) and its"],
    [10, 688, "backups. Patches are applied in the Sunday window, 02:00-04:00 UTC."],
    [10, 656, "2. Response times"],
    [10, 638, "Critical: 1 hour, around the clock.   High: 4 hours.   Normal: next business day."],
    [10, 606, "3. Access"],
    [10, 588, "Credentials are shared through Clane Vault only. No passwords by email or chat."],
    [10, 574, "Engineers get Use only access; nothing is copied out of the vault."],
    [10, 542, "4. Term"],
    [10, 524, "Twelve months from 1 October 2026, renewing yearly unless either side gives notice."],
    [10, 460, "Signed for Northwind Ltd: Sara Okafor          Signed for Harbour Hosting: Tom Reyes"],
  ];
  const stream = lines.map(([size, y, t]) => `BT /F${size >= 20 ? 2 : 1} ${size} Tf 56 ${y} Td (${esc(t)}) Tj ET`).join("\n")
    + "\n0.85 0.86 0.9 RG 56 740 m 539 740 l S 56 476 m 539 476 l S";
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  // Latin-1: every character here is ASCII, one byte each.
  return Uint8Array.from(out, (c) => c.charCodeAt(0) & 0xff);
}

/** The organisation's shared folders, who is in them, and their records. */
export const NORTHWIND_FOLDERS: NorthwindFolder[] = [
  { name: "Infrastructure", people: [[BEA, "Can edit"], [TOM, "Can edit"], [LIAM, "Use only"]], records: [
    { type: "Server credentials", title: "Production web server", options: { Protocol: "SSH" },
      fields: { "Hostname or IP": "10.20.0.5", Port: "22", Username: "deploy", Password: "Qm7#vT2x!Rk9pL4w" },
      notes: "web-01 in rack A3. Harbour Hosting patches it on Sundays.",
      custom: [{ label: "Rack", kind: "text", value: "A3, unit 14" }, { label: "Hosting support PIN", kind: "secret", value: "731 904" }] },
    { type: "Login", title: "AWS root account", fields: { Username: "ops@example.com", Password: "vR8#tQ2m!Lx6pZ9w", Website: "console.aws.amazon.com" },
      notes: "Root user. Billing and break-glass only." },
    { type: "SSH key", title: "Deploy key", fields: { Username: "deploy", Host: "git.example.com", "Private key": PRIVATE_KEY, "Public key": PUBLIC_KEY } },
    { type: "Database credentials", title: "Orders database", options: { Type: "PostgreSQL" },
      fields: { Host: "db-01.example.com", Port: "5432", Database: "orders", Username: "app_rw", Password: "Hn4$kW8z@Pc3tF6q" } },
    { type: "API key / secret", title: "Cloudflare API token", fields: { Service: "Cloudflare", "Key ID": "nw-dns-edit", Secret: "cf_9fXq2LmZ7tR4vK8wN3bH6yD1sJ5pG0aE", Endpoint: "https://api.example.com" } },
    { type: "Login", title: "GitHub org owner", fields: { Username: "northwind-bot", Password: "pF6&zR1x#Mv8sJ3k", Website: "github.com" } },
  ] },
  { name: "Finance", people: [[PRIYA, "Can edit"], [BEA, "Can view"]], records: [
    { type: "Payment card", title: "Company Visa", fields: { Cardholder: "Sara Okafor", "Card number": "4242 4242 4242 4242", Expiry: "08/29",
      "Security code": "737", PIN: "4821", "Billing address": "12 Harbour Street\nDublin D02 XY45\nIreland" } },
    { type: "Bank account", title: "Operating account", fields: { "Account name": "Northwind Ltd", Bank: "Example Bank", "IBAN / account number": "IE29 EXMP 9311 5212 3456 78",
      "BIC / sort code / routing": "EXMPIE2D", "Online banking login": "northwind-fin", Password: "Bx9!rJ4w@Tn7qK2h" } },
    { type: "Login", title: "Stripe dashboard", fields: { Username: "finance@example.com", Password: "Lm2^gS6t#Pk9vE4r", Website: "dashboard.stripe.com" } },
  ] },
  { name: "Office", people: [[BEA, "Can view"], [PRIYA, "Can view"], [TOM, "Can view"], [MAYA, "Can view"]], records: [
    { type: "Wi-Fi", title: "Office Wi-Fi", options: { Security: "WPA3" }, fields: { "Network name (SSID)": "Northwind-Staff", Password: "harbour-lantern-42" } },
    { type: "Wi-Fi", title: "Guest Wi-Fi", options: { Security: "WPA2" }, fields: { "Network name (SSID)": "Northwind-Guest", Password: "welcome-tide-17" } },
    { type: "Software licence", title: "Adobe Creative Cloud", fields: { Product: "Creative Cloud Teams", "Licence key": "NW7Q-4KXP-9TZM-2RBC", "Licensed to": "Northwind Ltd", Version: "2026" } },
  ] },
  { name: "Clients", people: [[MAYA, "Can edit"], [PRIYA, "Can view"]], records: [
    { type: "Login", title: "Acme customer portal", fields: { Username: "northwind-support", Password: "Tg7#qL2v!Rm9zW4x", Website: "portal.example.com" },
      notes: "Support login for Acme Ltd's portal. Tickets go to support@example.com." },
    { type: "Contact", title: "Acme IT contact", fields: { Name: "Jordan Blake", Company: "Acme Ltd", Email: "jordan@example.com", Phone: "+353 1 555 0142" } },
  ] },
];

/** The demo visitor's own items (the Personal space): the record types the shared folders don't use. */
export const PERSONAL_RECORDS: NorthwindRecord[] = [
  { type: "Login", title: "Personal email", fields: { Username: "sara.okafor@example.com", Password: "tidal-Quartz-81-lantern", Website: "mail.example.com" } },
  { type: "Identity document", title: "Passport", options: { "Document type": "Passport" },
    fields: { "Full name": "Sara Okafor", "Document number": "PX4417290", Nationality: "Irish", "Issue date": "2022-03-14", "Expiry date": "2032-03-13", "Issuing authority": "Example Passport Office" } },
  { type: "Address", title: "Home", fields: { Street: "4 Quay Lane", City: "Dublin", "County / state": "Dublin", Postcode: "D08 EX12", Country: "Ireland" } },
  { type: "Membership", title: "Harbour Gym", fields: { Organisation: "Harbour Gym", "Member ID": "HG-20931", Password: "rowing-Maple-27", "Expiry date": "2027-01-31" } },
  { type: "Secure note", title: "Spare key", notes: "The spare office key is with reception, envelope 12. Ask for it by name.",
    custom: [{ label: "Reception phone", kind: "phone", value: "+353 1 555 0100" }] },
];

/** Made-up colleagues in every demo sandbox (the flyer registers all six people above instead). */
export const DEMO_COLLEAGUES: NorthwindPerson[] = [BEA, TOM];
