import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { b64url, randomBytes, utf8, CryptoError } from "./encoding.js";
import { hkdf } from "./hkdf.js";
import { DEFAULT_KDF, deriveMasterKey, type KdfParams } from "./kdf.js";
import { cleanData, cleanFields, MAX_BODY_BYTES, type CustomField, type RecordBody } from "./records.js";
import { isRecordType, type RecordType } from "./recordTypes.js";
import { ATTACHMENT_NONCE_BASE_BYTES, validateAttachmentMeta, type AttachmentMeta } from "./attachments.js";

/**
 * A file a one-time link carries (docs/design/2026-10-12-attachments.md §2.4): its real file key, so the
 * recipient decrypts the stored chunks; nothing is re-encrypted. Opt-in per file and per link.
 */
export interface LinkAttachment { fileId: string; /** b64url, 32 bytes. */ fileKey: string; /** b64url, 8 bytes. */ nonceBase: string; meta: AttachmentMeta }
export const MAX_LINK_ATTACHMENTS = 25;
/** Plaintext JSON bytes of a link that carries files (its record fields alone still fit MAX_BODY_BYTES). */
export const MAX_LINK_BYTES = 64 * 1024;
const MAX_LINK_ATTACHMENT_BYTES = 4096;
const FILE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function cleanAttachments(list: unknown): LinkAttachment[] | undefined {
  if (list === undefined || list === null) return undefined;
  if (!Array.isArray(list)) throw new Error("link files must be a list");
  if (list.length > MAX_LINK_ATTACHMENTS) throw new Error(`a link carries at most ${MAX_LINK_ATTACHMENTS} files`);
  const seen = new Set<string>();
  const out = list.map((a: Partial<LinkAttachment>) => {
    if (!a || typeof a !== "object") throw new Error("link file is invalid");
    if (typeof a.fileId !== "string" || !FILE_ID.test(a.fileId) || seen.has(a.fileId)) throw new Error("link file id is invalid");
    seen.add(a.fileId);
    if (typeof a.fileKey !== "string" || b64url.decode(a.fileKey).length !== 32) throw new Error("link file key is invalid");
    if (typeof a.nonceBase !== "string" || b64url.decode(a.nonceBase).length !== ATTACHMENT_NONCE_BASE_BYTES) throw new Error("link file nonce is invalid");
    const item: LinkAttachment = { fileId: a.fileId, fileKey: a.fileKey, nonceBase: a.nonceBase, meta: validateAttachmentMeta(a.meta as AttachmentMeta) };
    if (utf8.encode(JSON.stringify(item)).length > MAX_LINK_ATTACHMENT_BYTES) throw new Error("link file is too large");
    return item;
  });
  return out.length ? out : undefined;
}

/**
 * The record fields a one-time link carries: a snapshot, never a TOTP secret (neither the login's 2FA secret nor a
 * TOTP custom field). `type` absent: a link made before record types (shown as a login).
 */
export interface LinkBody { title: string; type?: RecordType; username?: string; password?: string; url?: string; notes?: string; data?: Record<string, string>; fields?: CustomField[];
  /** Files the creator chose to include (absent: none). */ attachments?: LinkAttachment[] }

const FIELDS = ["username", "password", "url", "notes"] as const;
function clean(body: LinkBody): LinkBody {
  if (typeof body.title !== "string" || body.title.trim() === "") throw new Error("link title is required");
  const out: LinkBody = { title: body.title.trim() };
  if (body.type !== undefined) {
    if (!isRecordType(body.type)) throw new Error("link record type is invalid");
    out.type = body.type;
  }
  for (const f of FIELDS) {
    const v = body[f];
    if (v !== undefined && v !== "") out[f] = String(v);
  }
  if (out.type) {
    const data = cleanData(out.type, body.data);
    if (data) out.data = data;
  }
  const fields = cleanFields(body.fields, { dropTotp: true });
  if (fields) out.fields = fields;
  if (utf8.encode(JSON.stringify(out)).length > MAX_BODY_BYTES) throw new Error("link is too large");
  const attachments = cleanAttachments(body.attachments);
  if (attachments) {
    out.attachments = attachments;
    if (utf8.encode(JSON.stringify(out)).length > MAX_LINK_BYTES) throw new Error("link is too large");
  }
  return out;
}

/**
 * A record's one-time-link snapshot: its type and fields, without the 2FA secret or TOTP custom fields (clean drops
 * those), plus the files the creator chose to include.
 */
export const linkSnapshot = (b: RecordBody, attachments?: LinkAttachment[]): LinkBody => ({
  title: b.title, type: b.type, username: b.username, password: b.password, url: b.url, notes: b.notes,
  ...(b.data ? { data: b.data } : {}), ...(b.fields ? { fields: b.fields.filter((f) => f.kind !== "totp") } : {}),
  ...(attachments?.length ? { attachments } : {}),
});

const env = (s: string) => {
  if (!s.startsWith("v1.")) throw new CryptoError("bad_envelope");
  return s.slice(3);
};

function fragmentKey(fragment: string): Uint8Array {
  const key = b64url.decode(fragment);
  if (key.length !== 32) throw new CryptoError("bad_key", "link key must be 32 bytes");
  return key;
}

/** Password keys are bound to the link key (HKDF salt), so the password alone, or the URL alone, is not enough. */
async function passwordKeys(password: string, salt: Uint8Array, linkKey: Uint8Array, kdf: KdfParams) {
  if (password === "") throw new Error("link password is empty");
  const pwKey = await deriveMasterKey(password, salt, kdf);
  try {
    const [wrap, access] = await Promise.all([hkdf(pwKey, linkKey, "clane-vault/link-wrap", 32), hkdf(pwKey, linkKey, "clane-vault/link-access", 32)]);
    return { wrapKey: wrap, accessHash: b64url.encode(access) };
  } finally { pwKey.fill(0); }
}

export interface CreatedLink {
  linkKey: Uint8Array;
  /** Ciphertext the server stores: `v1.…` (no password) or `w1.<wrapped data key>.<payload>` (password). */
  encPayload: string;
  /** URL fragment (without `#`): always the b64url link key. */
  fragment: string;
  passwordSalt?: string;
  accessHash?: string;
}

/**
 * Encrypts a record snapshot for a one-time link (spec §5.3). The link key always travels in the URL fragment.
 * With a password, the payload is encrypted under a random data key, wrapped under a key derived from
 * Argon2id(password) and the link key; the server gets an access hash (from the same inputs) to check before
 * it releases the ciphertext.
 */
export async function createLink(linkId: string, body: LinkBody, opts: { password?: string; kdf?: KdfParams } = {}): Promise<CreatedLink> {
  const linkKey = randomBytes(32);
  const fragment = b64url.encode(linkKey);
  const snapshot = utf8.encode(JSON.stringify(clean(body)));
  if (!opts.password) return { linkKey, encPayload: await aeadEncrypt(linkKey, snapshot, `link:${linkId}`), fragment };
  const salt = randomBytes(16);
  const dataKey = randomBytes(32);
  const { wrapKey, accessHash } = await passwordKeys(opts.password, salt, linkKey, opts.kdf ?? DEFAULT_KDF);
  try {
    const payload = await aeadEncrypt(dataKey, snapshot, `link:${linkId}`);
    const wrapped = await aeadEncrypt(wrapKey, dataKey, `link-key:${linkId}`);
    return { linkKey, encPayload: `w1.${env(wrapped)}.${env(payload)}`, fragment, passwordSalt: b64url.encode(salt), accessHash };
  } finally { wrapKey.fill(0); dataKey.fill(0); }
}

/** What the recipient of a password link needs: the access hash for the server and the key to unwrap with. Needs the URL fragment too. */
export async function deriveLinkAccess(password: string, passwordSalt: string, fragment: string, kdf: KdfParams = DEFAULT_KDF) {
  const linkKey = fragmentKey(fragment);
  try { return await passwordKeys(password, b64url.decode(passwordSalt), linkKey, kdf); } finally { linkKey.fill(0); }
}

function parseBody(pt: Uint8Array): LinkBody {
  try { return clean(JSON.parse(utf8.decode(pt)) as LinkBody); } catch { throw new CryptoError("bad_envelope"); }
}

/** Opens a link payload with the key from the URL fragment. */
export async function openLink(linkId: string, encPayload: string, fragment: string): Promise<LinkBody> {
  if (encPayload.startsWith("w1.")) throw new CryptoError("bad_key", "this link needs a password");
  const key = fragmentKey(fragment);
  try { return parseBody(await aeadDecrypt(key, encPayload, `link:${linkId}`)); } finally { key.fill(0); }
}

/** Opens a password link payload with the wrap key from deriveLinkAccess. */
export async function openPasswordLink(linkId: string, encPayload: string, wrapKey: Uint8Array): Promise<LinkBody> {
  const parts = encPayload.split(".");
  if (parts[0] !== "w1" || parts.length !== 3) throw new CryptoError("bad_envelope", "not a password link");
  const dataKey = await aeadDecrypt(wrapKey, `v1.${parts[1]}`, `link-key:${linkId}`);
  try { return parseBody(await aeadDecrypt(dataKey, `v1.${parts[2]}`, `link:${linkId}`)); } finally { dataKey.fill(0); }
}

/** "Who it's for" label, encrypted under the creator's user key. */
export const encryptLinkLabel = (linkId: string, label: string, userKey: Uint8Array) => aeadEncrypt(userKey, utf8.encode(label), `link-label:${linkId}`);
export const decryptLinkLabel = async (linkId: string, labelEnc: string, userKey: Uint8Array) => utf8.decode(await aeadDecrypt(userKey, labelEnc, `link-label:${linkId}`));
