import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { validateAgentPolicy, type AgentPolicy } from "./agents.js";
import { randomBytes, utf8, CryptoError } from "./encoding.js";
import { CORE_KEYS, FIELD_KINDS, coreKeysOf, dataKeysOf, isRecordType, type CoreKey, type FieldKind, type RecordType } from "./recordTypes.js";

export type { RecordType } from "./recordTypes.js";

/** A field the user added to a record (any type): `id` is stable across edits (reordering, renaming). */
export interface CustomField { id: string; label: string; kind: FieldKind; value: string }

/**
 * The decrypted record (docs/record-types.md).
 *
 * v1 (no `v`): `type` "login" | "note" with username, password, url, totpSecret, notes. Read unchanged.
 * v2 (`v: 2`, written by every encrypt): any RecordType; the type's core fields (username, password, url, totpSecret)
 * at the top as before, its other template fields in `data` (keyed by the template's keys), and the user's `fields`.
 * `passwordChangedAt`: ISO time the password last changed (set by the editor; password health falls back to updatedAt).
 */
export interface RecordBody {
  v?: 2; type: RecordType; title: string;
  username?: string; password?: string; url?: string; totpSecret?: string; notes?: string; passwordChangedAt?: string;
  data?: Record<string, string>; fields?: CustomField[];
  /** How agents may use this record (docs/agents.md); absent = agents get no_policy. */
  agentPolicy?: AgentPolicy;
}

/** Limits on a body (docs/record-types.md). The whole body must fit the server's 64 KiB ciphertext envelope. */
export const MAX_CUSTOM_FIELDS = 64;
export const MAX_FIELD_LABEL = 100;
export const MAX_FIELD_VALUE = 64 * 1024;
/** Plaintext JSON bytes: base64 of nonce + ciphertext + tag must stay under the API's 65 536-character envelope. */
export const MAX_BODY_BYTES = 49_000;

const V1_FIELDS = ["username", "password", "url", "totpSecret", "notes"] as const;
const FIELD_ID = /^[A-Za-z0-9_-]{1,64}$/;

function str(v: unknown, what: string): string {
  if (typeof v !== "string") throw new Error(`${what} must be text`);
  if (v.length > MAX_FIELD_VALUE) throw new Error(`${what} is too long`);
  return v;
}

/** Template data for a type: known keys only, text values, blanks dropped. */
export function cleanData(type: RecordType, data: unknown): Record<string, string> | undefined {
  if (data === undefined || data === null) return undefined;
  if (typeof data !== "object" || Array.isArray(data)) throw new Error("record data must be an object");
  const keys = new Set(dataKeysOf(type));
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
    if (!keys.has(k)) throw new Error(`"${k}" isn't a field of this record type`);
    const s = str(v, k);
    if (s !== "") out[k] = s;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Custom fields: at most 64, labelled, allowed kinds only; blank values dropped. `dropTotp` leaves out TOTP fields (one-time links). */
export function cleanFields(fields: unknown, o: { dropTotp?: boolean } = {}): CustomField[] | undefined {
  if (fields === undefined || fields === null) return undefined;
  if (!Array.isArray(fields)) throw new Error("custom fields must be a list");
  if (fields.length > MAX_CUSTOM_FIELDS) throw new Error(`a record holds at most ${MAX_CUSTOM_FIELDS} custom fields`);
  const ids = new Set<string>();
  const out: CustomField[] = [];
  for (const f of fields as Partial<CustomField>[]) {
    if (!f || typeof f !== "object") throw new Error("custom field must be an object");
    if (typeof f.id !== "string" || !FIELD_ID.test(f.id) || ids.has(f.id)) throw new Error("custom field id is invalid");
    ids.add(f.id);
    if (!(FIELD_KINDS as readonly string[]).includes(f.kind as string)) throw new Error("custom field kind is invalid");
    const label = typeof f.label === "string" ? f.label.trim() : "";
    if (!label) throw new Error("custom field label is required");
    if (label.length > MAX_FIELD_LABEL) throw new Error("custom field label is too long");
    const value = str(f.value, "custom field value");
    if (value === "" || (o.dropTotp && f.kind === "totp")) continue;
    out.push({ id: f.id, label, kind: f.kind as FieldKind, value });
  }
  return out.length ? out : undefined;
}

function validateV1(body: RecordBody): RecordBody {
  if (body.type !== "login" && body.type !== "note") throw new Error("record type must be login or note");
  if (typeof body.title !== "string" || body.title.trim() === "") throw new Error("record title is required");
  const clean: RecordBody = { type: body.type, title: body.title.trim() };
  for (const f of V1_FIELDS) {
    const v = body[f];
    if (v !== undefined && v !== "") clean[f] = String(v);
  }
  if (clean.password && typeof body.passwordChangedAt === "string" && !Number.isNaN(Date.parse(body.passwordChangedAt))) clean.passwordChangedAt = body.passwordChangedAt;
  return clean;
}

/** `lenient` (reads only): an invalid stored agentPolicy is dropped, so people can still open the record and agents fail closed. */
function validateV2(body: RecordBody, lenient = false): RecordBody {
  if (!isRecordType(body.type)) throw new Error("record type is invalid");
  if (typeof body.title !== "string" || body.title.trim() === "") throw new Error("record title is required");
  if (body.title.length > 1024) throw new Error("record title is too long");
  const clean: RecordBody = { v: 2, type: body.type, title: body.title.trim() };
  const core = new Set<CoreKey>(coreKeysOf(body.type));
  for (const k of CORE_KEYS) {
    const v = body[k];
    if (v === undefined || v === "") continue;
    if (!core.has(k)) throw new Error(`"${k}" isn't a field of this record type`);
    clean[k] = str(v, k);
  }
  if (body.notes !== undefined && body.notes !== "") clean.notes = str(body.notes, "notes");
  // Kept only next to a password, and only when it is a real date.
  if (clean.password && typeof body.passwordChangedAt === "string" && !Number.isNaN(Date.parse(body.passwordChangedAt))) clean.passwordChangedAt = body.passwordChangedAt;
  const data = cleanData(body.type, body.data);
  if (data) clean.data = data;
  const fields = cleanFields(body.fields);
  if (fields) clean.fields = fields;
  if (body.agentPolicy !== undefined) {
    try { clean.agentPolicy = validateAgentPolicy(body.agentPolicy, clean); } catch (e) { if (!lenient) throw e; }
  }
  if (utf8.encode(JSON.stringify(clean)).length > MAX_BODY_BYTES) throw new Error("record is too large");
  return clean;
}

/** v1 bodies (no `v`) are read as they always were; anything else must be a valid v2 body. */
function validate(body: RecordBody, lenient = false): RecordBody {
  if (!body || typeof body !== "object") throw new Error("record body must be an object");
  if (body.v === undefined) return validateV1(body);
  if (body.v !== 2) throw new Error("unknown record version");
  return validateV2(body, lenient);
}

/** What an encrypt writes: always v2 (a v1-shaped login or note is a valid v2 body). */
export const normalizeRecordBody = (body: RecordBody): RecordBody => validate({ ...body, v: 2 });

export const wrapKey = (key: Uint8Array, wrappingKey: Uint8Array, aad: string) => aeadEncrypt(wrappingKey, key, aad);
export const unwrapKey = (wrapped: string, wrappingKey: Uint8Array, aad: string) => aeadDecrypt(wrappingKey, wrapped, aad);

export async function encryptRecordBody(recordId: string, body: RecordBody, recordKey: Uint8Array): Promise<string> {
  return aeadEncrypt(recordKey, utf8.encode(JSON.stringify(normalizeRecordBody(body))), `record-body:${recordId}`);
}

export async function encryptNewRecord(recordId: string, body: RecordBody, holderKey: Uint8Array) {
  const recordKey = randomBytes(32);
  const encBody = await encryptRecordBody(recordId, body, recordKey);
  const wrappedRecordKey = await wrapKey(recordKey, holderKey, `record-key:${recordId}`);
  return { encBody, wrappedRecordKey, recordKey };
}

export async function decryptRecordBody(recordId: string, encBody: string, recordKey: Uint8Array): Promise<RecordBody> {
  const plaintext = await aeadDecrypt(recordKey, encBody, `record-body:${recordId}`);
  try {
    return validate(JSON.parse(utf8.decode(plaintext)), true);
  } catch {
    throw new CryptoError("bad_envelope");
  }
}

export async function decryptRecord(recordId: string, encBody: string, wrappedRecordKey: string, holderKey: Uint8Array) {
  const recordKey = await unwrapKey(wrappedRecordKey, holderKey, `record-key:${recordId}`);
  return { body: await decryptRecordBody(recordId, encBody, recordKey), recordKey };
}

export const encryptFolderName = (folderId: string, name: string, key: Uint8Array) => {
  if (name.trim() === "") return Promise.reject(new Error("folder name is required"));
  return aeadEncrypt(key, utf8.encode(name.trim()), `folder-name:${folderId}`);
};
export const decryptFolderName = async (folderId: string, encName: string, key: Uint8Array) =>
  utf8.decode(await aeadDecrypt(key, encName, `folder-name:${folderId}`));
