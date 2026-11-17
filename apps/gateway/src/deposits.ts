import { randomUUID } from "node:crypto";
import {
  aeadDecrypt, agentDepositMessage, agentUpdateMessage, b64url, CryptoError, encryptRecordBody, MAX_FIELD_VALUE, normalizeRecordBody, openPersonalAgentRecordKey, randomBytes,
  sealDepositKeyToOwner, sealPersonalAgentRecordKey, serverRecordType, sha256B64, utf8,
  type AgentInject, type FieldKind, type MembershipKeys, type RecordBody, type RecordType,
} from "@clane-vault/crypto";
import type { PersonalAgentSync } from "./apiClient.js";
import type { Identity } from "./identity.js";
import type { HeldSecrets } from "./log.js";

export interface SaveInput {
  title: string; type: RecordType;
  fields?: { username?: string; password?: string; url?: string; notes?: string; data?: Record<string, string> };
  custom_fields?: { label: string; kind: FieldKind; value: string }[];
  agent_use?: { hosts: string[]; inject: AgentInject; secret?: string };
}
export type BuiltDeposit = { id: string; type: "login" | "item"; encBody: string; ownerSealedKey: string; agentSealedKey: string; signature: string };

/** The vault's rules refuse the body: the tool answers `invalid`. Carries no value. */
export class InvalidInput extends Error { override name = "InvalidInput"; constructor() { super("invalid"); } }

/** Holds every value of password, data.* and custom fields; the returned function releases them all. */
function holdValues(held: HeldSecrets, b: Pick<RecordBody, "password" | "data" | "fields">): () => void {
  const vs = [b.password, ...Object.values(b.data ?? {}), ...(b.fields ?? []).map((f) => f.value)].filter((v): v is string => !!v);
  const releases = vs.map((v) => held.hold(v));
  return () => { for (const r of releases) r(); };
}

const normalized = (body: RecordBody): RecordBody => { try { return normalizeRecordBody(body); } catch { throw new InvalidInput(); } };

/**
 * The stored body, read strictly: decryptRecordBody's lenient read drops an invalid agentPolicy and any field this gateway
 * doesn't know (one a newer web app wrote), and writing that copy back would delete them. Anything the strict read would
 * change or drop is InvalidInput, before any write. A v1 body (no `v`) only gains `v: 2`.
 */
async function readForUpdate(id: string, encBody: string, recordKey: Uint8Array): Promise<RecordBody> {
  let raw: Record<string, unknown>, plaintext: Uint8Array | undefined;
  try {
    plaintext = await aeadDecrypt(recordKey, encBody, `record-body:${id}`);
    raw = JSON.parse(utf8.decode(plaintext)) as Record<string, unknown>;
  } catch (e) {
    throw e instanceof CryptoError ? e : new CryptoError("bad_envelope");
  } finally {
    plaintext?.fill(0);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new CryptoError("bad_envelope");
  const clean = normalized(raw as unknown as RecordBody) as unknown as Record<string, unknown>;
  // Blank values are dropped by every editor too; anything else missing or changed is a loss.
  const lost = Object.keys(raw).some((k) => k !== "v" && raw[k] !== "" && raw[k] !== undefined && JSON.stringify(raw[k]) !== JSON.stringify(clean[k]));
  if (lost) throw new InvalidInput();
  return clean as unknown as RecordBody;
}

/**
 * normalizeRecordBody (a throw → InvalidInput), a random id and record key, both seals, the d1 signature at revision 1.
 * `keys` come from AgentKeyCache.open on this same sync, which proved `sync.owner` is the owner bound into the agent's k2 key:
 * only then may the record key be sealed to `sync.owner.publicKey`. Zeroes the key; the values are held until it returns.
 */
export async function buildDeposit(sync: PersonalAgentSync, keys: MembershipKeys, identity: Identity, input: SaveInput, held: HeldSecrets): Promise<BuiltDeposit> {
  const f = input.fields ?? {};
  const body: RecordBody = {
    v: 2, type: input.type, title: input.title, username: f.username, password: f.password, url: f.url, notes: f.notes, data: f.data,
    fields: input.custom_fields?.map((c) => ({ id: randomUUID(), ...c })),
    ...(input.agent_use ? { agentPolicy: { v: 1 as const, hosts: input.agent_use.hosts, inject: input.agent_use.inject,
      ...(input.agent_use.secret !== undefined ? { secret: input.agent_use.secret } : {}) } } : {}),
  };
  const release = holdValues(held, body);
  const recordKey = randomBytes(32);
  try {
    const clean = normalized(body);
    const id = randomUUID(), ownerUserId = sync.owner.userId, agentId = sync.agentId;
    const encBody = await encryptRecordBody(id, clean, recordKey);
    const ownerSealedKey = await sealDepositKeyToOwner(recordKey, { ownerUserId, id }, b64url.decode(sync.owner.publicKey));
    const agentSealedKey = await sealPersonalAgentRecordKey(recordKey, { ownerUserId, agentId, recordId: id }, keys.publicKey);
    const signature = await identity.signMessage("d1", agentDepositMessage({ ownerUserId, ownerPublicKey: sync.owner.publicKey, agentId, id, revision: 1,
      encBodyHash: await sha256B64(encBody) }));
    return { id, type: serverRecordType(clean), encBody, ownerSealedKey, agentSealedKey, signature };
  } finally {
    recordKey.fill(0);
    release();
  }
}

/**
 * Decrypts, applies `set` to username/password/url/notes/data only (data keys merge), leaves everything else (agentPolicy among it)
 * as decrypted, re-encrypts under the same key, signs for `revision + 1` (d1 for a deposit, u1 for a record).
 * Returns `revision` as given: what the API is sent, the revision the write replaces. Old and new values are held until it returns.
 */
export async function buildUpdate(sync: PersonalAgentSync, keys: MembershipKeys, identity: Identity, target: { kind: "deposit" | "record"; id: string; revision: number },
  set: NonNullable<SaveInput["fields"]>, held: HeldSecrets): Promise<{ encBody: string; revision: number; signature: string }> {
  const { id } = target, ownerUserId = sync.owner.userId, agentId = sync.agentId;
  const d = sync.deposits.find((x) => x.id === id), r = sync.records.find((x) => x.id === id);
  const row = target.kind === "deposit" ? d && { encBody: d.encBody, sealed: d.agentSealedKey } : r && { encBody: r.encBody, sealed: r.wrappedRecordKey };
  if (!row) throw new Error("no such item in the sync");
  const releaseNew = holdValues(held, set);
  let releaseOld = () => {};
  const recordKey = await openPersonalAgentRecordKey(row.sealed, { ownerUserId, agentId, recordId: id }, keys);
  try {
    const before = await readForUpdate(id, row.encBody, recordKey);
    releaseOld = holdValues(held, before);
    const { data, ...top } = set;
    const after = normalized({ ...before, ...top, ...(data ? { data: { ...before.data, ...data } } : {}) });
    const encBody = await encryptRecordBody(id, after, recordKey);
    const m = { ownerUserId, agentId, id, revision: target.revision + 1, encBodyHash: await sha256B64(encBody) };
    const signature = target.kind === "deposit"
      ? await identity.signMessage("d1", agentDepositMessage({ ...m, ownerPublicKey: sync.owner.publicKey }))
      : await identity.signMessage("u1", agentUpdateMessage(m));
    return { encBody, revision: target.revision, signature };
  } finally {
    recordKey.fill(0);
    releaseOld();
    releaseNew();
  }
}

/** RFC 6901 (`~1` is "/", `~0` is "~"): the value at `pointer` if the JSON parses and it is a non-empty string of at most MAX_FIELD_VALUE, else null. */
export function pointerValue(json: string, pointer: string): string | null {
  let v: unknown;
  try { v = JSON.parse(json); } catch { return null; }
  if (pointer !== "" && !pointer.startsWith("/")) return null;
  for (const t of pointer.split("/").slice(1).map((x) => x.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    if (Array.isArray(v)) { if (!/^(0|[1-9]\d*)$/.test(t)) return null; v = v[Number(t)]; }
    else if (v !== null && typeof v === "object" && Object.hasOwn(v, t)) v = (v as Record<string, unknown>)[t];
    else return null;
  }
  return typeof v === "string" && v.length > 0 && v.length <= MAX_FIELD_VALUE ? v : null;
}
