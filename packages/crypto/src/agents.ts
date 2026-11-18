import { b64url, utf8 } from "./encoding.js";
import { envKeys, envValue } from "./envFile.js";
import { coreKeysOf, dataKeysOf, type RecordType } from "./recordTypes.js";
import type { RecordBody } from "./records.js";
import { hkdf } from "./hkdf.js";
import { openSealed, sealTo, shared } from "./seal.js";
import { totpCode } from "./totp.js";
import type { SealKeys } from "./sharing.js";

export const AGENT_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
export type AgentMethod = (typeof AGENT_METHODS)[number];
export type AgentInject = { kind: "bearer" } | { kind: "basic" } | { kind: "header"; name: string; prefix?: string } | { kind: "query"; name: string };
export interface AgentPolicy { v: 1; hosts: string[]; inject: AgentInject; secret?: string; methods?: AgentMethod[]; paths?: string[]; approval?: boolean }

const HOST = /^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+(:\d{1,5})?$/;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "cookie", "proxy-authorization"]);
const QUERY_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const PREFIX = /^[\x20-\x7e]{0,32}$/;
const fail = (m: string): never => { throw new Error(`agent policy: ${m}`); };

function onlyKeys(o: object, allowed: string[], what: string) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) fail(`unknown ${what} key "${k}"`);
}

function cleanHost(h: unknown): string {
  const host = typeof h === "string" ? h.toLowerCase() : "";
  if (!HOST.test(host)) return fail("a host is invalid");
  const [name = "", port] = host.split(":");
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) fail("a host port is invalid");
  if (/^\d+$/.test(name.split(".").pop()!)) fail("IP addresses are not allowed as hosts");
  return host;
}

function cleanInject(i: unknown): AgentInject {
  if (!i || typeof i !== "object" || Array.isArray(i)) return fail("inject is required");
  const o = i as Record<string, unknown>;
  switch (o.kind) {
    case "bearer": case "basic":
      onlyKeys(o, ["kind"], "inject");
      return { kind: o.kind };
    case "header": {
      onlyKeys(o, ["kind", "name", "prefix"], "inject");
      if (typeof o.name !== "string" || !HEADER_NAME.test(o.name) || FORBIDDEN_HEADERS.has(o.name.toLowerCase())) fail("header name is invalid");
      const out: AgentInject = { kind: "header", name: o.name as string };
      if (o.prefix !== undefined) {
        if (typeof o.prefix !== "string" || !PREFIX.test(o.prefix)) fail("header prefix is invalid");
        out.prefix = o.prefix as string;
      }
      return out;
    }
    case "query":
      onlyKeys(o, ["kind", "name"], "inject");
      if (typeof o.name !== "string" || !QUERY_NAME.test(o.name)) fail("query name is invalid");
      return { kind: "query", name: o.name as string };
    default:
      return fail("inject kind is invalid");
  }
}

/** Throws Error with a readable message; returns the cleaned policy (hosts lower-cased). */
export function validateAgentPolicy(p: unknown, body: Pick<RecordBody, "type" | "fields" | "data">): AgentPolicy {
  if (!p || typeof p !== "object" || Array.isArray(p)) return fail("must be an object");
  const o = p as Record<string, unknown>;
  onlyKeys(o, ["v", "hosts", "inject", "secret", "methods", "paths", "approval"], "policy");
  if (o.v !== 1) fail("unknown version");
  if (!Array.isArray(o.hosts) || o.hosts.length < 1 || o.hosts.length > 32) fail("1 to 32 hosts are required");
  const out: AgentPolicy = { v: 1, hosts: (o.hosts as unknown[]).map(cleanHost), inject: cleanInject(o.inject) };
  if (o.secret !== undefined) {
    const s = o.secret;
    if (body.type === "envFile" && s === "data.content") fail("an env file is injected one entry at a time");
    const okRef = typeof s === "string" && (
      (s === "password" && (coreKeysOf(body.type) as string[]).includes("password")) ||
      (s.startsWith("data.") && dataKeysOf(body.type).includes(s.slice(5))) ||
      (s.startsWith("env:") && body.type === "envFile" && envKeys(body.data?.content ?? "").includes(s.slice(4))) ||
      (s.startsWith("field:") && !!body.fields?.some((f) => f.id === s.slice(6))));
    if (!okRef) fail("secret names a field this record doesn't have");
    out.secret = s as string;
  } else if (defaultSecretRef(body.type) === null) fail("choose which field to inject; this record type has no default");
  if (o.methods !== undefined) {
    if (!Array.isArray(o.methods) || o.methods.some((m) => !(AGENT_METHODS as readonly unknown[]).includes(m))) fail("methods are invalid");
    out.methods = o.methods as AgentMethod[];
  }
  if (o.paths !== undefined) {
    if (!Array.isArray(o.paths) || o.paths.length > 32 || o.paths.some((x) => typeof x !== "string" || !x.startsWith("/") || x.length > 256)) fail("paths are invalid");
    out.paths = o.paths as string[];
  }
  if (o.approval !== undefined) {
    if (typeof o.approval !== "boolean") fail("approval must be true or false");
    out.approval = o.approval as boolean;
  }
  return out;
}

/** apiKey → "data.secret"; login, server, database → "password"; any other type → null. */
export function defaultSecretRef(type: RecordType): string | null {
  return type === "apiKey" ? "data.secret" : type === "login" || type === "server" || type === "database" ? "password" : null;
}

/** The value the policy injects, or null when the field is empty or no ref applies. */
export function agentSecretOf(body: RecordBody): string | null {
  const ref = body.agentPolicy?.secret ?? defaultSecretRef(body.type);
  if (!ref) return null;
  const v = ref === "password" ? body.password : ref.startsWith("env:") ? envValue(body.data?.content ?? "", ref.slice(4)) : ref.startsWith("data.") ? body.data?.[ref.slice(5)] : body.fields?.find((f) => f.id === ref.slice(6))?.value;
  return v ? v : null;
}

/** Basic auth username: body.username ?? body.data?.keyId ?? "". */
export const basicUsername = (body: RecordBody): string => body.username ?? body.data?.keyId ?? "";

export const agentKeyMessage = (orgId: string, agentId: string, publicKeyB64: string) => `agent-key:${orgId}:${agentId}:${publicKeyB64}`;
export const agentPrivateKeyAad = (orgId: string, agentId: string, publicKeyB64: string) => `agent-private-key:${orgId}:${agentId}:${publicKeyB64}`;

/** Ed25519: raw public key, pkcs8 private key. */
export async function generateIdentityKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  return {
    publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
    privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
  };
}

/** First 16 chars of base64url(SHA-256(raw public key)). */
export async function gatewayKeyId(publicKeyRaw: Uint8Array): Promise<string> {
  return b64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyRaw as BufferSource))).slice(0, 16);
}

type Ids = { orgId: string; agentId: string; publicKey: string };

export interface PersonalIds { ownerUserId: string; ownerPublicKey: string; agentId: string; publicKey: string }
export const personalAgentKeyMessage = (i: PersonalIds) => `personal-agent-key:${i.ownerUserId}:${i.ownerPublicKey}:${i.agentId}:${i.publicKey}`;
export const personalAgentPrivateKeyAad = (i: PersonalIds) => `agent-private-key:personal:${i.ownerUserId}:${i.ownerPublicKey}:${i.agentId}:${i.publicKey}`;
export const personalAgentRecordAad = (ownerUserId: string, agentId: string, recordId: string) => `personal-agent-record:${ownerUserId}:${agentId}:${recordId}`;

export type GatewaySigTag = "g1" | "d1" | "u1" | "q1";

/** "<tag>.<keyId>.<sig>": Ed25519 over the UTF-8 of `message`. */
export async function signGatewayMessage(identityPrivatePkcs8: Uint8Array, keyId: string, tag: GatewaySigTag, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", identityPrivatePkcs8 as BufferSource, "Ed25519", false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key, utf8.encode(message) as BufferSource));
  return `${tag}.${keyId}.${b64url.encode(sig)}`;
}

/** False on a wrong tag, key id, signature or any malformed input; never throws. */
export async function verifyGatewayMessage(sig: string, tag: GatewaySigTag, message: string, identity: { keyId: string; publicKey: string }): Promise<boolean> {
  try {
    const [t, keyId, s, ...rest] = sig.split(".");
    if (t !== tag || rest.length || !s || keyId !== identity.keyId) return false;
    const key = await crypto.subtle.importKey("raw", b64url.decode(identity.publicKey) as BufferSource, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64url.decode(s) as BufferSource, utf8.encode(message) as BufferSource);
  } catch {
    return false;
  }
}

export const signAgentKey = (pkcs8: Uint8Array, keyId: string, ids: Ids) => signGatewayMessage(pkcs8, keyId, "g1", agentKeyMessage(ids.orgId, ids.agentId, ids.publicKey));
export const verifyAgentAttestation = (att: string, ids: Ids, identity: { keyId: string; publicKey: string }) =>
  verifyGatewayMessage(att, "g1", agentKeyMessage(ids.orgId, ids.agentId, ids.publicKey), identity);
export const signPersonalAgentKey = (pkcs8: Uint8Array, keyId: string, i: PersonalIds) => signGatewayMessage(pkcs8, keyId, "g1", personalAgentKeyMessage(i));
export const verifyPersonalAgentAttestation = (att: string, i: PersonalIds, identity: { keyId: string; publicKey: string }) =>
  verifyGatewayMessage(att, "g1", personalAgentKeyMessage(i), identity);

type RecordIds = { ownerUserId: string; agentId: string; recordId: string };
export const sealPersonalAgentRecordKey = (recordKey: Uint8Array, ids: RecordIds, agentPublicKey: Uint8Array) =>
  sealTo(agentPublicKey, recordKey, personalAgentRecordAad(ids.ownerUserId, ids.agentId, ids.recordId));
export const openPersonalAgentRecordKey = (sealed: string, ids: RecordIds, keys: SealKeys) =>
  openSealed(keys.privateKey, keys.publicKey, sealed, personalAgentRecordAad(ids.ownerUserId, ids.agentId, ids.recordId));

/** base64url(SHA-256(UTF-8 of text)): what deposit and update signatures name instead of the body. */
export async function sha256B64(text: string): Promise<string> {
  return b64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(text) as BufferSource)));
}
export const agentDepositOwnerAad = (ownerUserId: string, id: string) => `agent-deposit-owner:${ownerUserId}:${id}`;
export const agentDepositMessage = (m: { ownerUserId: string; ownerPublicKey: string; agentId: string; id: string; revision: number; encBodyHash: string }) =>
  `agent-deposit:${m.ownerUserId}:${m.ownerPublicKey}:${m.agentId}:${m.id}:${m.revision}:${m.encBodyHash}`;
export const agentUpdateMessage = (m: { ownerUserId: string; agentId: string; id: string; revision: number; encBodyHash: string }) =>
  `agent-update:${m.ownerUserId}:${m.agentId}:${m.id}:${m.revision}:${m.encBodyHash}`;
export const sealDepositKeyToOwner = (recordKey: Uint8Array, ids: { ownerUserId: string; id: string }, ownerPublicKey: Uint8Array) =>
  sealTo(ownerPublicKey, recordKey, agentDepositOwnerAad(ids.ownerUserId, ids.id));
export const openDepositKey = (sealed: string, ids: { ownerUserId: string; id: string }, keys: SealKeys) =>
  openSealed(keys.privateKey, keys.publicKey, sealed, agentDepositOwnerAad(ids.ownerUserId, ids.id));

/** A field reference an agent may be shown. Never "totpSecret": "totp" is the current code. */
export const REVEAL_REF = /^(username|password|url|notes|totp|data\.[A-Za-z0-9_]{1,40}|field:[A-Za-z0-9_-]{1,64}|env:[A-Za-z0-9_.-]{1,128})$/;
const revealFail = (m: string): never => { throw new Error(`reveal fields: ${m}`); };

/** 1–20 unique refs that this body has; returns them sorted. A seed (totpSecret, a totp-kind field) and a whole env file are never revealable. */
export function validateRevealFields(fields: unknown, body: Pick<RecordBody, "type" | "fields" | "totpSecret" | "data">): string[] {
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > 20) return revealFail("1 to 20 fields are required");
  if (new Set(fields).size !== fields.length) revealFail("fields must be unique");
  for (const f of fields as unknown[]) {
    if (typeof f !== "string" || !REVEAL_REF.test(f)) return revealFail("a field is invalid");
    const ok =
      f === "notes" ||
      ((f === "username" || f === "password" || f === "url") && (coreKeysOf(body.type) as string[]).includes(f)) ||
      (f === "totp" && !!body.totpSecret) ||
      (f.startsWith("data.") && dataKeysOf(body.type).includes(f.slice(5)) && !(body.type === "envFile" && f === "data.content")) ||
      (f.startsWith("field:") && !!body.fields?.some((x) => x.id === f.slice(6) && x.kind !== "totp")) ||
      (f.startsWith("env:") && body.type === "envFile" && envKeys(body.data?.content ?? "").includes(f.slice(4)));
    if (!ok) revealFail(`"${f}" isn't a revealable field of this record`);
  }
  return [...(fields as string[])].sort();
}

/** Only the named fields that have a value. "totp" → the current code; the seed is never returned under any ref. */
export async function revealFieldsOf(body: RecordBody, fields: string[], atMs = Date.now()): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const f of fields) {
    let v: string | null | undefined;
    if (f === "username" || f === "password" || f === "url" || f === "notes") v = body[f];
    else if (f === "totp") v = body.totpSecret ? await totpCode(body.totpSecret, atMs) : undefined;
    else if (f.startsWith("data.")) v = body.type === "envFile" && f === "data.content" ? undefined : body.data?.[f.slice(5)];
    else if (f.startsWith("field:")) { const c = body.fields?.find((x) => x.id === f.slice(6)); v = c && c.kind !== "totp" ? c.value : undefined; }
    else if (f.startsWith("env:") && body.type === "envFile") v = envValue(body.data?.content ?? "", f.slice(4));
    if (v) out[f] = v;
  }
  return out;
}

export interface RevealStub { title: string; type: RecordType; fields: string[] }
export const personalAgentStubAad = (ownerUserId: string, agentId: string, recordId: string) => `personal-agent-stub:${ownerUserId}:${agentId}:${recordId}`;
export const sealRevealStub = (stub: RevealStub, ids: RecordIds, agentPublicKey: Uint8Array) =>
  sealTo(agentPublicKey, utf8.encode(JSON.stringify({ title: stub.title, type: stub.type, fields: stub.fields })), personalAgentStubAad(ids.ownerUserId, ids.agentId, ids.recordId));
export async function openRevealStub(sealed: string, ids: RecordIds, keys: SealKeys): Promise<RevealStub> {
  const o = JSON.parse(utf8.decode(await openSealed(keys.privateKey, keys.publicKey, sealed, personalAgentStubAad(ids.ownerUserId, ids.agentId, ids.recordId))));
  if (typeof o?.title !== "string" || typeof o.type !== "string" || !Array.isArray(o.fields) || o.fields.some((f: unknown) => typeof f !== "string" || !REVEAL_REF.test(f))) throw new Error("reveal stub is invalid");
  return { title: o.title, type: o.type, fields: o.fields };
}

export const agentRevealRequestMessage = (m: { requestId: string; ownerUserId: string; agentId: string; recordId: string; fields: string[]; requestPublicKey: string; expiresAt: string }) =>
  `agent-reveal-request:${m.requestId}:${m.ownerUserId}:${m.agentId}:${m.recordId}:${[...m.fields].sort().join(",")}:${m.requestPublicKey}:${m.expiresAt}`;
export const agentRevealAad = (requestId: string, recordId: string, agentId: string) => `agent-reveal:${requestId}:${recordId}:${agentId}`;
type RevealIds = { requestId: string; recordId: string; agentId: string };
/** HKDF of X25519(owner, one-time request key): only the owner (or the request key's holder) can compute it, so it proves who sealed. */
const revealOwnerTag = async (privateKey: Uint8Array, publicKey: Uint8Array) =>
  b64url.encode(await hkdf(await shared(privateKey, publicKey), new Uint8Array(0), "clane-vault/agent-reveal-owner", 32));
/** Allow once: sealed to the one-time key, with the owner tag in the AAD so the API cannot forge an approval. */
export const sealReveal = async (fields: Record<string, string>, ids: RevealIds, requestPublicKey: Uint8Array, ownerPrivateKey: Uint8Array) =>
  sealTo(requestPublicKey, utf8.encode(JSON.stringify(fields)), `${agentRevealAad(ids.requestId, ids.recordId, ids.agentId)}:${await revealOwnerTag(ownerPrivateKey, requestPublicKey)}`);
/** Throws unless the owner whose key is `ownerPublicKey` sealed it; returns only the `requested` fields. */
export async function openReveal(sealed: string, ids: RevealIds, keys: SealKeys, ownerPublicKey: Uint8Array, requested: string[]): Promise<Record<string, string>> {
  const aad = `${agentRevealAad(ids.requestId, ids.recordId, ids.agentId)}:${await revealOwnerTag(keys.privateKey, ownerPublicKey)}`;
  const o = JSON.parse(utf8.decode(await openSealed(keys.privateKey, keys.publicKey, sealed, aad)));
  if (!o || typeof o !== "object" || Array.isArray(o) || Object.values(o).some((v) => typeof v !== "string")) throw new Error("reveal is invalid");
  return Object.fromEntries(Object.entries(o as Record<string, string>).filter(([k]) => requested.includes(k)));
}

/** Standing reveal (spec §5.6), inside the encrypted body: which agents may read which fields without asking. */
export interface AgentReveal { v: 1; agents: string[]; fields: string[] }
const AGENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Unknown keys refused; `agents` 1–20 unique lower-case UUIDs; `fields` through validateRevealFields (returned sorted). */
export function validateAgentReveal(p: unknown, body: Pick<RecordBody, "type" | "fields" | "totpSecret" | "data">): AgentReveal {
  const bad = (m: string): never => { throw new Error(`agent reveal: ${m}`); };
  if (!p || typeof p !== "object" || Array.isArray(p)) return bad("must be an object");
  const o = p as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!["v", "agents", "fields"].includes(k)) bad(`unknown key "${k}"`);
  if (o.v !== 1) bad("unknown version");
  const agents = o.agents;
  if (!Array.isArray(agents) || agents.length < 1 || agents.length > 20 || agents.some((a) => typeof a !== "string" || !AGENT_ID.test(a)) || new Set(agents).size !== agents.length)
    bad("1 to 20 different agents are required");
  return { v: 1, agents: [...(agents as string[])], fields: validateRevealFields(o.fields, body) };
}
