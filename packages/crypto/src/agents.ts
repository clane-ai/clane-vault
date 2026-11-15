import { b64url, utf8 } from "./encoding.js";
import { coreKeysOf, dataKeysOf, type RecordType } from "./recordTypes.js";
import type { RecordBody } from "./records.js";
import { openSealed, sealTo } from "./seal.js";
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
export function validateAgentPolicy(p: unknown, body: Pick<RecordBody, "type" | "fields">): AgentPolicy {
  if (!p || typeof p !== "object" || Array.isArray(p)) return fail("must be an object");
  const o = p as Record<string, unknown>;
  onlyKeys(o, ["v", "hosts", "inject", "secret", "methods", "paths", "approval"], "policy");
  if (o.v !== 1) fail("unknown version");
  if (!Array.isArray(o.hosts) || o.hosts.length < 1 || o.hosts.length > 32) fail("1 to 32 hosts are required");
  const out: AgentPolicy = { v: 1, hosts: (o.hosts as unknown[]).map(cleanHost), inject: cleanInject(o.inject) };
  if (o.secret !== undefined) {
    const s = o.secret;
    const okRef = typeof s === "string" && (
      (s === "password" && (coreKeysOf(body.type) as string[]).includes("password")) ||
      (s.startsWith("data.") && dataKeysOf(body.type).includes(s.slice(5))) ||
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
  const v = ref === "password" ? body.password : ref.startsWith("data.") ? body.data?.[ref.slice(5)] : body.fields?.find((f) => f.id === ref.slice(6))?.value;
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
