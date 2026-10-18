import { aeadDecrypt, aeadEncrypt, agentPrivateKeyAad, randomBytes } from "@clane-vault/crypto";
import type { Kek, KekContext } from "./kek.js";

export class EnvelopeError extends Error {
  constructor(public code: "kek_mismatch" | "bad_envelope") {
    super(code);
    this.name = "EnvelopeError";
  }
}

/** "k1.<kek.id>.<wrappedDek>.<v1…>" */
export async function sealWithKek(kek: Kek, ctx: KekContext, aad: string, plaintext: Uint8Array): Promise<string> {
  const dek = randomBytes(32);
  try {
    return `k1.${kek.id}.${await kek.wrap(dek, ctx)}.${await aeadEncrypt(dek, plaintext, aad)}`;
  } finally {
    dek.fill(0);
  }
}

export async function openWithKek(kek: Kek, ctx: KekContext, aad: string, envelope: string): Promise<Uint8Array> {
  const p = envelope.split(".");
  if (p.length !== 5 || p[0] !== "k1" || p[3] !== "v1" || !p[2] || !p[4]) throw new EnvelopeError("bad_envelope");
  if (p[1] !== kek.id) throw new EnvelopeError("kek_mismatch");
  const dek = await kek.unwrap(p[2], ctx);
  try {
    return await aeadDecrypt(dek, `v1.${p[4]}`, aad);
  } finally {
    dek.fill(0);
  }
}

type Ids = { orgId: string; agentId: string; publicKey: string };

export const wrapAgentKey = (kek: Kek, ids: Ids, privateKey: Uint8Array): Promise<string> =>
  sealWithKek(kek, { orgId: ids.orgId, agentId: ids.agentId }, agentPrivateKeyAad(ids.orgId, ids.agentId, ids.publicKey), privateKey);

export const unwrapAgentKey = (kek: Kek, ids: Ids, envelope: string): Promise<Uint8Array> =>
  openWithKek(kek, { orgId: ids.orgId, agentId: ids.agentId }, agentPrivateKeyAad(ids.orgId, ids.agentId, ids.publicKey), envelope);
