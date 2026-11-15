import { aeadDecrypt, aeadEncrypt, agentPrivateKeyAad, personalAgentPrivateKeyAad, randomBytes, type PersonalIds } from "@clane-vault/crypto";
import type { Kek, KekContext } from "./kek.js";

export class EnvelopeError extends Error {
  constructor(public code: "kek_mismatch" | "bad_envelope") {
    super(code);
    this.name = "EnvelopeError";
  }
}

type Tag = "k1" | "k2";

/** "<tag>.<kek.id>.<wrappedDek>.<v1…>": k1 for organisation agents and the identity, k2 for personal agents. */
export async function sealWithKek(kek: Kek, ctx: KekContext, aad: string, plaintext: Uint8Array, tag: Tag = "k1"): Promise<string> {
  const dek = randomBytes(32);
  try {
    return `${tag}.${kek.id}.${await kek.wrap(dek, ctx)}.${await aeadEncrypt(dek, plaintext, aad)}`;
  } finally {
    dek.fill(0);
  }
}

/** Another tag than `tag` is bad_envelope. */
export async function openWithKek(kek: Kek, ctx: KekContext, aad: string, envelope: string, tag: Tag = "k1"): Promise<Uint8Array> {
  const p = envelope.split(".");
  if (p.length !== 5 || p[0] !== tag || p[3] !== "v1" || !p[2] || !p[4]) throw new EnvelopeError("bad_envelope");
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

const personalCtx = (ids: PersonalIds) => ({ agentId: ids.agentId, ownerUserId: ids.ownerUserId });

/** k2: the AAD binds the owner's public key, so the key opens only while the API reports that same owner key. */
export const wrapPersonalAgentKey = (kek: Kek, ids: PersonalIds, privateKey: Uint8Array): Promise<string> =>
  sealWithKek(kek, personalCtx(ids), personalAgentPrivateKeyAad(ids), privateKey, "k2");

export const unwrapPersonalAgentKey = (kek: Kek, ids: PersonalIds, envelope: string): Promise<Uint8Array> =>
  openWithKek(kek, personalCtx(ids), personalAgentPrivateKeyAad(ids), envelope, "k2");
