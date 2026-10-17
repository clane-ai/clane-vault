import { randomUUID } from "node:crypto";
import { link, readFile, unlink, writeFile } from "node:fs/promises";
import { b64url, CryptoError, gatewayKeyId, generateIdentityKeyPair, signAgentKey } from "@clane-vault/crypto";
import { EnvelopeError, openWithKek, sealWithKek } from "./envelope.js";
import type { Kek } from "./kek.js";

export interface Identity { keyId: string; publicKey: string; sign(ids: { orgId: string; agentId: string; publicKey: string }): Promise<string> }

const CTX = { purpose: "gateway-identity" };
const aad = (publicKey: string) => `gateway-identity-key:${publicKey}`;

/** A torn, empty or foreign file is refused, never overwritten: replacing it would change the gateway's identity. */
async function readIdentityFile(file: string): Promise<{ publicKey: string; sealed: string }> {
  let j: unknown;
  try { j = JSON.parse(await readFile(file, "utf8")); } catch { throw new EnvelopeError("bad_envelope"); }
  const o = j as { v?: unknown; publicKey?: unknown; sealed?: unknown };
  if (o?.v !== 1 || typeof o.publicKey !== "string" || typeof o.sealed !== "string") throw new EnvelopeError("bad_envelope");
  return { publicKey: o.publicKey, sealed: o.sealed };
}

/** Writes a complete temp file, then links it into place, so the file never exists half-written. False when another replica won. */
async function createAtomically(file: string, content: string): Promise<boolean> {
  const tmp = `${file}.${randomUUID()}.tmp`;
  await writeFile(tmp, content, { flag: "wx", mode: 0o600 });
  try {
    await link(tmp, file);
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw e;
  } finally {
    await unlink(tmp).catch(() => {});
  }
}

export async function loadOrCreateIdentity(file: string, kek: Kek): Promise<Identity> {
  let publicKey: string, pkcs8: Uint8Array;
  const kp = await generateIdentityKeyPair();
  const fresh = b64url.encode(kp.publicKey);
  let created = false;
  try {
    created = await createAtomically(file, JSON.stringify({ v: 1, publicKey: fresh, sealed: await sealWithKek(kek, CTX, aad(fresh), kp.privateKey) }));
  } finally {
    if (!created) kp.privateKey.fill(0);
  }
  if (created) {
    publicKey = fresh;
    pkcs8 = kp.privateKey;
  } else {
    const f = await readIdentityFile(file);
    publicKey = f.publicKey;
    pkcs8 = await openWithKek(kek, CTX, aad(publicKey), f.sealed).catch((err) => {
      throw err instanceof CryptoError ? new EnvelopeError("bad_envelope") : err;
    });
  }
  const keyId = await gatewayKeyId(b64url.decode(publicKey));
  return { keyId, publicKey, sign: (ids) => signAgentKey(pkcs8, keyId, ids) };
}
