import { readFile, writeFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import { b64url, CryptoError, gatewayKeyId, generateIdentityKeyPair, signAgentKey } from "@clane-vault/crypto";
import { EnvelopeError, openWithKek, sealWithKek } from "./envelope.js";
import type { Kek } from "./kek.js";

export interface Identity { keyId: string; publicKey: string; sign(ids: { orgId: string; agentId: string; publicKey: string }): Promise<string> }

const CTX = { purpose: "gateway-identity" };
const aad = (publicKey: string) => `gateway-identity-key:${publicKey}`;

async function readIdentityFile(file: string): Promise<{ publicKey: string; sealed: string }> {
  // Another replica may have created the file and not written it yet.
  for (let i = 0; ; i++) {
    const text = await readFile(file, "utf8");
    if (text || i >= 40) {
      let j: unknown;
      try { j = JSON.parse(text); } catch { throw new EnvelopeError("bad_envelope"); }
      const o = j as { v?: unknown; publicKey?: unknown; sealed?: unknown };
      if (o?.v !== 1 || typeof o.publicKey !== "string" || typeof o.sealed !== "string") throw new EnvelopeError("bad_envelope");
      return { publicKey: o.publicKey, sealed: o.sealed };
    }
    await sleep(50);
  }
}

export async function loadOrCreateIdentity(file: string, kek: Kek): Promise<Identity> {
  let publicKey: string, pkcs8: Uint8Array;
  const kp = await generateIdentityKeyPair();
  const fresh = b64url.encode(kp.publicKey);
  try {
    await writeFile(file, JSON.stringify({ v: 1, publicKey: fresh, sealed: await sealWithKek(kek, CTX, aad(fresh), kp.privateKey) }), { flag: "wx", mode: 0o600 });
    publicKey = fresh;
    pkcs8 = kp.privateKey;
  } catch (e) {
    kp.privateKey.fill(0);
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    const f = await readIdentityFile(file);
    publicKey = f.publicKey;
    pkcs8 = await openWithKek(kek, CTX, aad(publicKey), f.sealed).catch((err) => {
      throw err instanceof CryptoError ? new EnvelopeError("bad_envelope") : err;
    });
  }
  const keyId = await gatewayKeyId(b64url.decode(publicKey));
  return { keyId, publicKey, sign: (ids) => signAgentKey(pkcs8, keyId, ids) };
}
