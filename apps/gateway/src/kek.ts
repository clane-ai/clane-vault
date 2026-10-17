import { createHash } from "node:crypto";
import { readFile as fsReadFile } from "node:fs/promises";
import { aeadDecrypt, aeadEncrypt, b64url } from "@clane-vault/crypto";

export type KekContext = Record<string, string>;
export interface Kek { readonly id: string; wrap(dek: Uint8Array, ctx: KekContext): Promise<string>; unwrap(wrapped: string, ctx: KekContext): Promise<Uint8Array> }
export interface AwsKmsLike {
  encrypt(i: { KeyId: string; Plaintext: Uint8Array; EncryptionContext: KekContext }): Promise<{ CiphertextBlob?: Uint8Array }>;
  decrypt(i: { KeyId: string; CiphertextBlob: Uint8Array; EncryptionContext: KekContext }): Promise<{ Plaintext?: Uint8Array }>;
}
export interface KekDeps { aws?: AwsKmsLike; fetch?: typeof fetch; readFile?: (p: string) => Promise<Uint8Array> }

const hash12 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("base64url").slice(0, 12);
/** Sorted `k=v` pairs joined with `;`. */
const canonical = (ctx: KekContext) => Object.keys(ctx).sort().map((k) => `${k}=${ctx[k]}`).join(";");
const b64 = (u8: Uint8Array) => Buffer.from(u8).toString("base64");

export async function loadKek(spec: string, deps: KekDeps = {}): Promise<Kek> {
  const i = spec.indexOf(":");
  const kind = i < 0 ? "" : spec.slice(0, i), arg = spec.slice(i + 1);
  if (kind === "file") return fileKek(new Uint8Array(await (deps.readFile ?? fsReadFile)(arg)));
  if (kind === "aws-kms" && arg) return awsKek(arg, deps.aws ?? await realAws());
  if (kind === "gcp-kms" && arg) return gcpKek(arg, deps.fetch ?? fetch);
  throw new Error("GATEWAY_KEK must be aws-kms:<key arn>, gcp-kms:<resource name> or file:<path>");
}

function fileKek(key: Uint8Array): Kek {
  if (key.length !== 32) throw new Error("GATEWAY_KEK file must hold exactly 32 bytes");
  return {
    id: `file-${hash12(key)}`,
    wrap: async (dek, ctx) => (await aeadEncrypt(key, dek, `kek:${canonical(ctx)}`)).slice(3),
    unwrap: (wrapped, ctx) => aeadDecrypt(key, `v1.${wrapped}`, `kek:${canonical(ctx)}`),
  };
}

async function realAws(): Promise<AwsKmsLike> {
  const m = await import("@aws-sdk/client-kms");
  // Bundled by esbuild, the SDK's CommonJS build arrives as the default export only.
  const { KMSClient, EncryptCommand, DecryptCommand } = (m as unknown as { default?: typeof m }).default ?? m;
  const c = new KMSClient({});
  return { encrypt: (i) => c.send(new EncryptCommand(i)), decrypt: (i) => c.send(new DecryptCommand(i)) };
}

function awsKek(arn: string, aws: AwsKmsLike): Kek {
  return {
    id: `aws-${hash12(arn)}`,
    async wrap(dek, ctx) {
      const r = await aws.encrypt({ KeyId: arn, Plaintext: dek, EncryptionContext: ctx });
      if (!r.CiphertextBlob) throw new Error("KMS Encrypt returned no ciphertext");
      return b64url.encode(r.CiphertextBlob);
    },
    async unwrap(wrapped, ctx) {
      const r = await aws.decrypt({ KeyId: arn, CiphertextBlob: b64url.decode(wrapped), EncryptionContext: ctx });
      if (!r.Plaintext) throw new Error("KMS Decrypt returned no plaintext");
      return new Uint8Array(r.Plaintext);
    },
  };
}

const METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

function gcpKek(resource: string, f: typeof fetch): Kek {
  let token: { value: string; until: number } | undefined;
  async function bearer() {
    if (token && Date.now() < token.until) return token.value;
    const r = await f(METADATA_TOKEN, { headers: { "Metadata-Flavor": "Google" } });
    if (!r.ok) throw new Error(`GCP metadata token request failed (${r.status})`);
    const j = await r.json() as { access_token?: string; expires_in?: number };
    if (!j.access_token) throw new Error("GCP metadata server returned no token");
    token = { value: j.access_token, until: Date.now() + Math.max(0, (j.expires_in ?? 0) - 60) * 1000 };
    return token.value;
  }
  async function call(op: "encrypt" | "decrypt", body: Record<string, string>) {
    const r = await f(`https://cloudkms.googleapis.com/v1/${resource}:${op}`, {
      method: "POST", headers: { authorization: `Bearer ${await bearer()}`, "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`Cloud KMS ${op} failed (${r.status})`);
    return await r.json() as { ciphertext?: string; plaintext?: string };
  }
  return {
    id: `gcp-${hash12(resource)}`,
    async wrap(dek, ctx) {
      const j = await call("encrypt", { plaintext: b64(dek), additionalAuthenticatedData: b64(Buffer.from(canonical(ctx))) });
      if (!j.ciphertext) throw new Error("Cloud KMS encrypt returned no ciphertext");
      return Buffer.from(j.ciphertext, "base64").toString("base64url");
    },
    async unwrap(wrapped, ctx) {
      const j = await call("decrypt", { ciphertext: b64(b64url.decode(wrapped)), additionalAuthenticatedData: b64(Buffer.from(canonical(ctx))) });
      if (!j.plaintext) throw new Error("Cloud KMS decrypt returned no plaintext");
      return new Uint8Array(Buffer.from(j.plaintext, "base64"));
    },
  };
}
