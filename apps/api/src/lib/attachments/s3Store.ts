import { createHash } from "node:crypto";
import { DeleteObjectsCommand, GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import type { S3Settings } from "../backup/destinations.js";
import type { ChunkStore } from "./store.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Chunks as S3 objects `<prefix><attachmentId>/<index>` (docs/attachments.md, "S3 storage"). The API proxies every
 * byte (no pre-signed URLs), so authorization stays in one place. The index rows stay in Postgres.
 */
export class S3ChunkStore implements ChunkStore {
  readonly kind = "s3" as const;
  private readonly client: S3Client;
  constructor(private readonly s: S3Settings) {
    this.client = new S3Client({
      region: s.region, forcePathStyle: s.forcePathStyle,
      // S3-compatible services (MinIO, Supabase Storage, R2) don't all accept the SDK's default CRC checksums.
      requestChecksumCalculation: "WHEN_REQUIRED", responseChecksumValidation: "WHEN_REQUIRED",
      ...(s.endpoint ? { endpoint: s.endpoint } : {}),
      ...(s.accessKeyId && s.secretAccessKey ? { credentials: { accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey } } : {}),
    });
  }

  private key(attachmentId: string, index: number) { return `${this.s.prefix}${attachmentId}/${index}`; }

  describe() { return { bucket: this.s.bucket, prefix: this.s.prefix, ...(this.s.endpoint ? { endpoint: new URL(this.s.endpoint).host } : {}) }; }

  async put(attachmentId: string, index: number, data: Uint8Array) {
    await this.client.send(new PutObjectCommand({ Bucket: this.s.bucket, Key: this.key(attachmentId, index), Body: data, ContentType: "application/octet-stream",
      ContentLength: data.byteLength, ContentMD5: createHash("md5").update(data).digest("base64") }));
  }

  async get(attachmentId: string, index: number) {
    try {
      const r = await this.client.send(new GetObjectCommand({ Bucket: this.s.bucket, Key: this.key(attachmentId, index) }));
      return r.Body ? await r.Body.transformToByteArray() : null;
    } catch (e) {
      if ((e as { name?: string }).name === "NoSuchKey" || (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 404) return null;
      throw e;
    }
  }

  private async keys(prefix: string): Promise<string[]> {
    const out: string[] = [];
    let token: string | undefined;
    do {
      const r = await this.client.send(new ListObjectsV2Command({ Bucket: this.s.bucket, Prefix: prefix, ...(token ? { ContinuationToken: token } : {}) }));
      for (const o of r.Contents ?? []) if (o.Key) out.push(o.Key);
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
    } while (token);
    return out;
  }

  async has(attachmentId: string) {
    const p = `${this.s.prefix}${attachmentId}/`;
    return new Set((await this.keys(p)).map((k) => Number(k.slice(p.length))).filter((n) => Number.isInteger(n) && n >= 0));
  }

  async deleteAll(attachmentId: string) {
    const keys = await this.keys(`${this.s.prefix}${attachmentId}/`);
    for (let i = 0; i < keys.length; i += 1000) {
      const r = await this.client.send(new DeleteObjectsCommand({ Bucket: this.s.bucket, Delete: { Objects: keys.slice(i, i + 1000).map((Key) => ({ Key })), Quiet: true } }));
      if (r.Errors?.length) throw new Error(`S3 delete failed for ${r.Errors.length} object(s)`);
    }
  }

  /** Attachment ids that have objects under the prefix (the orphan pass compares them with Attachment rows). */
  async listAttachmentIds(): Promise<string[]> {
    const ids = new Set<string>();
    for (const k of await this.keys(this.s.prefix)) {
      const id = k.slice(this.s.prefix.length).split("/")[0] ?? "";
      if (UUID.test(id)) ids.add(id);
    }
    return [...ids];
  }

  destroy() { this.client.destroy(); }
}
