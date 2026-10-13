import { createReadStream, createWriteStream } from "node:fs";
import { copyFile, mkdir, readdir, rename, rm, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { DeleteObjectsCommand, GetObjectCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";

export interface S3Settings { endpoint?: string; region: string; bucket: string; prefix: string; accessKeyId?: string; secretAccessKey?: string; forcePathStyle: boolean }

/** Where backups go. `name` is the bare object name (`clane-vault-…dump.age`); the destination adds its prefix/dir. */
export interface Destination {
  /** Shown to admins and in logs: never credentials. */
  describe(): { type: "s3"; bucket: string; prefix: string; endpoint?: string } | { type: "local"; dir: string };
  /** Full key or path of `name` in this destination. */
  locate(name: string): string;
  put(name: string, file: string): Promise<void>;
  /** Bare names of everything under the prefix/dir. */
  list(): Promise<string[]>;
  remove(names: string[]): Promise<void>;
  get(keyOrName: string): Promise<Readable>;
}

export class LocalDestination implements Destination {
  constructor(private readonly dir: string) {}
  describe() { return { type: "local" as const, dir: this.dir }; }
  locate(name: string) { return join(this.dir, name); }
  async put(name: string, file: string) {
    await mkdir(this.dir, { recursive: true });
    // Copy under a temporary name first so a half-written file never looks like a backup.
    const tmp = join(this.dir, `.${name}.partial`);
    await copyFile(file, tmp);
    await rename(tmp, this.locate(name));
  }
  async list() {
    try { return await readdir(this.dir); } catch (e) { if ((e as NodeJS.ErrnoException).code === "ENOENT") return []; throw e; }
  }
  async remove(names: string[]) { for (const n of names) await rm(this.locate(basename(n)), { force: true }); }
  async get(keyOrName: string) {
    const p = keyOrName.includes("/") || keyOrName.includes("\\") ? keyOrName : this.locate(keyOrName);
    await stat(p);
    return createReadStream(p);
  }
}

export class S3Destination implements Destination {
  private readonly client: S3Client;
  constructor(private readonly s: S3Settings) {
    this.client = new S3Client({
      region: s.region, forcePathStyle: s.forcePathStyle,
      ...(s.endpoint ? { endpoint: s.endpoint } : {}),
      ...(s.accessKeyId && s.secretAccessKey ? { credentials: { accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey } } : {}),
    });
  }
  describe() { return { type: "s3" as const, bucket: this.s.bucket, prefix: this.s.prefix, ...(this.s.endpoint ? { endpoint: new URL(this.s.endpoint).host } : {}) }; }
  locate(name: string) { return `${this.s.prefix}${name}`; }
  async put(name: string, file: string) {
    const up = new Upload({ client: this.client, params: { Bucket: this.s.bucket, Key: this.locate(name), Body: createReadStream(file), ContentType: "application/octet-stream" } });
    await up.done();
  }
  async list() {
    const out: string[] = [];
    let token: string | undefined;
    do {
      const r = await this.client.send(new ListObjectsV2Command({ Bucket: this.s.bucket, Prefix: this.s.prefix, ...(token ? { ContinuationToken: token } : {}) }));
      for (const o of r.Contents ?? []) if (o.Key && !o.Key.slice(this.s.prefix.length).includes("/")) out.push(o.Key.slice(this.s.prefix.length));
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
    } while (token);
    return out;
  }
  async remove(names: string[]) {
    for (let i = 0; i < names.length; i += 1000) {
      const r = await this.client.send(new DeleteObjectsCommand({ Bucket: this.s.bucket, Delete: { Objects: names.slice(i, i + 1000).map((n) => ({ Key: this.locate(n) })), Quiet: true } }));
      if (r.Errors?.length) throw new Error(`S3 delete failed for ${r.Errors.length} object(s)`);
    }
  }
  /** Accepts a full key, or a bare name that gets the configured prefix. */
  async get(keyOrName: string) {
    const key = keyOrName.startsWith(this.s.prefix) || keyOrName.includes("/") ? keyOrName : this.locate(keyOrName);
    const r = await this.client.send(new GetObjectCommand({ Bucket: this.s.bucket, Key: key }));
    return r.Body as Readable;
  }
  destroy() { this.client.destroy(); }
}

/** Streams to a file and returns its byte count. */
export async function streamToFile(src: Readable, file: string): Promise<number> {
  let n = 0;
  src.on("data", (c: Buffer) => { n += c.length; });
  await pipeline(src, createWriteStream(file, { mode: 0o600 }));
  return n;
}
