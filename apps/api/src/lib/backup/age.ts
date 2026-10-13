import { Readable } from "node:stream";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { Decrypter, Encrypter } from "age-encryption";

export const AGE_RECIPIENT = /^age1[0-9a-z]{20,}$/;

/** Encrypts a Node stream to one age recipient (X25519 `age1…` or hybrid `age1pq1…`), streaming. */
export async function encryptStream(input: Readable, recipient: string): Promise<Readable> {
  const e = new Encrypter();
  e.addRecipient(recipient);
  const out = await e.encrypt(Readable.toWeb(input) as unknown as ReadableStream<Uint8Array>);
  return Readable.fromWeb(out as unknown as WebReadableStream<Uint8Array>);
}

export async function decryptStream(input: Readable, identities: string[]): Promise<Readable> {
  const d = new Decrypter();
  for (const i of identities) d.addIdentity(i);
  const out = await d.decrypt(Readable.toWeb(input) as unknown as ReadableStream<Uint8Array>);
  return Readable.fromWeb(out as unknown as WebReadableStream<Uint8Array>);
}

/** The secret keys in an age identity file (`age-keygen` output: comments plus `AGE-SECRET-KEY-…` lines). */
export function parseIdentityFile(text: string): string[] {
  const keys = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith("AGE-SECRET-KEY-"));
  if (keys.length === 0) throw new Error("No AGE-SECRET-KEY-… line found in the identity file");
  return keys;
}
