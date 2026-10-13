import { describe, expect, it } from "vitest";
import {
  encryptNewRecord, decryptRecord, encryptRecordBody, encryptFolderName, decryptFolderName, randomBytes, type RecordBody, aeadDecrypt, aeadEncrypt, utf8,
} from "../src/index.js";

const body: RecordBody = { type: "login", title: "AWS root", username: "ops@clane.ai", password: "Tg7#qL2v!Rm9zW4x", url: "console.aws.amazon.com", notes: "Rotate 90d" };

describe("records", () => {
  const userKey = randomBytes(32);
  const id = crypto.randomUUID();

  it("round-trips a record", async () => {
    const enc = await encryptNewRecord(id, body, userKey);
    const dec = await decryptRecord(id, enc.encBody, enc.wrappedRecordKey, userKey);
    expect(dec.body).toEqual({ ...body, v: 2 });
    expect(dec.recordKey).toEqual(enc.recordKey);
  });

  it("does not leak any field into the ciphertext", async () => {
    const enc = await encryptNewRecord(id, body, userKey);
    for (const v of Object.values(body)) expect(enc.encBody).not.toContain(String(v));
  });

  it("refuses a body moved to another record id", async () => {
    const enc = await encryptNewRecord(id, body, userKey);
    await expect(decryptRecord(crypto.randomUUID(), enc.encBody, enc.wrappedRecordKey, userKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("re-encrypts an edited body under the same record key", async () => {
    const enc = await encryptNewRecord(id, body, userKey);
    const encBody = await encryptRecordBody(id, { ...body, password: "new" }, enc.recordKey);
    expect((await decryptRecord(id, encBody, enc.wrappedRecordKey, userKey)).body.password).toBe("new");
  });

  it("rejects a body that is not a valid record", async () => {
    await expect(encryptNewRecord(id, { type: "login", title: "" } as RecordBody, userKey)).rejects.toThrow(/title/);
  });

  it("round-trips folder names", async () => {
    const fid = crypto.randomUUID();
    const enc = await encryptFolderName(fid, "Infrastructure", userKey);
    expect(await decryptFolderName(fid, enc, userKey)).toBe("Infrastructure");
  });

  it("rejects record body encrypted for different record id", async () => {
    const idA = crypto.randomUUID();
    const idB = crypto.randomUUID();
    const recordKey = randomBytes(32);
    const encBodyA = await encryptRecordBody(idA, body, recordKey);
    const wrappedKey = await aeadEncrypt(userKey, recordKey, `record-key:${idB}`);
    await expect(decryptRecord(idB, encBodyA, wrappedKey, userKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects folder name encrypted for different folder id", async () => {
    const fidA = crypto.randomUUID();
    const fidB = crypto.randomUUID();
    const encA = await encryptFolderName(fidA, "Folder A", userKey);
    await expect(decryptFolderName(fidB, encA, userKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects non-JSON record body", async () => {
    const recordKey = randomBytes(32);
    const encBody = await aeadEncrypt(recordKey, utf8.encode("not json"), `record-body:${id}`);
    const wrappedKey = await aeadEncrypt(userKey, recordKey, `record-key:${id}`);
    await expect(decryptRecord(id, encBody, wrappedKey, userKey)).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("rejects invalid record body shape", async () => {
    const recordKey = randomBytes(32);
    const encBody = await aeadEncrypt(recordKey, utf8.encode(JSON.stringify({ type: "invalid" })), `record-body:${id}`);
    const wrappedKey = await aeadEncrypt(userKey, recordKey, `record-key:${id}`);
    await expect(decryptRecord(id, encBody, wrappedKey, userKey)).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("keeps passwordChangedAt only next to a password and only when it is a date", async () => {
    const at = "2026-01-02T03:04:05.000Z";
    const rt = async (b: RecordBody) => { const e = await encryptNewRecord(id, b, userKey); return (await decryptRecord(id, e.encBody, e.wrappedRecordKey, userKey)).body; };
    expect((await rt({ ...body, passwordChangedAt: at })).passwordChangedAt).toBe(at);
    expect((await rt({ ...body, passwordChangedAt: "soon" })).passwordChangedAt).toBeUndefined();
    expect((await rt({ type: "note", title: "n", passwordChangedAt: at })).passwordChangedAt).toBeUndefined();
  });
});
