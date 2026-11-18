import { describe, expect, it } from "vitest";
import { encryptNewRecord, generateKeyPair, randomBytes, shareRecordKey, type UnlockedKeys } from "@clane-vault/crypto";
import { decryptSync } from "./decrypt";
import type { SyncRecord } from "./types";

const ME = "11111111-0000-4000-8000-000000000001";
const AGENT = "bbbbbbbb-0000-4000-8000-000000000002";
const rec = (p: Partial<SyncRecord> & Pick<SyncRecord, "id" | "encBody" | "wrappedRecordKey">): SyncRecord =>
  ({ folderId: null, type: "login", revision: 1, updatedAt: "2026-11-15T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ownerId: ME, ...p });

describe("decryptSync in the Personal space (personal agents)", () => {
  it("a record of mine whose key is a sealed box (s1.) still does not open: the guard is untouched", async () => {
    const keys: UnlockedKeys = { userKey: randomBytes(32), ...(await generateKeyPair()) };
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, keys.userKey);
    const sealed = await shareRecordKey(enc.recordKey, id, keys.publicKey);
    expect(sealed.startsWith("s1.")).toBe(true);
    const out = await decryptSync({ serverTime: "", folders: [], records: [rec({ id, encBody: enc.encBody, wrappedRecordKey: sealed, agentGrants: [{ agentId: AGENT, use: true, write: false }] })] }, keys, ME, null);
    expect(out.records[0]).toMatchObject({ body: null, recordKey: null, error: "cannot_open" });
  });

  it("agentGrants survive decryptSync", async () => {
    const keys: UnlockedKeys = { userKey: randomBytes(32), ...(await generateKeyPair()) };
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Stripe", password: "x" }, keys.userKey);
    const grants = [{ agentId: AGENT, use: true, write: true }];
    const out = await decryptSync({ serverTime: "", folders: [], records: [rec({ id, encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey, agentGrants: grants })] }, keys, ME, null);
    expect(out.records[0].body?.title).toBe("Stripe");
    expect(out.records[0].agentGrants).toEqual(grants);
  });
});
