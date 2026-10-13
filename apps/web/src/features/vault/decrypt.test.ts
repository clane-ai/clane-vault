import { describe, expect, it } from "vitest";
import { createTeamFolder, encryptNewRecord, encryptFolderName, generateKeyPair, randomBytes, sealFolderKeyFor, shareRecordKey, wrapKey, type UnlockedKeys } from "@clane-vault/crypto";
import { decryptSync } from "./decrypt";
import type { SyncRecord, SyncResponse } from "./types";

const keysFor = async (): Promise<UnlockedKeys> => ({ userKey: randomBytes(32), ...(await generateKeyPair()) });
const rec = (p: Partial<SyncRecord> & Pick<SyncRecord, "id" | "encBody" | "wrappedRecordKey">): SyncRecord =>
  ({ folderId: null, type: "login", revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user", ...p });

describe("decryptSync", () => {
  it("decrypts folders and records and isolates a broken record", async () => {
    const keys = await keysFor();
    const fid = crypto.randomUUID(), good = crypto.randomUUID(), bad = crypto.randomUUID();
    const g = await encryptNewRecord(good, { type: "login", title: "Stripe", password: "x" }, keys.userKey);
    const b = await encryptNewRecord(bad, { type: "note", title: "Broken" }, randomBytes(32)); // wrong key
    const sync: SyncResponse = {
      serverTime: new Date().toISOString(),
      folders: [{ id: fid, kind: "private", encName: await encryptFolderName(fid, "Finance", keys.userKey), deletedAt: null }],
      records: [rec({ id: good, folderId: fid, encBody: g.encBody, wrappedRecordKey: g.wrappedRecordKey }), rec({ id: bad, type: "note", encBody: b.encBody, wrappedRecordKey: b.wrappedRecordKey })],
    };
    const out = await decryptSync(sync, keys);
    expect(out.folders).toEqual([expect.objectContaining({ id: fid, name: "Finance", kind: "private", deleted: false })]);
    expect(out.records.find((r) => r.id === good)!.body!.title).toBe("Stripe");
    const broken = out.records.find((r) => r.id === bad)!;
    expect(broken.body).toBeNull();
    expect(broken.error).toBe("cannot_open");
  });

  it("opens team folders and their records with my private key, and records shared directly with me", async () => {
    const owner = await keysFor(), me = await keysFor();
    const fid = crypto.randomUUID(), teamRec = crypto.randomUUID(), sharedRec = crypto.randomUUID(), otherTeam = crypto.randomUUID();
    const team = await createTeamFolder(fid, "Infra", owner.publicKey);
    const tr = await encryptNewRecord(teamRec, { type: "login", title: "AWS root", password: "team" }, owner.userKey);
    const sr = await encryptNewRecord(sharedRec, { type: "login", title: "Stripe", password: "shared" }, owner.userKey);
    const notMine = await createTeamFolder(otherTeam, "Not for me", owner.publicKey); // key sealed to someone else
    const sync: SyncResponse = {
      serverTime: "",
      folders: [
        { id: fid, kind: "team", encName: team.encName, deletedAt: null, ownerId: "owner", myPermission: "view", wrappedFolderKey: await sealFolderKeyFor(team.folderKey, fid, me.publicKey),
          members: [{ userId: "owner", name: "Ana", email: "ana@clane.ai", publicKey: "", permission: "owner" }] },
        { id: otherTeam, kind: "team", encName: notMine.encName, deletedAt: null, myPermission: "view", wrappedFolderKey: notMine.wrappedFolderKey, members: [] },
      ],
      records: [
        rec({ id: teamRec, folderId: fid, keyFolderId: fid, holderType: "folder", permission: "view", encBody: tr.encBody, wrappedRecordKey: await wrapKey(tr.recordKey, team.folderKey, `record-key:${teamRec}`) }),
        rec({ id: sharedRec, permission: "use", sharedBy: "Ana", encBody: sr.encBody, wrappedRecordKey: await shareRecordKey(sr.recordKey, sharedRec, me.publicKey) }),
      ],
    };
    const out = await decryptSync(sync, me);
    const f = out.folders.find((x) => x.id === fid)!;
    expect(f).toMatchObject({ name: "Infra", kind: "team", myPermission: "view" });
    expect(f.folderKey).toEqual(team.folderKey);
    expect(out.folders.find((x) => x.id === otherTeam)).toMatchObject({ name: "Can't open this folder", folderKey: null });
    expect(out.records.find((r) => r.id === teamRec)!.body!.password).toBe("team");
    expect(out.records.find((r) => r.id === sharedRec)).toMatchObject({ body: { title: "Stripe" }, permission: "use", sharedBy: "Ana" });
  });

  it("fails closed when a record share is bound to a different record id", async () => {
    const owner = await keysFor(), me = await keysFor();
    const a = crypto.randomUUID(), b = crypto.randomUUID();
    const ra = await encryptNewRecord(a, { type: "note", title: "A" }, owner.userKey);
    // the server swaps in a share sealed for record b
    const sealedForB = await shareRecordKey(ra.recordKey, b, me.publicKey);
    const out = await decryptSync({ serverTime: "", folders: [], records: [rec({ id: a, encBody: ra.encBody, wrappedRecordKey: sealedForB, sharedBy: "Ana", permission: "view" })] }, me);
    expect(out.records[0]).toMatchObject({ body: null, error: "cannot_open" });
  });

  it("refuses a sealed (s1.) key on a record I own: owner rows are always wrapped under my user key", async () => {
    const me = await keysFor();
    const id = crypto.randomUUID();
    const enc = await encryptNewRecord(id, { type: "login", title: "Planted", password: "evil" }, randomBytes(32));
    // anyone (e.g. the server) can seal a key to my public key and claim the record is mine
    const planted = rec({ id, ownerId: "me", encBody: enc.encBody, wrappedRecordKey: await shareRecordKey(enc.recordKey, id, me.publicKey) });
    expect((await decryptSync({ serverTime: "", folders: [], records: [planted] }, me, "me")).records[0]).toMatchObject({ body: null, error: "cannot_open" });
    // the same row as a share from someone else still opens
    expect((await decryptSync({ serverTime: "", folders: [], records: [{ ...planted, ownerId: "ana", sharedBy: "Ana" }] }, me, "me")).records[0]!.body!.title).toBe("Planted");
  });

  it("opens a record I own through a team folder I own (folder wrap, no owner row)", async () => {
    const me = await keysFor();
    const fid = crypto.randomUUID(), id = crypto.randomUUID();
    const team = await createTeamFolder(fid, "Infra", me.publicKey);
    const enc = await encryptNewRecord(id, { type: "login", title: "Handed over" }, randomBytes(32));
    const out = await decryptSync({ serverTime: "",
      folders: [{ id: fid, kind: "team", encName: team.encName, deletedAt: null, ownerId: "me", myPermission: "owner", wrappedFolderKey: team.wrappedFolderKey, members: [] }],
      records: [rec({ id, folderId: fid, keyFolderId: fid, holderType: "folder", ownerId: "me", encBody: enc.encBody, wrappedRecordKey: await wrapKey(enc.recordKey, team.folderKey, `record-key:${id}`) })] }, me, "me");
    expect(out.records[0]).toMatchObject({ body: { title: "Handed over" }, permission: "owner" });
  });

  it("opens folders and shares sealed to my membership key, bound to the org I asked for", async () => {
    const me = await keysFor();
    const orgA = crypto.randomUUID(), orgB = crypto.randomUUID();
    const { createMembershipKeys, sealOrgFolderKey, sealOrgRecordShare } = await import("@clane-vault/crypto");
    const mk = await createMembershipKeys(me.userKey, { orgId: orgA, userId: "me" });
    const fid = crypto.randomUUID(), rid = crypto.randomUUID(), sid = crypto.randomUUID();
    const fk = randomBytes(32);
    const encName = await encryptFolderName(fid, "Ops", fk);
    const tr = await encryptNewRecord(rid, { type: "login", title: "Team", password: "t" }, randomBytes(32));
    const sr = await encryptNewRecord(sid, { type: "login", title: "Shared", password: "s" }, randomBytes(32));
    const sync: SyncResponse = { serverTime: "", membershipKeys: [{ ...mk.material, state: "current" }],
      folders: [{ id: fid, kind: "team", encName, deletedAt: null, ownerId: "ana", myPermission: "view", members: [], sealedTo: mk.material.publicKey,
        wrappedFolderKey: await sealOrgFolderKey(fk, { orgId: orgA, folderId: fid }, mk.keys.publicKey) }],
      records: [
        rec({ id: rid, folderId: fid, keyFolderId: fid, holderType: "folder", ownerId: "ana", permission: "view", encBody: tr.encBody, wrappedRecordKey: await wrapKey(tr.recordKey, fk, `record-key:${rid}`) }),
        rec({ id: sid, ownerId: "ana", sharedBy: "Ana", permission: "view", sealedTo: mk.material.publicKey, encBody: sr.encBody, wrappedRecordKey: await sealOrgRecordShare(sr.recordKey, { orgId: orgA, recordId: sid }, mk.keys.publicKey) }),
      ] };
    const out = await decryptSync(sync, me, "me", orgA);
    expect(out.membershipKey).toBe(mk.material.publicKey);
    expect(out.folders[0]!.name).toBe("Ops");
    expect(out.records.map((r) => r.body?.title)).toEqual(["Team", "Shared"]);
    // The same response presented as another org's: the membership key doesn't even unwrap (bound to org A).
    const elsewhere = await decryptSync(sync, me, "me", orgB);
    expect(elsewhere.membershipKey).toBeNull();
    expect(elsewhere.folders[0]!.name).toBe("Can't open this folder");
    expect(elsewhere.records.every((r) => r.error === "cannot_open")).toBe(true);
    // A membership key of another user (or a swapped wrap) is never used.
    expect((await decryptSync(sync, me, "someone-else", orgA)).records.every((r) => r.error === "cannot_open")).toBe(true);
  });
});
