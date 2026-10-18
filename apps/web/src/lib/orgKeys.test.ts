import { beforeEach, describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import {
  b64url, createAccount, createMembershipKeys, generateKeyPair, configureKdfFloor, openMembershipEscrow, openOrgFolderKey, openOrgRecordShare, randomBytes, sealFolderKeyFor,
  shareRecordKey, unlockMembershipKeys, type KdfParams, type MembershipKeys,
} from "@clane-vault/crypto";
import { server } from "@/test/server";
import { forOrg } from "./api";
import { AgentAttestationError, assertPinned, ensureGatewayPinned, gatewayPinStatus, isAgent, KeyChangedError, myMembershipKey, pinGateway, pinKey, pinnedGateway, pinStatus, sealFolderKeyTo, sealShareTo, syncMembershipKeys, verifyAgentKey } from "./orgKeys";

configureKdfFloor({ m: 1024, t: 1 });
const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 1, p: 1 };
const ORG = "0e0e0e0e-1111-4222-8333-444455556666";
beforeEach(() => { try { localStorage.clear(); } catch { /* none */ } });

describe("sealing to a recipient", () => {
  it("uses their membership key when they have one, else their account key; says which", async () => {
    const acct = await createAccount("pw pw pw pw pw", FAST);
    const mk = await createMembershipKeys(acct.keys.userKey, { orgId: ORG, userId: "u1" });
    const fk = randomBytes(32), rk = randomBytes(32), fid = crypto.randomUUID(), rid = crypto.randomUUID();
    const a = await sealFolderKeyTo(fk, { orgId: ORG, folderId: fid }, { id: "u1", publicKey: acct.material.publicKey, membershipKey: mk.material.publicKey }, "me");
    expect(a.sealedTo).toBe(mk.material.publicKey);
    expect(await openOrgFolderKey(a.wrappedFolderKey, { orgId: ORG, folderId: fid }, mk.keys)).toEqual(fk);
    const b = await sealFolderKeyTo(fk, { orgId: ORG, folderId: fid }, { id: "u1", publicKey: acct.material.publicKey, membershipKey: null }, "me");
    expect(b.sealedTo).toBeNull();
    const s = await sealShareTo(rk, { orgId: ORG, recordId: rid }, { id: "u1", publicKey: acct.material.publicKey, membershipKey: mk.material.publicKey }, "me");
    expect(await openOrgRecordShare(s.sealedRecordKey, { orgId: ORG, recordId: rid }, mk.keys)).toEqual(rk);
  });

  it("pins the key sealed to and flags a change", () => {
    expect(pinStatus("me", ORG, "u1", "K1").status).toBe("new");
    pinKey("me", ORG, "u1", "K1");
    expect(pinStatus("me", ORG, "u1", "K1").status).toBe("same");
    expect(pinStatus("me", ORG, "u1", "K2")).toEqual({ status: "changed", previous: "K1" });
  });

  it("refuses to seal to a changed key until it's accepted (re-pinned); a first contact goes through", () => {
    expect(() => assertPinned("me", ORG, { id: "u1", publicKey: "A", membershipKey: "K1" })).not.toThrow();
    pinKey("me", ORG, "u1", "K1", "A");
    expect(() => assertPinned("me", ORG, { id: "u1", publicKey: "A", membershipKey: "K1" })).not.toThrow();
    expect(() => assertPinned("me", ORG, { id: "u1", publicKey: "A", membershipKey: "EVIL" })).toThrow(KeyChangedError);
    expect(() => assertPinned("me", ORG, { id: "u1", publicKey: "EVIL", membershipKey: null })).toThrow(KeyChangedError);
    pinKey("me", ORG, "u1", "K2", "A");
    expect(() => assertPinned("me", ORG, { id: "u1", publicKey: "A", membershipKey: "K2" })).not.toThrow();
  });

  it("flags a pinned membership key that the server now drops (sealing would go to an account key it names)", () => {
    pinKey("me", ORG, "u1", "K1", "ACCT");
    expect(pinStatus("me", ORG, "u1", null, "ACCT")).toEqual({ status: "changed", previous: "K1" });
    expect(pinStatus("me", ORG, "u1", undefined, "OTHER")).toEqual({ status: "changed", previous: "K1" });
    // Account keys are pinned too; their first membership key is the normal upgrade.
    pinKey("me", ORG, "u2", null, "ACCT2");
    expect(pinStatus("me", ORG, "u2", null, "ACCT2").status).toBe("same");
    expect(pinStatus("me", ORG, "u2", null, "EVIL").status).toBe("changed");
    expect(pinStatus("me", ORG, "u2", "M2", "ACCT2").status).toBe("new");
  });

  it("my own key is only one I can open: a key the server merely lists for me is refused", async () => {
    const me = await createAccount("pw pw pw pw pw", FAST);
    const mine = await createMembershipKeys(me.keys.userKey, { orgId: ORG, userId: "u1" });
    const evil = await createMembershipKeys(randomBytes(32), { orgId: ORG, userId: "u1" });
    let listed = mine.material;
    server.use(http.get("/api/v1/membership-key", () => HttpResponse.json({ keys: [{ ...listed, state: "current" }] })));
    expect(await myMembershipKey(forOrg(ORG), ORG, "u1", me.keys.userKey)).toBe(mine.material.publicKey);
    // The server swaps in a key pair of its own (or just another public key next to my wrapped private key).
    listed = evil.material;
    await expect(myMembershipKey(forOrg(ORG), ORG, "u1", me.keys.userKey)).rejects.toThrow();
    listed = { ...mine.material, publicKey: evil.material.publicKey };
    await expect(myMembershipKey(forOrg(ORG), ORG, "u1", me.keys.userKey)).rejects.toThrow();
  });
});

describe("the membership job", () => {
  it("creates my key, moves rows from my account key, then escrows to the listed admin", async () => {
    const me = await createAccount("pw pw pw pw pw", FAST);
    const admin = await createMembershipKeys(randomBytes(32), { orgId: ORG, userId: "a1" });
    const fid = crypto.randomUUID(), rid = crypto.randomUUID();
    const fk = randomBytes(32), rk = randomBytes(32);
    const legacyFolder = await sealFolderKeyFor(fk, fid, me.keys.publicKey);
    const legacyShare = await shareRecordKey(rk, rid, me.keys.publicKey);
    let stored = null as { publicKey: string; wrappedPrivateKey: string } | null;
    let rows = null as null | { folders: { folderId: string; from: string | null; wrappedFolderKey: string }[]; shares: { recordId: string; from: string | null; wrappedRecordKey: string }[] };
    let escrows = null as null | { memberPublicKey: string; escrows: { adminId: string; adminPublicKey: string; sealedKey: string }[] };
    server.use(
      http.get("/api/v1/membership-key", () => HttpResponse.json({ userKeyGen: 1, keys: stored ? [{ ...stored, state: "current", escrowOpenedAt: null }] : [], rotateNeeded: false, pendingRows: rows ? 0 : 2, repairNeeded: false,
        escrow: { enabled: true, ackRequired: false, needed: rows ? [{ adminId: "a1", publicKey: admin.material.publicKey }] : [], holders: [], recoverable: false } })),
      http.post("/api/v1/membership-key", async ({ request }) => { const b = (await request.json()) as { publicKey: string; wrappedPrivateKey: string }; stored = b; return HttpResponse.json({ created: true, key: { ...b, state: "current" } }, { status: 201 }); }),
      http.get("/api/v1/membership-key/pending", () => HttpResponse.json(rows ? { folders: [], shares: [], folderAfter: null, shareAfter: null }
        : { folders: [{ folderId: fid, sealedTo: null, wrappedFolderKey: legacyFolder }], shares: [{ recordId: rid, sealedTo: null, wrappedRecordKey: legacyShare }], folderAfter: null, shareAfter: null })),
      http.put("/api/v1/membership-key/rows", async ({ request }) => { rows = (await request.json()) as never; return HttpResponse.json({ updated: 2, retired: 0, pendingRows: 0 }); }),
      http.put("/api/v1/membership-key/escrows", async ({ request }) => { escrows = (await request.json()) as never; return HttpResponse.json({ stored: 1 }); }),
    );
    const r = await syncMembershipKeys(forOrg(ORG), ORG, "u1", me.keys);
    expect(r).toMatchObject({ created: true, moved: 2, escrowed: 1 });
    const mine: MembershipKeys = await unlockMembershipKeys(me.keys.userKey, { orgId: ORG, userId: "u1" }, stored!);
    expect(rows!.folders[0]!.from).toBeNull();
    // The batch names the key it is sealed to (the server refuses it if another device rotated meanwhile).
    expect((rows as unknown as { to: string }).to).toBe(stored!.publicKey);
    expect(await openOrgFolderKey(rows!.folders[0]!.wrappedFolderKey, { orgId: ORG, folderId: fid }, mine)).toEqual(fk);
    expect(await openOrgRecordShare(rows!.shares[0]!.wrappedRecordKey, { orgId: ORG, recordId: rid }, mine)).toEqual(rk);
    expect(escrows!.memberPublicKey).toBe(stored!.publicKey);
    const opened = await openMembershipEscrow(admin.keys, escrows!.escrows[0]!.sealedKey, { userId: "u1", adminId: "a1" }, stored!.publicKey);
    expect(opened.privateKey).toEqual(mine.privateKey);
  });

  it("rotates after an admin opened the escrow, and moves rows from the old key", async () => {
    const me = await createAccount("pw pw pw pw pw", FAST);
    const old = await createMembershipKeys(me.keys.userKey, { orgId: ORG, userId: "u1" });
    const fid = crypto.randomUUID(), fk = randomBytes(32);
    const { sealOrgFolderKey } = await import("@clane-vault/crypto");
    const onOld = await sealOrgFolderKey(fk, { orgId: ORG, folderId: fid }, old.keys.publicKey);
    let rotated = null as null | { from: string; publicKey: string; wrappedPrivateKey: string };
    let moved = null as null | { folders: { folderId: string; from: string | null; wrappedFolderKey: string }[] };
    server.use(
      http.get("/api/v1/membership-key", () => HttpResponse.json({ userKeyGen: 1, keys: [{ ...old.material, state: "current", escrowOpenedAt: "2026-10-08T00:00:00Z" }], rotateNeeded: !rotated, pendingRows: 0, repairNeeded: false,
        escrow: { enabled: false, ackRequired: false, needed: [], holders: [], recoverable: false } })),
      http.post("/api/v1/membership-key/rotate", async ({ request }) => { rotated = (await request.json()) as never; return HttpResponse.json({ ok: true }); }),
      http.get("/api/v1/membership-key/pending", () => HttpResponse.json({ folders: moved ? [] : [{ folderId: fid, sealedTo: old.material.publicKey, wrappedFolderKey: onOld }], shares: [], folderAfter: null, shareAfter: null })),
      http.put("/api/v1/membership-key/rows", async ({ request }) => { moved = (await request.json()) as never; return HttpResponse.json({ updated: 1, retired: 1, pendingRows: 0 }); }),
    );
    const r = await syncMembershipKeys(forOrg(ORG), ORG, "u1", me.keys);
    expect(r).toMatchObject({ rotated: true, moved: 1 });
    expect(rotated!.from).toBe(old.material.publicKey);
    expect(moved!.folders[0]!.from).toBe(old.material.publicKey);
    const next = await unlockMembershipKeys(me.keys.userKey, { orgId: ORG, userId: "u1" }, rotated!);
    expect(await openOrgFolderKey(moved!.folders[0]!.wrappedFolderKey, { orgId: ORG, folderId: fid }, next)).toEqual(fk);
    await expect(openOrgFolderKey(moved!.folders[0]!.wrappedFolderKey, { orgId: ORG, folderId: fid }, old.keys)).rejects.toThrow();
  });
});

describe("agent keys: the gateway's attestation is checked against the pinned gateway identity before sealing (R41)", () => {
  async function setup() {
    const { gatewayKeyId, generateIdentityKeyPair, signAgentKey, b64url } = await import("@clane-vault/crypto");
    const gw = await generateIdentityKeyPair();
    const identity = { keyId: await gatewayKeyId(gw.publicKey), publicKey: b64url.encode(gw.publicKey) };
    const agentKey = b64url.encode((await generateKeyPair()).publicKey);
    const attestation = await signAgentKey(gw.privateKey, identity.keyId, { orgId: ORG, agentId: "ag1", publicKey: agentKey });
    const agent = { id: "ag1", kind: "agent" as const, publicKey: agentKey, membershipKey: agentKey, attestation, gatewayKeyId: identity.keyId };
    return { identity, agent, agentKey };
  }
  const reasonOf = (p: Promise<unknown>) => p.then(() => "ok", (e: unknown) => (e instanceof AgentAttestationError ? e.reason : `other: ${String(e)}`));

  it("pins one gateway identity per signed-in user and org, and refuses a keyId that isn't derived from the key", async () => {
    const { identity } = await setup();
    expect(pinnedGateway("me", ORG)).toBeNull();
    await pinGateway("me", ORG, identity);
    expect(pinnedGateway("me", ORG)).toEqual(identity);
    expect(pinnedGateway("me", "other-org")).toBeNull();
    expect(pinnedGateway("someone-else", ORG)).toBeNull();
    await expect(pinGateway("me", "o2", { keyId: "AAAAAAAAAAAAAAAA", publicKey: identity.publicKey })).rejects.toThrow(/doesn't match/);
    expect(pinnedGateway("me", "o2")).toBeNull();
  });

  it("members pin the gateway on first use from /org/agents/gateway; never repin; a later gateway is gateway_changed", async () => {
    const { identity, agent } = await setup();
    let served: Record<string, string> = { url: "https://gw/mcp", identityKeyId: identity.keyId, identityPublicKey: identity.publicKey };
    let calls = 0;
    server.use(http.get("/api/v1/org/agents/gateway", () => { calls++; return HttpResponse.json(served); }));
    const oapi = forOrg(ORG);
    expect(await ensureGatewayPinned(oapi, "me", ORG)).toEqual({ identity, pinnedNow: true });
    expect(pinnedGateway("me", ORG)).toEqual(identity);
    expect(await reasonOf(verifyAgentKey("me", ORG, agent))).toBe("ok");
    // Pinned: no request, no repin, even if the server now serves another identity.
    const other = await setup();
    served = { identityKeyId: other.identity.keyId, identityPublicKey: other.identity.publicKey };
    expect(await ensureGatewayPinned(oapi, "me", ORG)).toEqual({ identity, pinnedNow: false });
    expect(calls).toBe(1);
    // An agent the other gateway attested is refused.
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...other.agent }))).toBe("gateway_changed");
    // An inconsistent pair is never pinned.
    served = { identityKeyId: identity.keyId, identityPublicKey: other.identity.publicKey };
    expect(await reasonOf(ensureGatewayPinned(oapi, "me2", ORG))).toBe("unpinned");
    expect(pinnedGateway("me2", ORG)).toBeNull();
    // Gateway unreachable: refused, nothing pinned.
    server.use(http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ error: "gateway_unavailable" }, { status: 503 })));
    expect(await reasonOf(ensureGatewayPinned(oapi, "me3", ORG))).toBe("unpinned");
  });

  it("two concurrent first pins never overwrite each other; only an explicit repin replaces; private mode isn't pinnedNow", async () => {
    const a = await setup(), b = await setup();
    const results = await Promise.allSettled([pinGateway("race", ORG, a.identity), pinGateway("race", ORG, b.identity)]);
    expect(results[0]).toEqual({ status: "fulfilled", value: true });
    expect(results[1].status === "rejected" && (results[1].reason as AgentAttestationError).reason).toBe("gateway_changed");
    expect(pinnedGateway("race", ORG)).toEqual(a.identity);
    expect(gatewayPinStatus("race", ORG, b.identity).status).toBe("changed");
    expect(await pinGateway("race", ORG, a.identity)).toBe(false);
    expect(await pinGateway("race", ORG, b.identity, { repin: true })).toBe(true);
    expect(gatewayPinStatus("race", ORG, b.identity).status).toBe("same");
    // Private mode: setItem throws, so nothing was pinned now.
    server.use(http.get("/api/v1/org/agents/gateway", () => HttpResponse.json({ url: "https://gw/mcp", identityKeyId: a.identity.keyId, identityPublicKey: a.identity.publicKey })));
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("QuotaExceededError"); });
    try { expect(await ensureGatewayPinned(forOrg(ORG), "private", ORG)).toEqual({ identity: a.identity, pinnedNow: false }); } finally { set.mockRestore(); }
  });

  it("passes a correctly attested agent key; refuses missing, unpinned, other-gateway and forged attestations", async () => {
    const { identity, agent } = await setup();
    expect(await reasonOf(verifyAgentKey("me", ORG, agent))).toBe("unpinned");
    await pinGateway("me", ORG, identity);
    expect(await reasonOf(verifyAgentKey("me", ORG, agent))).toBe("ok");
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...agent, attestation: undefined }))).toBe("missing");
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...agent, gatewayKeyId: "someoneelse00000" }))).toBe("gateway_changed");
    // The server swaps in a key of its own: the gateway's signature no longer covers it.
    const swapped = b64url.encode((await generateKeyPair()).publicKey);
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...agent, membershipKey: swapped }))).toBe("invalid");
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...agent, publicKey: swapped, membershipKey: null }))).toBe("invalid");
    // Signed for another org or agent id.
    expect(await reasonOf(verifyAgentKey("me", "other-org", agent))).toBe("unpinned");
    expect(await reasonOf(verifyAgentKey("me", ORG, { ...agent, id: "ag2" }))).toBe("invalid");
  });

  it("sealing refuses an unverified agent, and spots agents by attestation or email even without kind", async () => {
    const { identity, agent } = await setup();
    const fk = randomBytes(32), ids = { orgId: ORG, folderId: crypto.randomUUID() };
    expect(await reasonOf(sealFolderKeyTo(fk, ids, agent, "me"))).toBe("unpinned");
    expect(await reasonOf(sealShareTo(fk, { orgId: ORG, recordId: "r1" }, { ...agent, kind: undefined }, "me"))).toBe("unpinned");
    expect(await reasonOf(sealFolderKeyTo(fk, ids, { id: "x", publicKey: agent.publicKey, email: "agent+x@agents.invalid" }, "me"))).toBe("unpinned");
    await pinGateway("me", ORG, identity);
    expect((await sealFolderKeyTo(fk, ids, agent, "me")).sealedTo).toBe(agent.membershipKey);
    expect(isAgent({ id: "u", publicKey: "k" })).toBe(false);
  });
});
