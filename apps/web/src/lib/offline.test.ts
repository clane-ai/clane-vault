import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import type { AccountMaterial } from "@clane-vault/crypto";
import { ApiError } from "./api";
import { dropSync, isUnreachable, loadCopy, loadSync, offlineEnabled, saveAccount, saveSync, setOfflineEnabled, wipeOffline } from "./offline";
import type { SyncResponse } from "@/features/vault/types";

const material = { kdfSalt: "salt", kdfParams: { m: 1 }, wrappedUserKey: "v1.x", publicKey: "pk", wrappedPrivateKey: "v1.y" } as unknown as AccountMaterial;
const sync = (n: number, privateLocked = false): SyncResponse => ({ folders: [], records: Array.from({ length: n }, (_, i) => ({ id: `r${i}` })) as never, serverTime: "t", ...(privateLocked ? { privateLocked } : {}) });
const sara = { id: "u1", email: "sara@clane.ai", name: "Sara" };

beforeEach(async () => { setOfflineEnabled(true); await wipeOffline(); });

describe("offline copy", () => {
  it("stores the account material and each org's sync, per user", async () => {
    await saveAccount(sara, material, []);
    await saveSync("u1", "org-a", sync(2));
    await saveSync("u1", "-", sync(1));
    const c = await loadCopy();
    expect(c).toMatchObject({ userId: "u1", email: "sara@clane.ai", material });
    expect((await loadSync("u1", "org-a"))!.sync.records).toHaveLength(2);
    expect((await loadSync("u1", "-"))!.sync.records).toHaveLength(1);
    expect(await loadSync("u2", "org-a")).toBeNull();
    // A sync for a user without a saved account is ignored.
    await saveSync("u9", "org-a", sync(5));
    expect((await loadCopy())!.userId).toBe("u1");
  });

  it("a newer sync replaces the old one, so items the server withheld (privateLocked) are not kept", async () => {
    await saveAccount(sara, material, []);
    await saveSync("u1", "-", sync(3));
    await saveSync("u1", "-", sync(1, true));
    const s = (await loadSync("u1", "-"))!.sync;
    expect(s.records).toHaveLength(1);
    expect(s.privateLocked).toBe(true);
  });

  it("keeps syncs when the same account signs in again, wipes them on account switch", async () => {
    await saveAccount(sara, material, []);
    await saveSync("u1", "-", sync(2));
    await saveAccount(sara, material, []);
    expect(await loadSync("u1", "-")).not.toBeNull();
    await saveAccount({ id: "u2", email: "b@x.ie", name: "B" }, material, []);
    const c = await loadCopy();
    expect(c!.userId).toBe("u2");
    expect(c!.syncs).toEqual({});
    expect(await loadSync("u1", "-")).toBeNull();
  });

  it("wipes everything on sign-out, and stores nothing while the toggle is off", async () => {
    await saveAccount(sara, material, []);
    await wipeOffline();
    expect(await loadCopy()).toBeNull();
    setOfflineEnabled(false);
    expect(offlineEnabled()).toBe(false);
    await saveAccount(sara, material, []);
    await saveSync("u1", "-", sync(1));
    setOfflineEnabled(true);
    expect(await loadCopy()).toBeNull();
  });

  it("drops one org's sync (org policy: no offline copies) and keeps the rest", async () => {
    await saveAccount(sara, material, []);
    await saveSync("u1", "org-a", sync(2));
    await saveSync("u1", "org-b", sync(1));
    await dropSync("u1", "org-a");
    expect(await loadSync("u1", "org-a")).toBeNull();
    expect(await loadSync("u1", "org-b")).not.toBeNull();
  });

  it("on the next sign-in or refresh, drops the copies of orgs the account left or that forbid offline copies", async () => {
    const org = (id: string, offlineAllowed = true) => ({ id, name: id, slug: id, role: "member" as const, isDefault: false, policies: { offlineAllowed } });
    await saveAccount(sara, material, [org("org-a"), org("org-b"), org("org-c")]);
    for (const k of ["-", "org-a", "org-b", "org-c"]) await saveSync("u1", k, sync(1));
    // Removed from org-b; org-c switched offline copies off.
    await saveAccount(sara, material, [org("org-a"), org("org-c", false)]);
    expect(await loadSync("u1", "-")).not.toBeNull();
    expect(await loadSync("u1", "org-a")).not.toBeNull();
    expect(await loadSync("u1", "org-b")).toBeNull();
    expect(await loadSync("u1", "org-c")).toBeNull();
  });

  it("tells an unreachable server from a refusal", () => {
    expect(isUnreachable(new TypeError("Failed to fetch"))).toBe(true);
    expect(isUnreachable(new ApiError(503, "server_error", null))).toBe(true);
    expect(isUnreachable(new ApiError(401, "session_expired", null))).toBe(false);
    expect(isUnreachable(new ApiError(500, "server_error", null))).toBe(false);
  });
});
