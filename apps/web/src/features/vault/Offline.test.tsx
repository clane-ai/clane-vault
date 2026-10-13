import "fake-indexeddb/auto";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { configureKdfFloor, createAccount, encryptNewRecord, type KdfParams } from "@clane-vault/crypto";
import { server } from "@/test/server";
import { chooseFromAccountMenu } from "@/test/nav";
import { AppRoutes } from "@/routes";
import { SessionProvider } from "@/lib/session";
import { loadCopy, loadSync, saveAccount, setOfflineEnabled, wipeOffline } from "@/lib/offline";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
const user = { id: "u1", email: "sara@clane.ai", name: "Sara" };
const PW = "offline pw";

async function fixture() {
  const acct = await createAccount(PW, FAST);
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title: "GitHub", username: "dev", password: "gh-pass" }, acct.keys.userKey);
  const sync = { serverTime: "", folders: [], records: [{ id, folderId: null, type: "login", encBody: enc.encBody, revision: 1, updatedAt: "2026-10-01T00:00:00.000Z", deletedAt: null, permission: "owner", wrappedRecordKey: enc.wrappedRecordKey, holderType: "user", ownerId: "u1" }] };
  return { acct, sync };
}
type Fx = Awaited<ReturnType<typeof fixture>>;
let syncCalls = 0;
const online = ({ acct, sync }: Fx) => server.use(
  http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material, orgs: [] })),
  http.get("/api/v1/sync", () => { syncCalls++; return HttpResponse.json(sync); }),
  http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
);
const offline = () => server.use(http.all("/api/v1/*", () => HttpResponse.error()));
const mount = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SessionProvider><MemoryRouter><AppRoutes /></MemoryRouter></SessionProvider></QueryClientProvider>);

/** Records sit in collapsed folder groups: switch to the flat list first. */
async function findRecord() {
  await userEvent.click(await screen.findByRole("button", { name: "List" }));
  return screen.findByText("GitHub");
}
async function unlock(label = "Unlock", pw = PW) {
  await userEvent.type(await screen.findByLabelText("Master password"), pw);
  await userEvent.click(screen.getByRole("button", { name: label }));
}

beforeEach(async () => { localStorage.clear(); setOfflineEnabled(true); await wipeOffline(); syncCalls = 0; });

describe("offline copy", () => {
  it("is saved online, unlocks offline read-only with a banner, and resumes online on reconnect", async () => {
    const fx = await fixture();
    online(fx);
    const first = mount();
    await unlock();
    expect(await findRecord()).toBeInTheDocument();
    await waitFor(async () => expect(await loadSync("u1", "-")).not.toBeNull());
    expect(JSON.stringify(await loadCopy())).not.toContain("gh-pass"); // ciphertext only
    first.unmount();

    offline();
    mount();
    expect(await screen.findByText(/You're offline/)).toBeInTheDocument();
    expect(screen.queryByText(/Forgot master password/)).not.toBeInTheDocument();
    await unlock("Unlock offline copy", "wrong password");
    expect(await screen.findByRole("alert")).toHaveTextContent("That master password is not right");
    await unlock("Unlock offline copy");
    expect(await screen.findByTestId("offline-banner")).toHaveTextContent("Offline — read only.");
    expect(await findRecord()).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New" })).toBeDisabled();
    await userEvent.click(screen.getByText("GitHub"));
    expect(await screen.findByRole("button", { name: /copy password/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Share" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Move to trash" })).not.toBeInTheDocument();
    expect(syncCalls).toBe(1);

    server.resetHandlers();
    online(fx);
    window.dispatchEvent(new Event("online"));
    await waitFor(() => expect(screen.queryByTestId("offline-banner")).not.toBeInTheDocument());
    // Online again: the vault reloads from the server and editing is back (the open record panel shows Edit).
    expect(await screen.findByRole("button", { name: "Edit" })).toBeInTheDocument();
    expect(syncCalls).toBe(2);
  });

  it("the offline copy opens every record type (a card, a server with custom fields)", async () => {
    const fx = await fixture();
    const cardId = crypto.randomUUID(), srvId = crypto.randomUUID();
    const card = await encryptNewRecord(cardId, { type: "card", title: "Company Visa", data: { cardholder: "Ada", number: "4242424242424242", cvv: "737" } }, fx.acct.keys.userKey);
    const srv = await encryptNewRecord(srvId, { type: "server", title: "Build box", username: "deploy", password: "pw", data: { hostname: "10.0.0.5" }, fields: [{ id: "a", label: "Rack", kind: "text", value: "R12" }] }, fx.acct.keys.userKey);
    const row = (id: ReturnType<typeof crypto.randomUUID>, e: typeof card) => ({ id, folderId: null, type: "item", encBody: e.encBody, revision: 1, updatedAt: "2026-10-01T00:00:00.000Z", deletedAt: null, permission: "owner", wrappedRecordKey: e.wrappedRecordKey, holderType: "user", ownerId: "u1" });
    fx.sync.records.push(row(cardId, card), row(srvId, srv));
    online(fx);
    const first = mount();
    await unlock();
    expect(await findRecord()).toBeInTheDocument();
    await waitFor(async () => expect(await loadSync("u1", "-")).not.toBeNull());
    expect(JSON.stringify(await loadCopy())).not.toContain("4242424242424242");
    first.unmount();

    offline();
    mount();
    await unlock("Unlock offline copy");
    await screen.findByTestId("offline-banner");
    await userEvent.click(await screen.findByRole("button", { name: "List" }));
    await userEvent.click(await screen.findByText("Company Visa"));
    expect(await screen.findByLabelText("Card number")).toHaveTextContent("•••• •••• •••• 4242");
    await userEvent.click(screen.getByText("Build box"));
    expect(await screen.findByLabelText("Hostname or IP")).toHaveTextContent("10.0.0.5");
    expect(screen.getByLabelText("Rack")).toHaveTextContent("R12");
  });

  it("signing out offline wipes the copy and ends the server session at the next start", async () => {
    const fx = await fixture();
    await saveAccount(user, fx.acct.material, []);
    offline();
    const a = mount();
    await unlock("Unlock offline copy");
    await screen.findByTestId("offline-banner");
    await chooseFromAccountMenu("Sign out");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(await loadCopy()).toBeNull();
    a.unmount();

    let loggedOut = 0;
    server.resetHandlers();
    online(fx);
    server.use(http.post("/api/v1/auth/logout", () => { loggedOut++; return new HttpResponse(null, { status: 204 }); }));
    mount();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(loggedOut).toBe(1);
  });

  it("a refused refresh (signed out or revoked elsewhere) wipes the copy", async () => {
    const fx = await fixture();
    await saveAccount(user, fx.acct.material, []);
    mount(); // default handler: 401 session_expired
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    await waitFor(async () => expect(await loadCopy()).toBeNull());
  });

  it("turning the setting off in Settings deletes the copy right away", async () => {
    const fx = await fixture();
    online(fx);
    mount();
    await unlock();
    await findRecord();
    await waitFor(async () => expect(await loadSync("u1", "-")).not.toBeNull());
    await chooseFromAccountMenu("Settings");
    await userEvent.click(await screen.findByRole("link", { name: "This device" }));
    await userEvent.click(await screen.findByRole("switch", { name: "Offline copy" }));
    expect(localStorage.getItem("cv.offline")).toBe("off");
    // Deleted from IndexedDB, not just hidden by the setting.
    await waitFor(async () => { setOfflineEnabled(true); expect(await loadCopy()).toBeNull(); });
  });

  it("an org whose policy forbids offline copies never gets its vault stored", async () => {
    const fx = await fixture();
    const acme = { id: "o1", name: "Acme", slug: "acme", role: "member", isDefault: true, policies: { offlineAllowed: false } };
    server.use(
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: fx.acct.material, orgs: [acme] })),
      http.get("/api/v1/sync", () => HttpResponse.json(fx.sync)),
      http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [acme], invitations: [], allowOrgCreation: true, instanceAdmin: false })),
    );
    mount();
    await unlock();
    await findRecord();
    await waitFor(async () => expect((await loadCopy())?.userId).toBe("u1"));
    await new Promise((r) => setTimeout(r, 50));
    expect(await loadSync("u1", "o1")).toBeNull();
  });

  it("keeps nothing when the device setting is off", async () => {
    setOfflineEnabled(false);
    const fx = await fixture();
    online(fx);
    const a = mount();
    await unlock();
    expect(await findRecord()).toBeInTheDocument();
    a.unmount();
    setOfflineEnabled(true);
    expect(await loadCopy()).toBeNull();
    offline();
    mount();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});

describe("offline copy with membership keys (per-org key pairs)", () => {
  it("keeps the membership key material with the org's sync, and opens membership-sealed team folders offline", async () => {
    const { createMembershipKeys, sealOrgFolderKey, encryptFolderName, randomBytes, wrapKey } = await import("@clane-vault/crypto");
    const ORG = { id: "0e0e0e0e-1111-4222-8333-444455556666", name: "Acme", slug: "acme", role: "member", isDefault: true };
    const acct = await createAccount(PW, FAST);
    const mk = await createMembershipKeys(acct.keys.userKey, { orgId: ORG.id, userId: "u1" });
    const fid = crypto.randomUUID(), rid = crypto.randomUUID(), fk = randomBytes(32);
    const enc = await encryptNewRecord(rid, { type: "login", title: "GitHub", username: "team", password: "team-pass" }, randomBytes(32));
    const sync = { serverTime: "", orgId: ORG.id, membershipKeys: [{ ...mk.material, state: "current" }],
      folders: [{ id: fid, kind: "team", encName: await encryptFolderName(fid, "Ops", fk), ownerId: "ana", deletedAt: null, myPermission: "view", members: [], groups: [],
        sealedTo: mk.material.publicKey, wrappedFolderKey: await sealOrgFolderKey(fk, { orgId: ORG.id, folderId: fid }, mk.keys.publicKey) }],
      records: [{ id: rid, folderId: fid, keyFolderId: fid, type: "login", encBody: enc.encBody, revision: 1, updatedAt: "2026-10-01T00:00:00.000Z", deletedAt: null, permission: "view",
        wrappedRecordKey: await wrapKey(enc.recordKey, fk, `record-key:${rid}`), holderType: "folder", ownerId: "ana", ownerName: "Ana" }] };
    server.use(
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material, orgs: [ORG] })),
      http.get("/api/v1/sync", ({ request }) => { syncCalls++; return request.headers.get("x-org-id") === ORG.id ? HttpResponse.json(sync) : HttpResponse.json({ error: "org_forbidden" }, { status: 403 }); }),
      http.get("/api/v1/records/:id/activity", () => HttpResponse.json({ events: [] })),
      http.get("/api/v1/membership-key", () => HttpResponse.json({ error: "unavailable" }, { status: 503 })),
      http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [ORG], invitations: [], allowOrgCreation: false, instanceAdmin: false })),
    );
    // The org's space was the last one used on this device (its offline copy is the org's own sync).
    localStorage.setItem("cv.org.u1", ORG.id);
    const first = mount();
    await unlock();
    expect(await findRecord()).toBeInTheDocument();
    await waitFor(async () => expect((await loadSync("u1", ORG.id))?.sync).toMatchObject({ membershipKeys: [{ publicKey: mk.material.publicKey }] }));
    expect(JSON.stringify(await loadCopy())).not.toContain("team-pass");
    first.unmount();

    offline();
    mount();
    await unlock("Unlock offline copy");
    expect(await screen.findByTestId("offline-banner")).toBeInTheDocument();
    expect(await findRecord()).toBeInTheDocument();
  });
});
