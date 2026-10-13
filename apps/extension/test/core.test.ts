import { beforeEach, describe, expect, it } from "vitest";
import { createCore, type Core } from "../src/background/core";
import type { ItemView, StateView } from "../src/shared/messages";
import { EMAIL, ORG, ORG2, PASSWORD, fakeApi, fakePlatform } from "./fakeApi";

type Api = Awaited<ReturnType<typeof fakeApi>>;
let api: Api, env: ReturnType<typeof fakePlatform>, core: Core;
const TAB = 7, HTTP_TAB = 8, OTHER_TAB = 9, NEWTAB = 10;
const state = () => core.onPopup({ type: "state" }) as Promise<StateView>;
const items = async (pageUrl?: string) => ((await core.onPopup({ type: "items", pageUrl })) as { items: ItemView[] }).items;
const content = (m: Parameters<Core["onContent"]>[0], url = "https://accounts.example.com/login", frameId = 0, tabId = TAB) => core.onContent(m, { tabId, frameId, url });

async function signedIn() {
  await core.onPopup({ type: "setServer", url: "https://vault.test" });
  expect(await core.onPopup({ type: "signIn", email: EMAIL, password: PASSWORD, code: "123456" })).toEqual({ ok: true });
}

beforeEach(async () => {
  api = await fakeApi();
  env = fakePlatform(api.fetch, { [TAB]: "https://accounts.example.com/login", [HTTP_TAB]: "http://example.com/", [OTHER_TAB]: "https://evil.test/", [NEWTAB]: "chrome://newtab/" });
  core = createCore(env.p);
});

describe("set-up and sign-in", () => {
  it("starts in setup, accepts only https or local http servers", async () => {
    expect((await state()).phase).toBe("setup");
    expect(await core.onPopup({ type: "setServer", url: "http://vault.example.com" })).toEqual({ ok: false, error: "bad_url" });
    expect(await core.onPopup({ type: "setServer", url: "http://localhost:5173/" })).toEqual({ ok: true, serverUrl: "http://localhost:5173" });
    expect((await state()).phase).toBe("signed_out");
  });

  it("works with a server under a path: API at ${server}/api/v1, web vault link to ${server}/", async () => {
    expect(await core.onPopup({ type: "setServer", url: "https://vault.test/vault/" })).toEqual({ ok: true, serverUrl: "https://vault.test/vault" });
    expect(await core.onPopup({ type: "signIn", email: EMAIL, password: PASSWORD, code: "123456" })).toEqual({ ok: true });
    expect(await state()).toMatchObject({ phase: "unlocked", serverUrl: "https://vault.test/vault", webVaultUrl: "https://vault.test/vault/" });
    expect(api.s.calls.length).toBeGreaterThan(0);
    expect(api.s.calls.every((c) => c.url.startsWith("https://vault.test/vault/api/v1/"))).toBe(true);
  });

  it("asks for the authenticator code, then signs in with the extension client", async () => {
    await core.onPopup({ type: "setServer", url: "https://vault.test" });
    expect(await core.onPopup({ type: "signIn", email: EMAIL, password: PASSWORD })).toEqual({ ok: false, error: "totp_required" });
    expect(await core.onPopup({ type: "signIn", email: EMAIL, password: "wrong", code: "123456" })).toEqual({ ok: false, error: "invalid_credentials" });
    expect(await core.onPopup({ type: "signIn", email: ` ${EMAIL.toUpperCase()} `, password: PASSWORD, code: "123456" })).toEqual({ ok: true });
    const s = await state();
    // A new device opens the Personal space (no org).
    expect(s).toMatchObject({ phase: "unlocked", orgId: null, lastEmail: EMAIL, user: { email: EMAIL } });
    expect(api.s.calls.find((c) => c.path === "/auth/login")!.body).toMatchObject({ client: "extension" });
  });

  it("keeps keys and tokens out of storage.local", async () => {
    await signedIn();
    const local = JSON.stringify([...env.p.local.data.entries()]);
    expect(local).not.toMatch(/userKey|privateKey|refreshToken|accessToken/);
    expect(env.p.session.data.get("keys")).toBeDefined();
    expect((env.p.session.data.get("auth") as { refreshToken: string }).refreshToken).toBe(api.s.refresh);
  });

  it("survives a service-worker restart from storage.session", async () => {
    await signedIn();
    core = createCore(env.p);
    expect((await state()).phase).toBe("unlocked");
  });

  it("sign-out revokes the session on the server and forgets it", async () => {
    await signedIn();
    const refresh = api.s.refresh;
    expect((await core.onPopup({ type: "signOut" }) as StateView).phase).toBe("signed_out");
    expect(api.s.calls.find((c) => c.path === "/auth/logout")!.body).toEqual({ refreshToken: refresh });
    expect(env.p.session.data.has("auth")).toBe(false);
    expect(env.p.session.data.has("keys")).toBe(false);
  });
});

describe("auto-lock", () => {
  it("locks after the idle time and unlocks with the master password", async () => {
    await signedIn();
    expect(env.alarms.at(-1)).toBe(15);
    env.clock.t += 14 * 60_000;
    await core.onAlarm();
    expect((await state()).phase).toBe("unlocked");
    env.clock.t += 16 * 60_000;
    await core.onAlarm();
    expect((await state()).phase).toBe("locked");
    expect(env.p.session.data.has("keys")).toBe(false);
    expect(await core.onPopup({ type: "items" })).toEqual({ error: "locked" });
    expect(await core.onPopup({ type: "unlock", password: "nope" })).toEqual({ ok: false, error: "wrong_password" });
    expect(await core.onPopup({ type: "unlock", password: PASSWORD })).toEqual({ ok: true });
  });

  it("locks on wake-up when the worker slept past the idle time", async () => {
    await signedIn();
    env.clock.t += 20 * 60_000;
    core = createCore(env.p);
    expect((await state()).phase).toBe("locked");
  });

  it("honours a configured idle time and the lock button", async () => {
    await signedIn();
    await core.onPopup({ type: "settings", autoLockMinutes: 5 });
    env.clock.t += 6 * 60_000;
    await core.onAlarm();
    expect((await state()).phase).toBe("locked");
    await core.onPopup({ type: "unlock", password: PASSWORD });
    expect((await core.onPopup({ type: "lock" }) as StateView).phase).toBe("locked");
  });

  it("an org policy shortens the idle time", async () => {
    api.orgs[1]!.policies = { autoLockMinutes: 3, extensionAllowed: true };
    await signedIn();
    expect(await state()).toMatchObject({ autoLockMinutes: 3, autoLockPolicy: 3 });
    expect(env.alarms.at(-1)).toBe(3);
    env.clock.t += 4 * 60_000;
    await core.onAlarm();
    expect((await state()).phase).toBe("locked");
  });

  it("locks when the system locks", async () => {
    await signedIn();
    await core.onSystemLocked();
    expect((await state()).phase).toBe("locked");
  });
});

describe("items, copy and fill", () => {
  let site: string, other: string, useOnly: string;
  beforeEach(async () => {
    other = await api.add({ type: "login", title: "Zeta", username: "z", password: "pz", url: "https://zeta.test" });
    site = await api.add({ type: "login", title: "Example", username: "ana", password: "p1", url: "https://example.com", totpSecret: "JBSWY3DPEHPK3PXP" });
    useOnly = await api.add({ type: "login", title: "Shared", username: "team", password: "secret", url: "https://accounts.example.com" }, { permission: "use", ownerId: "u-2" });
    await api.add({ type: "note", title: "A note", notes: "n" });
    await signedIn();
  });

  it("lists logins with the current site first and no secrets", async () => {
    const list = await items("https://accounts.example.com/login");
    expect(list.map((i) => [i.title, i.match])).toEqual([["Shared", "exact"], ["Example", "site"], ["Zeta", "none"]]);
    expect(JSON.stringify(list)).not.toMatch(/p1|secret|JBSWY3/);
    expect(list.find((i) => i.id === site)).toMatchObject({ hasPassword: true, hasTotp: true, username: "ana", permission: "owner" });
  });

  it("never lists, copies or fills the new record types (cards, servers, ...): logins only", async () => {
    const card = await api.add({ type: "card", title: "Company Visa", data: { cardholder: "Ana", number: "4242424242424242", expiry: "12/29", cvv: "123" } });
    const srv = await api.add({ type: "server", title: "Build box", username: "root", password: "srv-pw", data: { hostname: "accounts.example.com", port: "22" } });
    await api.add({ type: "sshKey", title: "Deploy key", username: "git", data: { host: "example.com", privateKey: "-----BEGIN KEY-----" } });
    const list = await items("https://accounts.example.com/login");
    expect(list.map((i) => i.title)).toEqual(["Shared", "Example", "Zeta"]);
    expect(JSON.stringify(list)).not.toMatch(/4242|srv-pw|Visa|Build box/);
    for (const id of [card, srv]) {
      expect(await core.onPopup({ type: "copy", id, field: "password" })).toMatchObject({ error: "not_found" });
      expect(await core.onPopup({ type: "fill", id, tabId: TAB })).toMatchObject({ error: "not_found" });
    }
    expect(env.fills).toEqual([]);
  });

  it("copies username, password and TOTP; use-only items never give out the password", async () => {
    expect(await core.onPopup({ type: "copy", id: site, field: "password" })).toEqual({ value: "p1" });
    const t = await core.onPopup({ type: "copy", id: site, field: "totp" }) as { value: string; secondsLeft: number };
    expect(t.value).toMatch(/^\d{6}$/);
    expect(t.secondsLeft).toBeGreaterThan(0);
    expect(await core.onPopup({ type: "copy", id: useOnly, field: "username" })).toEqual({ value: "team" });
    expect(await core.onPopup({ type: "copy", id: useOnly, field: "password" })).toEqual({ error: "use_only" });
    expect(await core.onPopup({ type: "copy", id: useOnly, field: "totp" })).toEqual({ error: "use_only" });
    await core.onPopup({ type: "copied" });
    expect(env.clipboardClears()).toBe(1);
  });

  it("fills a matching page, use-only items included", async () => {
    expect(await core.onPopup({ type: "fill", id: site, tabId: TAB })).toEqual({ ok: true });
    expect(await core.onPopup({ type: "fill", id: useOnly, tabId: TAB })).toEqual({ ok: true });
    expect(env.fills).toEqual([
      { tabId: TAB, origin: "https://accounts.example.com", username: "ana", password: "p1" },
      { tabId: TAB, origin: "https://accounts.example.com", username: "team", password: "secret" },
    ]);
  });

  it("needs an explicit confirmation on another site or a plain http page", async () => {
    expect(await core.onPopup({ type: "fill", id: other, tabId: TAB })).toEqual({ ok: false, confirm: "mismatch", pageHost: "accounts.example.com", pageOrigin: "https://accounts.example.com", itemHost: "zeta.test" });
    expect(await core.onPopup({ type: "fill", id: other, tabId: TAB, confirm: "insecure" })).toMatchObject({ ok: false, confirm: "mismatch" });
    expect(await core.onPopup({ type: "fill", id: site, tabId: HTTP_TAB })).toMatchObject({ ok: false, confirm: "insecure" });
    expect(await core.onPopup({ type: "fill", id: other, tabId: HTTP_TAB })).toMatchObject({ ok: false, confirm: "both" });
    expect(env.fills).toHaveLength(0);
    expect(await core.onPopup({ type: "fill", id: other, tabId: OTHER_TAB, confirm: "mismatch", origin: "https://evil.test" })).toEqual({ ok: true });
    expect(await core.onPopup({ type: "fill", id: site, tabId: NEWTAB })).toEqual({ ok: false, error: "unsupported_page" });
  });

  it("binds 'Fill anyway' to the page origin the user was shown", async () => {
    // no origin, or the origin of a page the tab has since left: ask again, fill nothing
    expect(await core.onPopup({ type: "fill", id: other, tabId: OTHER_TAB, confirm: "mismatch" })).toMatchObject({ ok: false, confirm: "mismatch", pageOrigin: "https://evil.test" });
    env.tabs[OTHER_TAB] = "https://evil2.test/";
    expect(await core.onPopup({ type: "fill", id: other, tabId: OTHER_TAB, confirm: "mismatch", origin: "https://evil.test" })).toMatchObject({ ok: false, confirm: "mismatch", pageOrigin: "https://evil2.test" });
    expect(env.fills).toHaveLength(0);
  });

  it("never fills a use-only item into another site, even when confirmed", async () => {
    expect(await core.onPopup({ type: "fill", id: useOnly, tabId: OTHER_TAB })).toEqual({ ok: false, error: "use_only_mismatch" });
    expect(await core.onPopup({ type: "fill", id: useOnly, tabId: OTHER_TAB, confirm: "mismatch", origin: "https://evil.test" })).toEqual({ ok: false, error: "use_only_mismatch" });
    expect(env.fills).toHaveLength(0);
  });

  it("treats about:, data:, blob: and file: tabs as unfillable", async () => {
    for (const url of ["about:blank", "data:text/html,<input type=password>", "blob:https://example.com/0b7e", "file:///C:/x.html", "view-source:https://example.com/"]) {
      env.tabs[OTHER_TAB] = url;
      expect(await core.onPopup({ type: "fill", id: site, tabId: OTHER_TAB, confirm: "mismatch", origin: "https://example.com" })).toEqual({ ok: false, error: "unsupported_page" });
    }
    expect(env.fills).toHaveLength(0);
  });

  it("shows nothing from an org that turned the extension off", async () => {
    api.orgs[0]!.policies = { extensionAllowed: false };
    await core.onPopup({ type: "signOut" });
    await signedIn();
    await core.onPopup({ type: "switchOrg", orgId: ORG });
    const before = api.s.calls.filter((c) => c.path === "/sync").length;
    expect(await core.onPopup({ type: "items" })).toEqual({ error: "extension_disabled", blocked: "extension_disabled" });
    expect(api.s.calls.filter((c) => c.path === "/sync").length).toBe(before);
    await core.onPopup({ type: "switchOrg", orgId: null });
    expect((await items()).length).toBe(3);
  });

  it("switches org and reports an org that requires SSO", async () => {
    api.s.ssoOrg = ORG2;
    expect((await core.onPopup({ type: "switchOrg", orgId: ORG2 }) as StateView).orgId).toBe(ORG2);
    expect(await core.onPopup({ type: "items" })).toEqual({ error: "sso_required", blocked: "sso_required" });
    expect((await state()).blocked).toBe("sso_required");
    expect(await core.onPopup({ type: "switchOrg", orgId: "33333333-3333-4333-8333-333333333333" })).toEqual({ error: "org_forbidden" });
    // An org's space shows that org's items only (none of my private ones), asked with ?space=org.
    await core.onPopup({ type: "switchOrg", orgId: ORG });
    expect((await items()).length).toBe(0);
    const last = api.s.calls.filter((c) => c.path === "/sync").at(-1)!;
    expect(last.headers["x-org-id"]).toBe(ORG);
    expect(last.search).toBe("?space=org");
    // Personal: no X-Org-Id, private items only; remembered for next time.
    await core.onPopup({ type: "switchOrg", orgId: null });
    expect((await items()).length).toBe(3);
    expect(api.s.calls.filter((c) => c.path === "/sync").at(-1)!.headers["x-org-id"]).toBeUndefined();
    expect((await state()).orgId).toBeNull();
  });

  it("saves a new login to Personal whatever space the popup shows", async () => {
    await core.onPopup({ type: "switchOrg", orgId: ORG });
    await core.onPopup({ type: "settings", saveOffers: true });
    env.tabs[1] = "https://new-site.test/login";
    const offer = await core.onContent({ type: "login.submitted", username: "ana", password: "brand-new" }, { tabId: 1, frameId: 0, url: "https://new-site.test/login" });
    expect(offer).toMatchObject({ kind: "save" });
    expect(await core.onContent({ type: "prompt.answer", action: "save" }, { tabId: 1, frameId: 0, url: "https://new-site.test/login" })).toEqual({ ok: true });
    const post = api.s.calls.filter((c) => c.path === "/records" && c.method === "POST").at(-1)!;
    expect(post.headers["x-org-id"]).toBeUndefined();
  });
});

describe("token refresh", () => {
  it("refreshes an expired access token with the body token and keeps the rotated one", async () => {
    await signedIn();
    const before = api.s.refresh;
    api.s.access = "server-forgot"; // the access token expired
    api.s.refresh = before;
    await items();
    const auth = env.p.session.data.get("auth") as { refreshToken: string; accessToken: string };
    expect(api.s.calls.find((c) => c.path === "/auth/refresh")!.body).toEqual({ refreshToken: before });
    expect(auth.refreshToken).toBe(api.s.refresh);
    expect(auth.refreshToken).not.toBe(before);
  });

  it("refreshes once for concurrent requests", async () => {
    await signedIn();
    api.s.access = "expired";
    await Promise.all([core.onPopup({ type: "stepUp", code: "123456" }), core.onPopup({ type: "stepUp", code: "123456" }), core.onPopup({ type: "items" })]);
    expect(api.s.calls.filter((c) => c.path === "/auth/refresh")).toHaveLength(1);
  });

  it("a refused refresh ends the session", async () => {
    await signedIn();
    api.s.access = "expired"; api.s.refresh = "revoked-elsewhere";
    expect(await core.onPopup({ type: "items" })).toMatchObject({ error: "session_expired" });
    expect((await state()).phase).toBe("signed_out");
  });
});

describe("save and update offers", () => {
  const submit = (username: string, password: string, url?: string, frameId?: number, tabId?: number) => content({ type: "login.submitted", username, password }, url, frameId, tabId);
  beforeEach(async () => {
    await signedIn();
    await core.onPopup({ type: "settings", saveOffers: true });
  });

  it("offers to save a new login and stores it encrypted in the private vault", async () => {
    expect(await submit("ana", "n3w")).toEqual({ kind: "save", host: "accounts.example.com", username: "ana" });
    // after the redirect, the next page of the same site asks again
    expect(await content({ type: "prompt.pending" }, "https://www.example.com/home")).toEqual({ kind: "save", host: "accounts.example.com", username: "ana" });
    expect(await content({ type: "prompt.pending" }, "https://evil.test/")).toBeNull();
    expect(await content({ type: "prompt.answer", action: "save" }, "https://www.example.com/home")).toEqual({ ok: true });
    const post = api.s.calls.find((c) => c.path === "/records" && c.method === "POST")!;
    expect(post.body).toMatchObject({ folderId: null, type: "login" });
    expect(JSON.stringify(post.body)).not.toContain("n3w");
    const id = (post.body as { id: string }).id;
    expect(await api.bodyOf(id)).toEqual({ v: 2, type: "login", title: "accounts.example.com", username: "ana", password: "n3w", url: "https://accounts.example.com" });
    expect(await content({ type: "prompt.pending" })).toBeNull();
  });

  it("offers an update when the password changed, nothing when it didn't", async () => {
    const id = await api.add({ type: "login", title: "Example", username: "ana", password: "old", url: "https://example.com" });
    await core.onPopup({ type: "items" });
    expect(await submit("ana", "old")).toBeNull();
    env.clock.t += 60_000;
    expect(await submit("ANA", "new")).toEqual({ kind: "update", host: "accounts.example.com", username: "ANA" });
    expect(await content({ type: "prompt.answer", action: "update" })).toEqual({ ok: true });
    expect((await api.bodyOf(id)).password).toBe("new");
  });

  it("updating a password keeps a v2 login's custom fields", async () => {
    const id = await api.add({ type: "login", title: "Example", username: "ana", password: "old", url: "https://example.com",
      fields: [{ id: "f1", label: "Account ID", kind: "text", value: "8812" }, { id: "f2", label: "Recovery codes", kind: "hiddenMultiline", value: "a1\nb2" }] });
    await core.onPopup({ type: "items" });
    env.clock.t += 60_000;
    expect(await submit("ana", "new")).toEqual({ kind: "update", host: "accounts.example.com", username: "ana" });
    expect(await content({ type: "prompt.answer", action: "update" })).toEqual({ ok: true });
    const b = await api.bodyOf(id);
    expect(b).toMatchObject({ v: 2, type: "login", password: "new", fields: [{ id: "f1", label: "Account ID", kind: "text", value: "8812" }, { id: "f2", label: "Recovery codes", kind: "hiddenMultiline", value: "a1\nb2" }] });
    expect(api.s.calls.find((c) => c.method === "PUT")?.body).toMatchObject({ type: "login" });
  });

  it("never offers to change an item I can't edit", async () => {
    await api.add({ type: "login", title: "Team", username: "team", password: "old", url: "https://example.com" }, { permission: "view", ownerId: "u-2" });
    expect(await submit("team", "new")).toBeNull();
  });

  it("remembers 'Never for this site'", async () => {
    await submit("ana", "pw");
    expect(await content({ type: "prompt.answer", action: "never" })).toEqual({ ok: true });
    expect(await submit("ana", "pw2", "https://login.example.com/")).toBeNull();
    expect(await submit("ana", "pw2", "https://other.test/")).toMatchObject({ kind: "save" });
  });

  it("ignores frames, disabled offers and a locked vault", async () => {
    expect(await submit("ana", "pw", undefined, 3)).toBeNull();
    await core.onPopup({ type: "settings", saveOffers: false });
    expect(await submit("ana", "pw")).toBeNull();
    await core.onPopup({ type: "settings", saveOffers: true });
    await core.onPopup({ type: "lock" });
    expect(await submit("ana", "pw")).toBeNull();
  });

  it("limits how fast a page can test logins (no guessing oracle)", async () => {
    await api.add({ type: "login", title: "Example", username: "ana", password: "right", url: "https://example.com" });
    for (let i = 0; i < 5; i++) expect(await submit("ana", `guess${i}`)).toMatchObject({ kind: "update" });
    // the right password would answer null too, so after the limit every answer is null whatever the guess
    expect(await submit("ana", "guess5")).toBeNull();
    expect(await submit("ana", "guess6", undefined, 0, OTHER_TAB)).toMatchObject({ kind: "update" });
    env.clock.t += 61_000;
    expect(await submit("ana", "guess7")).toMatchObject({ kind: "update" });
  });

  it("never offers to save the vault's own sign-in (the master password)", async () => {
    expect(await submit("me@example.com", "master", "https://vault.test/login")).toBeNull();
    expect(env.p.session.data.get("pending")).toBeUndefined();
  });

  it("content messages respect the idle lock even when the alarm didn't fire", async () => {
    env.clock.t += 16 * 60_000;
    expect(await submit("ana", "pw")).toBeNull();
    expect((await state()).phase).toBe("locked");
  });

  it("a page can't answer for another tab, and pending offers expire", async () => {
    await submit("ana", "pw");
    expect(await content({ type: "prompt.answer", action: "save" }, undefined, 0, 99)).toEqual({ ok: false, error: "nothing_pending" });
    env.clock.t += 6 * 60_000;
    await core.onPopup({ type: "state" });
    expect(await content({ type: "prompt.pending" })).toBeNull();
  });
});

describe("per-org key pairs", () => {
  it("opens team folders and shares sealed to my membership key in that org, and only there", async () => {
    const shared = await api.addOrgShare({ type: "login", title: "Org share", username: "o", password: "org-pw", url: "https://org.test" }, ORG);
    const team = await api.addTeamRecord({ type: "login", title: "Team login", username: "t", password: "team-pw", url: "https://team.test" }, ORG);
    await signedIn();
    // Personal never shows them; their org does.
    expect((await items()).map((i) => i.title)).not.toContain("Org share");
    await core.onPopup({ type: "switchOrg", orgId: ORG });
    expect(await core.onPopup({ type: "copy", id: shared, field: "password" })).toEqual({ value: "org-pw" });
    expect(await core.onPopup({ type: "copy", id: team, field: "password" })).toEqual({ value: "team-pw" });
    // In another org these aren't served, and my key from the first org is never used there.
    await core.onPopup({ type: "switchOrg", orgId: ORG2 });
    expect((await items()).map((i) => i.title)).not.toContain("Org share");
  });
});
