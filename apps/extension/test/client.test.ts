import { describe, expect, it, vi } from "vitest";
import { ApiError, createClient, type Tokens } from "../src/background/client";

const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function setup(respond: (path: string, init: RequestInit) => Response | Promise<Response>, server = "https://vault.test") {
  let tokens: Tokens = { accessToken: "a1", refreshToken: "r1" };
  const calls: { path: string; init: RequestInit }[] = [];
  const ended = vi.fn(async () => { tokens = { accessToken: null, refreshToken: null }; });
  const client = createClient({
    serverUrl: () => server,
    tokens: () => tokens,
    saveTokens: async (t) => { tokens = { ...tokens, ...t }; },
    sessionEnded: ended,
    fetch: (async (u: string | URL | Request, init?: RequestInit) => { const path = new URL(String(u)).pathname; calls.push({ path, init: init! }); return respond(path, init!); }) as typeof fetch,
  });
  return { client, calls, ended, tokens: () => tokens };
}

describe("extension API client", () => {
  it("calls ${server}/api/v1 when the server is under a path (https://host/vault)", async () => {
    const t = setup((path) => (path === "/vault/api/v1/auth/refresh" ? json(200, { accessToken: "a2", refreshToken: "r2" }) : json(t.calls.length > 1 ? 200 : 401, { ok: 1 })), "https://northwind.example.com/vault");
    expect(await t.client.get("/sync")).toEqual({ ok: 1 });
    expect(t.calls.map((c) => c.path)).toEqual(["/vault/api/v1/sync", "/vault/api/v1/auth/refresh", "/vault/api/v1/sync"]);
  });

  it("sends the bearer token and org header, never cookies", async () => {
    const t = setup(() => json(200, { ok: 1 }));
    await t.client.get("/sync", "org-1");
    const { init } = t.calls[0]!;
    expect(init.credentials).toBe("omit");
    expect(init.headers).toMatchObject({ authorization: "Bearer a1", "x-org-id": "org-1" });
  });

  it("on 401 refreshes with the body token (no bearer), stores the rotation and retries", async () => {
    let n = 0;
    const t = setup((path, init) => {
      if (path === "/api/v1/auth/refresh") return json(200, { accessToken: "a2", refreshToken: "r2" });
      return (init.headers as Record<string, string>).authorization === "Bearer a2" ? json(200, { n: ++n }) : json(401, { error: "unauthorized" });
    });
    expect(await t.client.get("/sync")).toEqual({ n: 1 });
    const r = t.calls.find((c) => c.path === "/api/v1/auth/refresh")!;
    expect(JSON.parse(String(r.init.body))).toEqual({ refreshToken: "r1" });
    expect((r.init.headers as Record<string, string>).authorization).toBeUndefined();
    expect(t.tokens()).toEqual({ accessToken: "a2", refreshToken: "r2" });
  });

  it("keeps its refresh token when a grace-window answer brings none", async () => {
    const t = setup((path) => (path === "/api/v1/auth/refresh" ? json(200, { accessToken: "a2" }) : json(200, {})));
    expect(await t.client.refresh()).toBe(true);
    expect(t.tokens()).toEqual({ accessToken: "a2", refreshToken: "r1" });
  });

  it("ends the session only when the server refuses the refresh token", async () => {
    const down = setup((path) => (path === "/api/v1/auth/refresh" ? json(503, {}) : json(401, {})));
    await expect(down.client.get("/sync")).rejects.toMatchObject({ code: "offline" });
    expect(down.ended).not.toHaveBeenCalled();
    const refused = setup(() => json(401, { error: "session_expired" }));
    await expect(refused.client.get("/sync")).rejects.toMatchObject({ code: "session_expired", status: 401 });
    expect(refused.ended).toHaveBeenCalledOnce();
  });

  it("does not refresh for auth routes and surfaces API errors", async () => {
    const t = setup(() => json(401, { error: "totp_required" }));
    const e = await t.client.post("/auth/login", {}).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).code).toBe("totp_required");
    expect(t.calls).toHaveLength(1);
  });

  it("logout sends the refresh token in the body and ignores network failures", async () => {
    const t = setup(() => { throw new TypeError("network"); });
    await expect(t.client.logout()).resolves.toBeUndefined();
    expect(JSON.parse(String(t.calls[0]!.init.body))).toEqual({ refreshToken: "r1" });
  });
});
