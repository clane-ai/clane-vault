import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { deriveLoginKeys } from "@clane-vault/crypto";
import { makeTestApp, resetDb, createActiveUser, freshTotp, orgHeader } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

type U = Awaited<ReturnType<typeof createActiveUser>>;
/** Signs in as the browser extension: the refresh token comes back in the body, no cookie. */
async function extLogin(u: U) {
  const { authKey } = await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams);
  return t.app.inject({ method: "POST", url: "/api/v1/auth/login", headers: { "user-agent": "Mozilla/5.0 Chrome" }, payload: { email: u.email, authKey, code: await freshTotp(u.totpSecret), client: "extension" } });
}
const refresh = (refreshToken: string) => t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", payload: { refreshToken } });

describe("browser extension sessions", () => {
  it("login with client=extension returns the refresh token in the body and sets no cookie", async () => {
    const u = await createActiveUser(t);
    const res = await extLogin(u);
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.refreshToken).toMatch(/^[0-9a-f-]{36}\.[A-Za-z0-9_-]+$/);
    expect(body.accessToken).toBeTruthy();
    expect(body.material.kdfSalt).toBe(u.material.kdfSalt);
    expect(res.cookies.find((c) => c.name === "cv_refresh")).toBeUndefined();
    const s = await t.prisma.session.findUniqueOrThrow({ where: { id: body.refreshToken.split(".")[0] } });
    expect(s.userAgent).toBe("Browser extension");
  });

  it("a normal login still uses the cookie and never returns the token", async () => {
    const u = await createActiveUser(t);
    const { authKey } = await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams);
    const res = await t.app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { email: u.email, authKey, code: await freshTotp(u.totpSecret) } });
    expect(res.json().refreshToken).toBeUndefined();
    expect(res.cookies.find((c) => c.name === "cv_refresh")).toBeDefined();
  });

  it("refresh from the body rotates the token; reuse after the grace window revokes the session", async () => {
    const u = await createActiveUser(t);
    const first = (await extLogin(u)).json().refreshToken as string;
    const r1 = await refresh(first);
    expect(r1.statusCode).toBe(200);
    const next = r1.json().refreshToken as string;
    expect(next).toBeTruthy();
    expect(next).not.toBe(first);
    expect(r1.cookies.find((c) => c.name === "cv_refresh")).toBeUndefined();
    const me = await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${r1.json().accessToken}`, ...orgHeader(u) } });
    expect(me.statusCode).toBe(200);
    // Within the grace window the previous token still answers (a lost response), without handing out a new one.
    const grace = await refresh(first);
    expect(grace.statusCode).toBe(200);
    expect(grace.json().refreshToken).toBeUndefined();
    await t.prisma.session.updateMany({ data: { rotatedAt: new Date(Date.now() - 60_000) } });
    expect((await refresh(first)).statusCode).toBe(401);
    expect((await refresh(next)).statusCode).toBe(401); // the whole session is gone
    expect(await t.prisma.event.count({ where: { action: "auth.refresh_reuse" } })).toBe(1);
  });

  it("concurrent body refreshes with the same token both succeed (compare-and-swap)", async () => {
    const u = await createActiveUser(t);
    const tok = (await extLogin(u)).json().refreshToken as string;
    const [a, b] = await Promise.all([refresh(tok), refresh(tok)]);
    expect([a.statusCode, b.statusCode]).toEqual([200, 200]);
    const fresh = [a, b].map((r) => r.json().refreshToken as string | undefined).filter(Boolean);
    expect(fresh).toHaveLength(1);
    expect((await refresh(fresh[0]!)).statusCode).toBe(200);
  });

  it("a cookie session's token is not accepted from the body", async () => {
    const u = await createActiveUser(t);
    const tok = decodeURIComponent(u.cookie.slice("cv_refresh=".length));
    expect((await refresh(tok)).statusCode).toBe(401);
    // and the cookie session is untouched
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } })).statusCode).toBe(200);
  });

  it("logout takes the token from the body and revokes the session", async () => {
    const u = await createActiveUser(t);
    const login = (await extLogin(u)).json();
    const out = await t.app.inject({ method: "POST", url: "/api/v1/auth/logout", payload: { refreshToken: login.refreshToken } });
    expect(out.statusCode).toBe(204);
    expect((await refresh(login.refreshToken)).statusCode).toBe(401);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${login.accessToken}`, ...orgHeader(u) } })).statusCode).toBe(401);
  });

  it("logout needs the token's secret, not just the session id", async () => {
    const u = await createActiveUser(t);
    const login = (await extLogin(u)).json();
    const sid = (login.refreshToken as string).split(".")[0];
    const out = await t.app.inject({ method: "POST", url: "/api/v1/auth/logout", payload: { refreshToken: `${sid}.not-the-secret` } });
    expect(out.statusCode).toBe(204);
    expect((await t.prisma.session.findUniqueOrThrow({ where: { id: sid } })).revokedAt).toBeNull();
    // same for a forged cookie
    await t.app.inject({ method: "POST", url: "/api/v1/auth/logout", headers: { cookie: `cv_refresh=${sid}.forged` } });
    expect((await t.prisma.session.findUniqueOrThrow({ where: { id: sid } })).revokedAt).toBeNull();
    expect((await refresh(login.refreshToken)).statusCode).toBe(200);
  });

  it("rejects malformed body tokens and unknown clients", async () => {
    const u = await createActiveUser(t);
    expect((await refresh("nope")).statusCode).toBe(401);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", payload: { refreshToken: 5 } })).statusCode).toBe(400);
    const { authKey } = await deriveLoginKeys(u.password, u.material.kdfSalt, u.material.kdfParams);
    const bad = await t.app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { email: u.email, authKey, code: await freshTotp(u.totpSecret), client: "mobile" } });
    expect(bad.statusCode).toBe(400);
  });
});
