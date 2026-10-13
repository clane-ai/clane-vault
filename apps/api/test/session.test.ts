import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { makeTestApp, resetDb, createActiveUser, orgHeader } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(() => resetDb(t.prisma));

describe("sessions", () => {
  it("guards /me", async () => {
    expect((await t.app.inject({ method: "GET", url: "/api/v1/me" })).statusCode).toBe(401);
    const u = await createActiveUser(t);
    const me = await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
    expect(me.json().user.email).toBe(u.email);
  });

  it("refreshes and rotates the cookie; the old cookie stops working", async () => {
    const u = await createActiveUser(t);
    const r1 = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } });
    expect(r1.statusCode).toBe(200);
    const next = r1.cookies.find((c) => c.name === "cv_refresh")!;
    expect(`cv_refresh=${next.value}`).not.toBe(u.cookie);
    // past the grace window, reuse of the old cookie is theft
    await t.prisma.session.updateMany({ data: { rotatedAt: new Date(Date.now() - 60_000) } });
    const reuse = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } });
    expect(reuse.statusCode).toBe(401);
    // reuse of an old token revokes the whole session (theft signal)
    const after = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: `cv_refresh=${next.value}` } });
    expect(after.statusCode).toBe(401);
  });

  it("logout revokes the session and its access token", async () => {
    const u = await createActiveUser(t);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/logout", headers: { cookie: u.cookie } })).statusCode).toBe(204);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } })).statusCode).toBe(401);
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } })).statusCode).toBe(401);
  });

  it("rejects a setup token on normal routes", async () => {
    const res = await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: "Bearer not-a-token" } });
    expect(res.statusCode).toBe(401);
  });

  it("concurrent refreshes with the same cookie both succeed and keep the session alive", async () => {
    const u = await createActiveUser(t);
    const req = () => t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: u.cookie } });
    const [a, b] = await Promise.all([req(), req()]);
    expect(a.statusCode).toBe(200);
    expect(b.statusCode).toBe(200);
    const c = [a, b].map((r) => r.cookies.find((x) => x.name === "cv_refresh")).find(Boolean)!;
    const next = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: `cv_refresh=${c.value}` } });
    expect(next.statusCode).toBe(200);
  });

  it("malformed refresh cookie yields 401/204, not 500", async () => {
    const r = await t.app.inject({ method: "POST", url: "/api/v1/auth/refresh", headers: { cookie: "cv_refresh=abc.def" } });
    expect(r.statusCode).toBe(401);
    expect(r.json().error).toBe("session_expired");
    expect((await t.app.inject({ method: "POST", url: "/api/v1/auth/logout", headers: { cookie: "cv_refresh=abc.def" } })).statusCode).toBe(204);
  });

  it("rejects access tokens of disabled users", async () => {
    const u = await createActiveUser(t);
    await t.prisma.user.update({ where: { email: u.email }, data: { status: "disabled" } });
    const me = await t.app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${u.accessToken}`, ...orgHeader(u) } });
    expect(me.statusCode).toBe(401);
  });
});
