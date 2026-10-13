import { afterAll, describe, expect, it } from "vitest";
import { makeTestApp } from "./helpers.js";

const t = await makeTestApp();
afterAll(() => t.app.close());

describe("health", () => {
  it("reports ok and database reachable", async () => {
    const res = await t.app.inject({ method: "GET", url: "/api/v1/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, db: true });
  });
  it("sets security headers", async () => {
    const res = await t.app.inject({ method: "GET", url: "/api/v1/health" });
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["cache-control"]).toBe("no-store");
  });
});
