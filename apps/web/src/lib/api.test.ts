import { describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { api, ApiError } from "./api";

describe("api client", () => {
  it("sends the bearer token and parses JSON", async () => {
    server.use(http.get("/api/v1/me", ({ request }) => HttpResponse.json({ auth: request.headers.get("authorization") })));
    api.setAccessToken("abc");
    expect(await api.get("/me")).toEqual({ auth: "Bearer abc" });
  });

  it("refreshes once on 401 and retries", async () => {
    let calls = 0;
    server.use(
      http.get("/api/v1/sync", ({ request }) => (++calls, request.headers.get("authorization") === "Bearer new" ? HttpResponse.json({ ok: 1 }) : HttpResponse.json({ error: "unauthorized" }, { status: 401 }))),
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "new", user: {}, material: {} })),
    );
    api.setAccessToken("old");
    expect(await api.get("/sync")).toEqual({ ok: 1 });
    expect(calls).toBe(2);
  });

  it("ends the session when refresh fails", async () => {
    const ended = vi.fn();
    api.onSessionEnded(ended);
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })),
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ error: "session_expired" }, { status: 401 })),
    );
    await expect(api.get("/sync")).rejects.toMatchObject({ status: 401, code: "session_expired" });
    expect(ended).toHaveBeenCalledOnce();
  });

  it("maps error bodies to ApiError", async () => {
    server.use(http.put("/api/v1/records/x", () => HttpResponse.json({ error: "conflict", current: { revision: 3 } }, { status: 409 })));
    const err = await api.put("/records/x", {}).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 409, code: "conflict", body: { current: { revision: 3 } } });
  });
});
