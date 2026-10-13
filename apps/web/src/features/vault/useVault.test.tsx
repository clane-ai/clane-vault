import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { randomBytes, decryptRecord } from "@clane-vault/crypto";
import { server } from "@/test/server";
import { useVault, ConflictError } from "./useVault";
import * as sessionModule from "@/lib/session";
import { vi } from "vitest";

let syncCalls = 0;
let gen = 0;
const userKey = randomBytes(32);
vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1" }, generation: () => gen, keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

function wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{children}</QueryClientProvider>;
}

describe("useVault", () => {
  it("encrypts before upload and shows the new record after refetch", async () => {
    const store: Record<string, unknown>[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: store })),
      http.post("/api/v1/records", async ({ request }) => {
        const b = (await request.json()) as Record<string, string>;
        store.push({ ...b, revision: 1, updatedAt: "2026-10-04T10:00:00Z", deletedAt: null, permission: "owner", holderType: "user" });
        return HttpResponse.json({ id: b.id, revision: 1 }, { status: 201 });
      }),
    );
    const { result } = renderHook(() => useVault(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(() => result.current.createRecord({ folderId: null, body: { type: "login", title: "GitHub", password: "plain-secret" } }));
    expect(JSON.stringify(store)).not.toContain("plain-secret");
    const r = store[0] as { id: string; encBody: string; wrappedRecordKey: string };
    expect((await decryptRecord(r.id, r.encBody, r.wrappedRecordKey, userKey)).body.title).toBe("GitHub");
    await waitFor(() => expect(result.current.records.map((x) => x.body?.title)).toEqual(["GitHub"]));
    expect(store[0]).toMatchObject({ type: "login" });
  });

  it("tells the server only login or item: the real type stays encrypted", async () => {
    const posted: Record<string, string>[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.post("/api/v1/records", async ({ request }) => {
        const b = (await request.json()) as Record<string, string>;
        posted.push(b);
        return HttpResponse.json({ id: b.id, revision: 1 }, { status: 201 });
      }),
    );
    const { result } = renderHook(() => useVault(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(() => result.current.createRecord({ folderId: null, body: { type: "card", title: "Visa", data: { number: "4242424242424242" } } }));
    await act(() => result.current.createRecord({ folderId: null, body: { type: "note", title: "Note" } }));
    expect(posted.map((p) => p.type)).toEqual(["item", "item"]);
    expect(JSON.stringify(posted.map(({ encBody: _e, wrappedRecordKey: _w, ...meta }) => meta))).not.toMatch(/card|4242/);
  });

  it("raises ConflictError on 409", async () => {
    server.use(
      http.get("/api/v1/sync", () => { syncCalls++; return HttpResponse.json({ serverTime: "", folders: [], records: [] }); }),
      http.put("/api/v1/records/:id", () => HttpResponse.json({ error: "conflict", current: { revision: 5 } }, { status: 409 })),
    );
    const { result } = renderHook(() => useVault(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    const rec = { id: crypto.randomUUID(), folderId: null, type: "login" as const, body: { type: "login" as const, title: "x" }, revision: 1, updatedAt: "", deleted: false, permission: "owner" as const, recordKey: randomBytes(32) };
    syncCalls = 0;
    await expect(result.current.updateRecord(rec, { type: "login", title: "y" })).rejects.toBeInstanceOf(ConflictError);
    await waitFor(() => expect(syncCalls).toBeGreaterThan(0));
  });

  it("never uploads a record wrapped under a zeroed key when locked mid-flight", async () => {
    const posts: { id: string; encBody: string; wrappedRecordKey: string }[] = [];
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.post("/api/v1/records", async ({ request }) => { posts.push((await request.json()) as never); return HttpResponse.json({}, { status: 201 }); }),
    );
    const { result } = renderHook(() => useVault(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    const p = result.current.createRecord({ folderId: null, body: { type: "login", title: "Mid", password: "p" } }).catch((e: Error) => e);
    const original = userKey.slice();
    gen++; userKey.fill(0); // simulate lock()
    await p;
    for (const r of posts) expect((await decryptRecord(r.id, r.encBody, r.wrappedRecordKey, original)).body.title).toBe("Mid");
    userKey.set(original);
    gen = 0;
  });

  it("refuses to update with a zeroed record key", async () => {
    server.use(http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })));
    const { result } = renderHook(() => useVault(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    const rec = { id: crypto.randomUUID(), folderId: null, type: "login" as const, body: { type: "login" as const, title: "x" }, revision: 1, updatedAt: "", deleted: false, permission: "owner" as const, recordKey: new Uint8Array(32) };
    await expect(result.current.updateRecord(rec, { type: "login", title: "y" })).rejects.toThrow("Vault locked");
  });
});
