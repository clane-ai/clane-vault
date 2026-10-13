import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { decryptFolderName, decryptRecord, randomBytes } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import type { VaultFolder } from "@/features/vault/types";
import { ImportSheet } from "./ImportSheet";
import { retry } from "./useImport";

retry.delayMs = 10;

const userKey = randomBytes(32);
vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1", name: "Sara" }, generation: () => 0, keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

const records = Array.from({ length: 30 }, (_, i) => ({ title: `Site ${i}`, login: `user${i}`, password: `pw-${i}-secret`, folders: [{ folder: i < 27 ? "Design" : "Infra" }] }));
const keeper = JSON.stringify({ records: [...records, { title: "" , login: "x" }] });
const existing: VaultFolder[] = [{ id: crypto.randomUUID(), name: "Infra", kind: "private", deleted: false }];

describe("ImportSheet", () => {
  it("previews a Keeper export, then encrypts and uploads in batches of 25 into source folders", async () => {
    const folders: { id: string; encName: string }[] = [];
    const batches: { records: { id: string; folderId: string | null; encBody: string; wrappedRecordKey: string }[] }[] = [];
    server.use(
      http.post("/api/v1/folders", async ({ request }) => { folders.push(await request.json() as never); return HttpResponse.json({}, { status: 201 }); }),
      http.post("/api/v1/records/batch", async ({ request }) => { batches.push(await request.json() as never); return HttpResponse.json({}, { status: 201 }); }),
    );
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={existing} /></QueryClientProvider>);
    await userEvent.upload(screen.getByLabelText("Export file"), new File([keeper], "keeper.json", { type: "application/json" }));
    expect(await screen.findByText(/from Keeper \(JSON\)/)).toHaveTextContent("30 records from Keeper (JSON), 1 skipped.");
    const f = screen.getByRole("region", { name: "Folders" });
    expect(within(f).getByText("Design").parentElement).toHaveTextContent("27");
    expect(within(f).getByText("Infra").parentElement).toHaveTextContent("3");
    expect(within(screen.getByRole("table", { name: "First records" })).getAllByRole("row")).toHaveLength(6);
    expect(screen.getByRole("region", { name: "Skipped rows" })).toHaveTextContent("Row 31: No title");
    await userEvent.click(screen.getByRole("button", { name: "Import 30" }));
    expect(await screen.findByText("Imported 30 records")).toBeInTheDocument();
    expect(screen.getByText(/1 new folder\./)).toBeInTheDocument();
    // Only "Design" is created; "Infra" already exists and is reused.
    expect(folders).toHaveLength(1);
    expect(await decryptFolderName(folders[0]!.id, folders[0]!.encName, userKey)).toBe("Design");
    expect(batches.map((b) => b.records.length)).toEqual([25, 5]);
    const all = batches.flatMap((b) => b.records);
    expect(JSON.stringify(batches)).not.toContain("pw-0-secret");
    const first = await decryptRecord(all[0]!.id, all[0]!.encBody, all[0]!.wrappedRecordKey, userKey);
    expect(first.body).toEqual({ v: 2, type: "login", title: "Site 0", username: "user0", password: "pw-0-secret" });
    expect(all[0]!.folderId).toBe(folders[0]!.id);
    expect(all[29]!.folderId).toBe(existing[0]!.id);
  });

  it("merges folder names case-insensitively and retries a failed batch once", async () => {
    const folders: unknown[] = [];
    let calls = 0;
    server.use(
      http.post("/api/v1/folders", async ({ request }) => { folders.push(await request.json()); return HttpResponse.json({}, { status: 201 }); }),
      http.post("/api/v1/records/batch", () => (++calls === 1 ? HttpResponse.json({ error: "server_error" }, { status: 503 }) : HttpResponse.json({}, { status: 201 }))),
    );
    const file = JSON.stringify({ records: [{ title: "A", password: "p", folders: [{ folder: "Design" }] }, { title: "B", password: "p", folders: [{ folder: "design " }] }] });
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={[]} /></QueryClientProvider>);
    await userEvent.upload(screen.getByLabelText("Export file"), new File([file], "k.json", { type: "application/json" }));
    await userEvent.click(await screen.findByRole("button", { name: "Import 2" }));
    expect(await screen.findByText("Imported 2 records")).toBeInTheDocument();
    expect(folders).toHaveLength(1);
    expect(calls).toBe(2);
  });

  it("reports a batch that fails twice as not uploaded", async () => {
    let calls = 0;
    server.use(http.post("/api/v1/records/batch", () => { calls++; return HttpResponse.json({ error: "server_error" }, { status: 500 }); }));
    const file = JSON.stringify({ records: [{ title: "A", password: "p" }] });
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={[]} /></QueryClientProvider>);
    await userEvent.upload(screen.getByLabelText("Export file"), new File([file], "k.json", { type: "application/json" }));
    await userEvent.click(await screen.findByRole("button", { name: "Import 1" }));
    expect(await screen.findByText(/1 couldn't be uploaded/)).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it("maps the columns of an unknown CSV, previews the mapped rows, then imports", async () => {
    const batches: { records: { encBody: string; wrappedRecordKey: string; id: string }[] }[] = [];
    server.use(http.post("/api/v1/records/batch", async ({ request }) => { batches.push(await request.json() as never); return HttpResponse.json({}, { status: 201 }); }));
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={[]} /></QueryClientProvider>);
    const csv = "Account,Website,User,Pass,Memo\nAcme,https://acme.io,ops,pw1,hi\nBeta,https://b.io,u2,pw2,\n";
    await userEvent.upload(screen.getByLabelText("Export file"), new File([csv], "other.csv", { type: "text/csv" }));
    const region = await screen.findByRole("region", { name: "Match columns" });
    expect(within(region).getByLabelText("Title")).toHaveValue("0");
    expect(within(region).getByLabelText("Password")).toHaveValue("3");
    expect(within(region).getByLabelText("Notes")).toHaveValue("");
    await userEvent.selectOptions(within(region).getByLabelText("Notes"), "Memo");
    await userEvent.selectOptions(within(region).getByLabelText("Username"), "");
    const sample = screen.getByRole("table", { name: "Mapped rows" });
    expect(within(sample).getAllByRole("row")[1]).toHaveTextContent("Acme");
    expect(within(sample).getAllByRole("row")[1]).not.toHaveTextContent("ops");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/from CSV \(mapped columns\)/)).toHaveTextContent("2 records from CSV (mapped columns).");
    await userEvent.click(screen.getByRole("button", { name: "Import 2" }));
    expect(await screen.findByText("Imported 2 records")).toBeInTheDocument();
    const r = batches[0]!.records[0]!;
    expect((await decryptRecord(r.id, r.encBody, r.wrappedRecordKey, userKey)).body).toEqual({ v: 2, type: "login", title: "Acme", password: "pw1", url: "https://acme.io", notes: "hi" });
  });

  it("refuses a mapping without a title, password or website column", async () => {
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={[]} /></QueryClientProvider>);
    await userEvent.upload(screen.getByLabelText("Export file"), new File(["foo,bar\n1,2\n"], "x.csv", { type: "text/csv" }));
    await screen.findByRole("region", { name: "Match columns" });
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("title, password or website");
  });

  it("explains files it can't read", async () => {
    render(<QueryClientProvider client={new QueryClient()}><ImportSheet open onOpenChange={vi.fn()} folders={[]} /></QueryClientProvider>);
    await userEvent.upload(screen.getByLabelText("Export file"), new File(["{ nope"], "x.json", { type: "application/json" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("can't be read");
  });
});
