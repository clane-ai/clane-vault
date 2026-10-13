import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { b64url, decryptRecord, decryptRecordBody, generateKeyPair, openFolderKey, randomBytes, unwrapKey } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { retry } from "@/features/import/useImport";
import commander from "./fixtures/commander.json?raw";
import MigratePage from "./MigratePage";
import { reportCsv, type MigrationReport } from "./report";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

retry.delayMs = 10;
const userKey = randomBytes(32);
let keys: { userKey: Uint8Array; privateKey: Uint8Array; publicKey: Uint8Array };
let bob: { publicKey: Uint8Array; privateKey: Uint8Array };
beforeAll(async () => {
  const kp = await generateKeyPair();
  keys = { userKey, ...kp };
  bob = await generateKeyPair();
  vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u-admin", name: "Admin", email: "admin@acme.test", role: "admin" }, generation: () => 0, keys } as never);
  URL.createObjectURL = vi.fn(() => "blob:report");
  URL.revokeObjectURL = vi.fn();
});

type Body = Record<string, any>;
function api(opts: { pending?: Body[] } = {}) {
  const calls = { folders: [] as Body[], members: [] as Body[], pending: [] as Body[], batches: [] as Body[], invites: [] as Body[], completes: [] as Body[] };
  server.use(
    http.get("/api/v1/admin/people", async () => HttpResponse.json({ users: [
      { id: "u-admin", name: "Admin", email: "admin@acme.test", role: "admin", status: "active", createdAt: "", publicKey: b64url.encode(keys.publicKey) },
      { id: "u-bob", name: "Bob", email: "bob@acme.test", role: "member", status: "active", createdAt: "", publicKey: b64url.encode(bob.publicKey) },
    ], invites: [] })),
    http.get("/api/v1/pending-members", () => HttpResponse.json({ pending: opts.pending ?? [] })),
    http.post("/api/v1/folders", async ({ request }) => { calls.folders.push(await request.json() as Body); return HttpResponse.json({}, { status: 201 }); }),
    http.post("/api/v1/folders/:id/members", async ({ request, params }) => { calls.members.push({ folderId: params.id, ...(await request.json() as Body) }); return HttpResponse.json({ ok: true }, { status: 201 }); }),
    http.post("/api/v1/folders/:id/pending-members", async ({ request, params }) => { calls.pending.push({ folderId: params.id, ...(await request.json() as Body) }); return HttpResponse.json({ id: crypto.randomUUID() }, { status: 201 }); }),
    http.post("/api/v1/folders/:id/pending-members/:pid/complete", async ({ request, params }) => { calls.completes.push({ folderId: params.id, pid: params.pid, ...(await request.json() as Body) }); return HttpResponse.json({ ok: true }, { status: 201 }); }),
    http.post("/api/v1/records/batch", async ({ request }) => { calls.batches.push(await request.json() as Body); return HttpResponse.json({}, { status: 201 }); }),
    http.post("/api/v1/admin/invites", async ({ request }) => {
      const b = await request.json() as Body;
      calls.invites.push(b);
      return HttpResponse.json({ id: crypto.randomUUID(), email: b.email, role: "member", expiresAt: "", inviteUrl: `http://localhost:5173/invite/tok-${b.email}`, emailed: false }, { status: 201 });
    }),
  );
  return calls;
}
const renderPage = (folders = [], records = []) =>
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MigratePage folders={folders} records={records} /></QueryClientProvider>);

describe("Migrate from Keeper page", () => {
  it("shows the plan, then migrates into team folders with members, invites and pending members, and reports", async () => {
    const calls = api();
    renderPage();
    await waitFor(() => expect(screen.getByLabelText("Keeper export file")).toBeEnabled());
    await userEvent.upload(screen.getByLabelText("Keeper export file"), new File([commander], "keeper.json", { type: "application/json" }));

    expect(await screen.findByText(/Keeper Commander \(JSON\)/)).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Folders" })).toHaveTextContent("4");
    expect(screen.getByRole("group", { name: "Records" })).toHaveTextContent("8"); // 9 placements, one repeated in the export
    const infra = screen.getByRole("listitem", { name: "Engineering / Infra" });
    expect(within(infra).getByText("Team folder")).toBeInTheDocument();
    const people = within(infra).getByRole("list", { name: "People in Engineering / Infra" });
    expect(within(people).getByText("Bob · bob@acme.test").parentElement).toHaveTextContent("Added now");
    expect(within(people).getByText("carol@acme.test").parentElement).toHaveTextContent("Will be invited");
    expect(within(people).getByText("Platform Team").parentElement).toHaveTextContent("Not mapped (Keeper team)");
    expect(screen.getByRole("region", { name: "Not migrated" })).toHaveTextContent("1 attachment on 1 record");

    // Leave out "Personal / Work" and don't invite dave.
    await userEvent.click(screen.getByRole("checkbox", { name: "Include Personal / Work" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Invite dave@acme.test" }));
    expect(screen.getByRole("group", { name: "Records" })).toHaveTextContent("7");
    await userEvent.click(screen.getByRole("button", { name: /Start migration \(7 records\)/ }));

    const report = await screen.findByRole("region", { name: "Migration report" }, { timeout: 10_000 });
    expect(report).toHaveTextContent("7 records created · 1 skipped · 0 failed");
    // Counts per record type (never values) in the report.
    expect(within(report).getByLabelText("Record types")).toHaveTextContent(/Login \d+ · .*Payment card 1/);
    // Folders: two team folders + one private, nothing for the unticked folder.
    expect(calls.folders.map((f) => f.kind ?? "private")).toEqual(["team", "team", "private"]);
    const infraFolder = calls.folders[0]!;
    // Bob is added with edit, sealed to his key; carol and eve wait as pending members; dave isn't invited.
    expect(calls.members).toHaveLength(1);
    expect(calls.members[0]).toMatchObject({ folderId: infraFolder.id, userId: "u-bob", permission: "edit" });
    const fk = await openFolderKey(calls.members[0]!.wrappedFolderKey, infraFolder.id, bob);
    expect(calls.pending.map((p) => [p.email, p.permission])).toEqual([["carol@acme.test", "view"], ["eve@acme.test", "edit"]]);
    expect(calls.invites).toEqual([{ email: "carol@acme.test", role: "member" }, { email: "eve@acme.test", role: "member" }]);

    // Team-folder records carry the folder wrap (Bob can open) and my own wrap; no plaintext is sent.
    const all = calls.batches.flatMap((b) => b.records);
    expect(JSON.stringify(calls.batches)).not.toContain("Tg7#qL2v!Rm9zW4x");
    const aws = all.find((r: Body) => r.folderId === infraFolder.id)!;
    const rk = await unwrapKey(aws.wrappedRecordKey, fk, `record-key:${aws.id}`);
    expect((await decryptRecordBody(aws.id, aws.encBody, rk)).totpSecret).toBe("JBSWY3DPEHPK3PXP");
    expect((await decryptRecord(aws.id, aws.encBody, aws.ownerWrappedRecordKey, userKey)).body.title).toBe("AWS root");

    const invites = within(report).getByRole("region", { name: "Invite links" });
    await userEvent.click(within(invites).getByRole("button", { name: "Copy invite link for carol@acme.test" }));
    expect(copySecret).toHaveBeenCalledWith("http://localhost:5173/invite/tok-carol@acme.test", expect.any(Number));
    expect(within(report).getByRole("region", { name: "Add after they register" })).toHaveTextContent("carol@acme.test → Engineering / Infra (Can view)");
    expect(within(report).getByRole("region", { name: "Notes" })).toHaveTextContent("dave@acme.test → Sales (not invited (unticked))");
    expect(within(report).getByRole("link", { name: "CSV" })).toHaveAttribute("download", "keeper-migration-report.csv");
  });

  it("Complete pending members seals the folder key to each person who is ready", async () => {
    const fid = crypto.randomUUID();
    const folderKey = randomBytes(32);
    const calls = api({ pending: [
      { id: "p1", folderId: fid, email: "bob@acme.test", permission: "edit", createdAt: "", user: { id: "u-bob", name: "Bob", publicKey: b64url.encode(bob.publicKey) } },
      { id: "p2", folderId: fid, email: "zed@acme.test", permission: "view", createdAt: "", user: null },
    ] });
    renderPage([{ id: fid, name: "Infra", kind: "team", deleted: false, myPermission: "owner", folderKey }] as never);
    const card = await screen.findByRole("region", { name: "Pending members" });
    expect(card).toHaveTextContent("2 waiting · 1 ready");
    expect(within(card).getByRole("listitem", { name: "zed@acme.test → Infra" })).toHaveTextContent("Not registered yet");
    await userEvent.click(within(card).getByRole("button", { name: "Complete pending members" }));
    await waitFor(() => expect(calls.completes).toHaveLength(1));
    expect(calls.completes[0]).toMatchObject({ folderId: fid, pid: "p1", userId: "u-bob" });
    expect(await openFolderKey(calls.completes[0]!.wrappedFolderKey, fid, bob)).toEqual(folderKey);
  });
});

describe("reportCsv", () => {
  it("writes one table and neutralises spreadsheet formulas", () => {
    const r: MigrationReport = { source: "commander", startedAt: "", finishedAt: "", folders: [{ name: "=HYPERLINK(1)", kind: "team", status: "created", created: 2, skipped: 1, failed: 0 }],
      added: [], invites: [{ email: "a@b.c", url: "http://x/invite/t" }], pending: [{ email: "a@b.c", folder: "F, G", permission: "view", reason: "invited now" }],
      managers: [], teams: [], attachments: [], skipped: [], notAdded: [], failures: [], multiFolder: 0 };
    expect(reportCsv(r).split("\r\n")).toEqual([
      "section,folder,item,detail,status", `folder,"'=HYPERLINK(1)",team,created 2; skipped 1; failed 0,created`,
      "invite,,a@b.c,http://x/invite/t,send this link", `add after registering,"F, G",a@b.c,view,invited now`, "",
    ]);
  });
  it("lists record types (counts only)", () => {
    const r: MigrationReport = { source: "commander", startedAt: "", finishedAt: "", folders: [], added: [], invites: [], pending: [], managers: [], teams: [], attachments: [],
      skipped: [], notAdded: [], failures: [], multiFolder: 0, types: [{ type: "login", label: "Login", count: 4 }, { type: "card", label: "Payment card", count: 1 }] };
    expect(reportCsv(r).split("\r\n")).toEqual(["section,folder,item,detail,status", "record type,,Login,4,planned", "record type,,Payment card,1,planned", ""]);
  });
});
