import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { attachmentCiphertextSize, attachmentMetaFor, b64url, decryptLinkLabel, encodeNonceBase, encryptAttachmentMeta, newAttachment, openLink, randomBytes, wrapFileKey } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import type { VaultRecord } from "@/features/vault/types";
import { OneTimeLinkSheet } from "./OneTimeLinkSheet";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

const userKey = randomBytes(32);
vi.spyOn(sessionModule, "useSession").mockReturnValue({ user: { id: "u1", name: "Sara" }, generation: () => 0, keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);

const record: VaultRecord = { id: crypto.randomUUID(), folderId: null, type: "login", revision: 1, updatedAt: "2026-10-04T09:00:00Z", deleted: false, permission: "owner", recordKey: new Uint8Array(32),
  body: { type: "login", title: "Customer portal", username: "acme", password: "Tg7#qL2v!Rm9zW4x", totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" } };

describe("OneTimeLinkSheet", () => {
  it("creates a link with the chosen limits, shows it with Copy, and lists links for the record with Revoke", async () => {
    let posted: Record<string, unknown> | null = null;
    let revoked = "";
    const links: unknown[] = [];
    server.use(
      http.get("/api/v1/records/:id/links", () => HttpResponse.json({ links })),
      http.post("/api/v1/links", async ({ request }) => {
        posted = await request.json() as Record<string, unknown>;
        links.push({ id: posted.id, recordId: record.id, expiresAt: new Date(Date.now() + 7 * 864e5).toISOString(), maxOpens: 3, opens: 0, revokedAt: null, createdAt: new Date().toISOString(), labelEnc: posted.labelEnc, hasPassword: false, state: "active" });
        return HttpResponse.json({ id: posted.id }, { status: 201 });
      }),
      http.delete("/api/v1/links/:id", ({ params }) => { revoked = params.id as string; return new HttpResponse(null, { status: 204 }); }),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><OneTimeLinkSheet record={record} open onOpenChange={vi.fn()} /></QueryClientProvider>);
    await userEvent.type(screen.getByLabelText("Who it's for"), "Acme Ltd");
    await userEvent.click(screen.getByRole("radio", { name: "7 days" }));
    await userEvent.click(screen.getByRole("radio", { name: "3 times" }));
    await userEvent.click(screen.getByRole("button", { name: "Create link" }));
    const shown = await screen.findByLabelText("Link to send");
    const p = posted as unknown as { id: string; recordId: string; encPayload: string; expiresInHours: number; maxOpens: number; labelEnc: string };
    expect(p).toMatchObject({ recordId: record.id, expiresInHours: 168, maxOpens: 3 });
    expect(JSON.stringify(p)).not.toContain("Tg7#qL2v");
    expect(JSON.stringify(p)).not.toContain("Acme");
    expect(await decryptLinkLabel(p.id, p.labelEnc, userKey)).toBe("Acme Ltd");
    const url = shown.textContent!;
    expect(url).toMatch(new RegExp(`/s/${p.id}#[A-Za-z0-9_-]{43}$`));
    const opened = await openLink(p.id, p.encPayload, url.split("#")[1]!);
    expect(opened).toEqual({ title: "Customer portal", type: "login", username: "acme", password: "Tg7#qL2v!Rm9zW4x" }); // no TOTP secret
    await userEvent.click(screen.getByRole("button", { name: "Copy link" }));
    expect(copySecret).toHaveBeenCalledWith(url);
    await userEvent.click(screen.getByRole("button", { name: "Create another" }));
    const list = await screen.findByRole("region", { name: "Links for this record" });
    expect(within(list).getByText(/For Acme Ltd/)).toBeInTheDocument();
    expect(within(list).getByText(/Opened 0 of 3/)).toBeInTheDocument();
    await userEvent.click(within(list).getByRole("button", { name: "Revoke link for Acme Ltd" }));
    expect(revoked).toBe(p.id);
  });

  it("files are opt-in per link: none by default; a picked file's key travels inside the encrypted payload, with a warning", async () => {
    const recordKey = randomBytes(32);
    const fid = crypto.randomUUID();
    const a = newAttachment(5000);
    const meta = attachmentMetaFor({ name: "lease.pdf", type: "application/pdf", size: 5000 }, "e".repeat(64));
    const id = crypto.randomUUID();
    const rec: VaultRecord = { ...record, id, recordKey, attachments: [{ id: fid, encMeta: await encryptAttachmentMeta(id, fid, meta, recordKey), wrappedFileKey: await wrapFileKey(id, fid, a.fileKey, recordKey),
      nonceBase: encodeNonceBase(a.nonceBase), size: attachmentCiphertextSize(5000), chunkSize: 1048576, chunkCount: 1, createdBy: "u1", createdByName: "Sara", createdAt: new Date().toISOString() }] };
    const posted: Record<string, unknown>[] = [];
    server.use(
      http.get("/api/v1/attachments/limits", () => HttpResponse.json({ enabled: true, chunkSize: 1048576, maxFileMb: 100, maxPerRecord: 25, maxRecordMb: 250 })),
      http.get("/api/v1/records/:id/links", () => HttpResponse.json({ links: [] })),
      http.post("/api/v1/links", async ({ request }) => { const b = await request.json() as Record<string, unknown>; posted.push(b); return HttpResponse.json({ id: b.id }, { status: 201 }); }),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><OneTimeLinkSheet record={rec} open onOpenChange={vi.fn()} /></QueryClientProvider>);
    const box = await screen.findByRole("checkbox", { name: "Include lease.pdf" });
    expect(box).not.toBeChecked();
    expect(screen.queryByText(/carries the keys to these files/)).not.toBeInTheDocument();
    await userEvent.click(box);
    expect(screen.getByText(/carries the keys to these files/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Create link" }));
    const url = (await screen.findByLabelText("Link to send")).textContent!;
    const p = posted[0] as { id: string; encPayload: string; attachmentIds: string[] };
    expect(p.attachmentIds).toEqual([fid]);
    const body = await openLink(p.id, p.encPayload, url.split("#")[1]!);
    expect(body.attachments).toEqual([{ fileId: fid, fileKey: b64url.encode(a.fileKey), nonceBase: encodeNonceBase(a.nonceBase), meta }]);
    expect(p.encPayload).not.toContain(b64url.encode(a.fileKey));
  });
});
