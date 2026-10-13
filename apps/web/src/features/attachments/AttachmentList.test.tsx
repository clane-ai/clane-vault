import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { attachmentCiphertextSize, attachmentMetaFor, encodeNonceBase, encryptAttachmentMeta, encryptChunk, newAttachment, randomBytes, wrapFileKey } from "@clane-vault/crypto";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import type { SyncAttachment, VaultRecord } from "@/features/vault/types";
import { FilesSection } from "./AttachmentList";
import { useFileDrop } from "./AttachmentDropZone";
import { QueuedFiles } from "./EditorFiles";
import { PreviewSheet } from "./PreviewSheet";
import { resetUploadsForTests } from "./uploader";
import type { FileRow } from "./useAttachments";

let offline = false;
vi.spyOn(sessionModule, "useSession").mockImplementation(() => ({ user: { id: "u1" }, generation: () => 0, offline, org: null, keys: { userKey: randomBytes(32) } }) as never);
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);
afterEach(() => { offline = false; resetUploadsForTests(); });

const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

async function fileOn(recordId: string, recordKey: Uint8Array, name: string, mime: string, data: Uint8Array) {
  const id = crypto.randomUUID();
  const a = newAttachment(data.length);
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource))].map((x) => x.toString(16).padStart(2, "0")).join("");
  const meta = attachmentMetaFor({ name, type: mime, size: data.length }, hash);
  const att: SyncAttachment = { id, encMeta: await encryptAttachmentMeta(recordId, id, meta, recordKey), wrappedFileKey: await wrapFileKey(recordId, id, a.fileKey, recordKey), nonceBase: encodeNonceBase(a.nonceBase),
    size: attachmentCiphertextSize(data.length), chunkSize: 1048576, chunkCount: 1, createdBy: "u2", createdByName: "Ana", createdAt: new Date().toISOString() };
  const chunk = await encryptChunk(a.fileKey, a.nonceBase, id, 0, 1, data);
  return { att, meta, chunk };
}

async function recordWith(permission: VaultRecord["permission"], files: { name: string; mime: string; data: Uint8Array }[]) {
  const id = crypto.randomUUID();
  const recordKey = randomBytes(32);
  const made = await Promise.all(files.map((f) => fileOn(id, recordKey, f.name, f.mime, f.data)));
  const r: VaultRecord = { id, folderId: null, type: "item", revision: 1, updatedAt: new Date().toISOString(), deleted: false, permission, recordKey,
    body: { type: "note", title: "Lease" }, attachments: made.map((m) => (permission === "use" ? { ...m.att, wrappedFileKey: undefined, nonceBase: undefined } : m.att)) };
  server.use(http.get(`/api/v1/records/${id}/attachments/:fid/chunks/0`, ({ params }) => {
    const m = made.find((x) => x.att.id === params.fid);
    return m ? new HttpResponse(m.chunk as BodyInit, { headers: { "content-type": "application/octet-stream" } }) : HttpResponse.json({ error: "not_found" }, { status: 404 });
  }));
  return { r, made };
}
const limits = (o: Partial<{ enabled: boolean; maxFileMb: number }> = {}) => server.use(http.get("/api/v1/attachments/limits", () => HttpResponse.json({ enabled: true, chunkSize: 1048576, maxFileMb: 100, maxPerRecord: 25, maxRecordMb: 250, ...o })));

describe("Files section", () => {
  it("owner: names decrypted, size and who added it; preview for an image, download and remove", async () => {
    limits();
    const { r } = await recordWith("owner", [{ name: "Passport.png", mime: "image/png", data: PNG }, { name: "setup.exe", mime: "application/x-msdownload", data: Uint8Array.from([0x4d, 0x5a]) }]);
    wrap(<FilesSection record={r} />);
    expect(await screen.findByText("Passport.png")).toBeInTheDocument();
    expect(screen.getAllByText(/Added by Ana/)).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Preview Passport.png" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Preview setup.exe" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove Passport.png" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Attach file" })).toBeInTheDocument();
    // A program warns before it downloads.
    await userEvent.click(screen.getByRole("button", { name: "Download setup.exe" }));
    expect(screen.getByRole("alert")).toHaveTextContent("setup.exe is a program added by Ana");
  });

  it("view: download and preview, no remove, no attach", async () => {
    limits();
    const { r } = await recordWith("view", [{ name: "Passport.png", mime: "image/png", data: PNG }]);
    wrap(<FilesSection record={r} />);
    expect(await screen.findByRole("button", { name: "Download Passport.png" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove Passport.png" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Attach file" })).not.toBeInTheDocument();
  });

  it("use only: the list with a lock and no buttons, and how to get access", async () => {
    limits();
    const { r } = await recordWith("use", [{ name: "Passport.png", mime: "image/png", data: PNG }]);
    wrap(<FilesSection record={r} />);
    expect(await screen.findByText("Passport.png")).toBeInTheDocument();
    expect(screen.getByLabelText("Locked")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Download|Preview|Remove/ })).not.toBeInTheDocument();
    expect(screen.getByText(/Ask the owner for Can view to download/)).toBeInTheDocument();
  });

  it("offline: files listed as available online, buttons disabled", async () => {
    offline = true;
    const { r } = await recordWith("owner", [{ name: "Passport.png", mime: "image/png", data: PNG }]);
    wrap(<FilesSection record={r} />);
    expect(await screen.findByRole("button", { name: "Download Passport.png" })).toBeDisabled();
    expect(screen.getByText(/Available online/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Attach file" })).not.toBeInTheDocument();
  });

  it("a row that doesn't open says so and offers nothing", async () => {
    limits();
    const { r } = await recordWith("owner", [{ name: "x.txt", mime: "text/plain", data: Uint8Array.from([65]) }]);
    wrap(<FilesSection record={{ ...r, recordKey: randomBytes(32) }} />);
    expect(await screen.findByText("Can't open this file")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Download/ })).not.toBeInTheDocument();
  });
});

describe("previews", () => {
  async function rowFor(name: string, mime: string, data: Uint8Array) {
    const { r, made } = await recordWith("owner", [{ name, mime, data }]);
    const row: FileRow = { att: made[0]!.att, meta: made[0]!.meta, size: data.length };
    return { r, row, read: vi.fn(async () => [data]) };
  }

  it("an image goes to <img src=blob:> after its magic bytes check; the URL is revoked once loaded", async () => {
    const created: Blob[] = [];
    const create = vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { created.push(b as Blob); return "blob:preview"; });
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    const { row, read } = await rowFor("Passport.png", "image/png", PNG);
    wrap(<PreviewSheet row={row} read={read} onDownload={vi.fn()} onClose={vi.fn()} />);
    const img = await screen.findByTestId("image-preview");
    expect(img).toHaveAttribute("src", "blob:preview");
    expect(created[0]!.type).toBe("application/octet-stream");
    fireEvent.load(img);
    expect(revoke).toHaveBeenCalledWith("blob:preview");
    expect(document.querySelector("iframe, object, embed")).toBeNull();
    create.mockRestore(); revoke.mockRestore();
  });

  it("bytes that don't match the claimed type are never shown (an SVG posing as PNG)", async () => {
    const create = vi.spyOn(URL, "createObjectURL");
    const svg = new TextEncoder().encode("<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>");
    const { row, read } = await rowFor("cat.png", "image/png", svg);
    wrap(<PreviewSheet row={row} read={read} onDownload={vi.fn()} onClose={vi.fn()} />);
    expect(await screen.findByText(/isn't what its type says/)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
    expect(screen.queryByTestId("image-preview")).not.toBeInTheDocument();
    create.mockRestore();
  });

  it("text goes into a <pre> as text, never as HTML", async () => {
    const { row, read } = await rowFor("notes.txt", "text/plain", new TextEncoder().encode("<img src=x onerror=alert(1)> hello"));
    wrap(<PreviewSheet row={row} read={read} onDownload={vi.fn()} onClose={vi.fn()} />);
    const pre = await screen.findByTestId("text-preview");
    expect(pre.textContent).toBe("<img src=x onerror=alert(1)> hello");
    expect(pre.querySelector("img")).toBeNull();
  });

  it("types outside the allowlist are refused without fetching anything", async () => {
    const { row, read } = await rowFor("page.html", "text/html", new TextEncoder().encode("<h1>x</h1>"));
    wrap(<PreviewSheet row={row} read={read} onDownload={vi.fn()} onClose={vi.fn()} />);
    expect(await screen.findByText(/can't be previewed/)).toBeInTheDocument();
    expect(read).not.toHaveBeenCalled();
  });
});

describe("drop zone and the new-record queue", () => {
  function Panel({ canDrop, onFiles }: { canDrop: boolean; onFiles: (f: File[]) => void }) {
    const d = useFileDrop({ canDrop, title: "Lease", onFiles });
    return <div data-testid="panel" className="relative" {...d.handlers}>{d.overlay}</div>;
  }
  const dt = (files: File[]) => ({ dataTransfer: { types: ["Files"], files, dropEffect: "none" } });

  it("shows what dropping does, and attaches only where the person can edit", () => {
    const onFiles = vi.fn();
    const f = new File(["x"], "a.txt");
    const { rerender } = render(<Panel canDrop onFiles={onFiles} />);
    fireEvent.dragEnter(screen.getByTestId("panel"), dt([f]));
    expect(screen.getByTestId("drop-overlay")).toHaveTextContent("Drop to attach to Lease");
    fireEvent.drop(screen.getByTestId("panel"), dt([f]));
    expect(onFiles).toHaveBeenCalledWith([f]);
    expect(screen.queryByTestId("drop-overlay")).not.toBeInTheDocument();
    rerender(<Panel canDrop={false} onFiles={onFiles} />);
    fireEvent.dragEnter(screen.getByTestId("panel"), dt([f]));
    expect(screen.getByTestId("drop-overlay")).toHaveTextContent("You can't add files here");
    fireEvent.drop(screen.getByTestId("panel"), dt([f]));
    expect(onFiles).toHaveBeenCalledTimes(1);
  });

  it("a new record queues files (over-limit ones refused) until it is saved", async () => {
    limits({ maxFileMb: 1 });
    const onChange = vi.fn();
    wrap(<QueuedFiles queue={[]} onChange={onChange} />);
    await waitFor(() => expect(screen.getByTestId("attach-input")).toBeInTheDocument());
    await waitFor(async () => {
      const input = screen.getByTestId("attach-input") as HTMLInputElement;
      await userEvent.upload(input, [new File(["small"], "ok.txt", { type: "text/plain" }), new File([new Uint8Array(2 * 1024 * 1024)], "big.bin")]);
      expect(onChange).toHaveBeenLastCalledWith([expect.objectContaining({ name: "ok.txt" })]);
    });
  });
});
