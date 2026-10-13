import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { attachmentMetaFor, b64url, createLink, encryptChunk, newAttachment } from "@clane-vault/crypto";
import { server } from "@/test/server";
import PublicLinkPage from "./PublicLinkPage";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

const body = { title: "Customer portal", username: "acme-admin", password: "Tg7#qL2v!Rm9zW4x", url: "portal.example.com", notes: "Change it on first sign-in" };
const meta = (o: object = {}) => ({ needsPassword: false, passwordSalt: null, expiresAt: new Date(Date.now() + 3600_000).toISOString(), opensLeft: 1, ...o });

function renderAt(id: string, fragment: string) {
  window.history.replaceState(null, "", `/s/${id}${fragment ? `#${fragment}` : ""}`);
  return render(<MemoryRouter initialEntries={[`/s/${id}`]}><Routes><Route path="/s/:id" element={<PublicLinkPage />} /></Routes></MemoryRouter>);
}

describe("PublicLinkPage", () => {
  it("lists the files a link carries, downloads one with the token (decrypted here, octet-stream), never previews", async () => {
    const id = crypto.randomUUID(), fid = crypto.randomUUID();
    const data = new TextEncoder().encode("signed lease, page 1");
    const a = newAttachment(data.length);
    const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource))].map((x) => x.toString(16).padStart(2, "0")).join("");
    const fileMeta = attachmentMetaFor({ name: "lease.txt", type: "text/plain", size: data.length }, hash);
    const chunk = await encryptChunk(a.fileKey, a.nonceBase, fid, 0, 1, data);
    const l = await createLink(id, { title: "Lease", attachments: [{ fileId: fid, fileKey: b64url.encode(a.fileKey), nonceBase: b64url.encode(a.nonceBase), meta: fileMeta }] });
    const auth: (string | null)[] = [];
    server.use(
      http.get("/api/v1/public/links/:id", () => HttpResponse.json(meta())),
      http.post("/api/v1/public/links/:id/open", () => HttpResponse.json({ encPayload: l.encPayload, expiresAt: meta().expiresAt, opensLeft: 0, downloadToken: "tok-123" })),
      http.get(`/api/v1/public/links/${id}/attachments/${fid}/chunks/0`, ({ request }) => { auth.push(request.headers.get("authorization")); return new HttpResponse(chunk as BodyInit); }),
    );
    const blobs: Blob[] = [];
    const create = vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { blobs.push(b as Blob); return "blob:x"; });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    renderAt(id, l.fragment);
    await userEvent.click(await screen.findByRole("button", { name: "Show the details" }));
    const files = await screen.findByRole("region", { name: "Files" });
    expect(files).toHaveTextContent("lease.txt");
    expect(screen.queryByRole("button", { name: /Preview/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Download lease.txt" }));
    await vi.waitFor(() => expect(click).toHaveBeenCalled());
    expect(auth).toEqual(["Bearer tok-123"]);
    expect(blobs[0]!.type).toBe("application/octet-stream");
    expect(new TextDecoder().decode(await blobs[0]!.arrayBuffer())).toBe("signed lease, page 1");
    create.mockRestore(); click.mockRestore();
  });

  it("opens on request, decrypts in the browser, copies, and never sends the key", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body);
    const seen: string[] = [];
    server.use(
      http.get("/api/v1/public/links/:id", ({ request }) => { seen.push(request.url); return HttpResponse.json(meta()); }),
      http.post("/api/v1/public/links/:id/open", async ({ request }) => { seen.push(request.url + JSON.stringify(await request.json())); return HttpResponse.json({ encPayload: l.encPayload, expiresAt: meta().expiresAt, opensLeft: 0 }); }),
    );
    renderAt(id, l.fragment);
    expect(await screen.findByText(/can be opened 1 more time/)).toBeInTheDocument();
    expect(seen).toHaveLength(1); // looking does not open it
    await userEvent.click(screen.getByRole("button", { name: "Show the details" }));
    expect(await screen.findByRole("heading", { name: "Customer portal" })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toHaveTextContent("acme-admin");
    expect(screen.getByLabelText("Password")).not.toHaveTextContent(body.password);
    await userEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByLabelText("Password")).toHaveTextContent(body.password);
    expect(screen.getByText(body.notes)).toBeInTheDocument();
    expect(screen.getByText(/can't be opened again/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy password" }));
    expect(copySecret).toHaveBeenCalledWith(body.password);
    for (const s of seen) expect(s).not.toContain(l.fragment);
    expect(window.location.hash).toBe(""); // key dropped from the address bar
  });

  it.each([
    ["used_up", "This link has been used up"],
    ["expired", "This link has expired"],
    ["revoked", "This link was revoked"],
  ])("explains %s links without showing anything", async (error, text) => {
    server.use(http.get("/api/v1/public/links/:id", () => HttpResponse.json({ error }, { status: 410 })));
    renderAt(crypto.randomUUID(), "a".repeat(43));
    expect(await screen.findByRole("heading", { name: text })).toBeInTheDocument();
  });

  it("says when the link is used up between looking and opening", async () => {
    server.use(
      http.get("/api/v1/public/links/:id", () => HttpResponse.json(meta())),
      http.post("/api/v1/public/links/:id/open", () => HttpResponse.json({ error: "used_up" }, { status: 410 })),
    );
    renderAt(crypto.randomUUID(), "a".repeat(43));
    await userEvent.click(await screen.findByRole("button", { name: "Show the details" }));
    expect(await screen.findByRole("heading", { name: "This link has been used up" })).toBeInTheDocument();
  });

  it("treats a link without a 32-byte key after # as incomplete, even for password links", async () => {
    for (const frag of ["p", "abc", "not base64!"]) {
      const r = renderAt(crypto.randomUUID(), frag);
      expect(await screen.findByRole("heading", { name: "This link is incomplete" })).toBeInTheDocument();
      r.unmount();
    }
  });

  it("explains rate limiting", async () => {
    server.use(http.get("/api/v1/public/links/:id", () => HttpResponse.json({ error: "rate_limited" }, { status: 429 })));
    renderAt(crypto.randomUUID(), "a".repeat(43));
    expect(await screen.findByText("Too many requests — wait a minute and try again.")).toBeInTheDocument();
  });

  it("handles unknown, incomplete and damaged links", async () => {
    server.use(http.get("/api/v1/public/links/:id", () => HttpResponse.json({ error: "not_found" }, { status: 404 })));
    const { unmount } = renderAt(crypto.randomUUID(), "a".repeat(43));
    expect(await screen.findByRole("heading", { name: "This link doesn't exist" })).toBeInTheDocument();
    unmount();
    const r2 = renderAt(crypto.randomUUID(), "");
    expect(await screen.findByRole("heading", { name: "This link is incomplete" })).toBeInTheDocument();
    r2.unmount();
    const id = crypto.randomUUID();
    const l = await createLink(id, body);
    server.use(
      http.get("/api/v1/public/links/:id", () => HttpResponse.json(meta())),
      http.post("/api/v1/public/links/:id/open", () => HttpResponse.json({ encPayload: l.encPayload, expiresAt: meta().expiresAt, opensLeft: 0 })),
    );
    renderAt(id, (await createLink(id, body)).fragment); // someone else's key
    await userEvent.click(await screen.findByRole("button", { name: "Show the details" }));
    expect(await screen.findByRole("heading", { name: "This link can't be opened" })).toBeInTheDocument();
  });

  it("password links: asks for the password, sends only the access hash, retries on a wrong one", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body, { password: "blue cactus" });
    const sent: string[] = [];
    server.use(
      http.get("/api/v1/public/links/:id", () => HttpResponse.json(meta({ needsPassword: true, passwordSalt: l.passwordSalt, opensLeft: null }))),
      http.post("/api/v1/public/links/:id/open", async ({ request }) => {
        const b = await request.json() as { accessHash?: string };
        sent.push(JSON.stringify(b));
        return b.accessHash === l.accessHash ? HttpResponse.json({ encPayload: l.encPayload, expiresAt: meta().expiresAt, opensLeft: null }) : HttpResponse.json({ error: "wrong_password" }, { status: 403 });
      }),
    );
    expect(l.fragment).not.toBe("p");
    renderAt(id, l.fragment);
    await userEvent.type(await screen.findByLabelText("Password"), "red cactus");
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(await screen.findByText("That password isn't right.", {}, { timeout: 20_000 })).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("Password"));
    await userEvent.type(screen.getByLabelText("Password"), "blue cactus");
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(await screen.findByRole("heading", { name: "Customer portal" }, { timeout: 20_000 })).toBeInTheDocument();
    expect(screen.getByText(/works until/)).toBeInTheDocument();
    for (const s of sent) { expect(s).not.toContain("cactus"); expect(s).not.toContain(l.fragment); }
  }, 60_000);

  it("renders any record type read-only: template fields and custom fields, secrets hidden until revealed", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, { title: "Company Visa", type: "card", data: { cardholder: "Ada Lovelace", number: "4242424242424242", expiry: "12/29", cvv: "737" },
      fields: [{ id: "a", label: "Hotline", kind: "phone", value: "+353 1 555" }, { id: "b", label: "Key", kind: "hiddenMultiline", value: "-----BEGIN KEY-----" }] });
    server.use(
      http.get("/api/v1/public/links/:id", () => HttpResponse.json(meta())),
      http.post("/api/v1/public/links/:id/open", () => HttpResponse.json({ encPayload: l.encPayload, expiresAt: meta().expiresAt, opensLeft: 0 })),
    );
    renderAt(id, l.fragment);
    expect(await screen.findByRole("heading", { name: "Someone shared a record with you" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show the details" }));
    expect(await screen.findByRole("heading", { name: "Company Visa" })).toBeInTheDocument();
    expect(screen.getByText(/Payment card ·/)).toBeInTheDocument();
    expect(screen.getByLabelText("Cardholder")).toHaveTextContent("Ada Lovelace");
    expect(screen.getByLabelText("Card number")).toHaveTextContent("•••• •••• •••• 4242");
    expect(screen.getByLabelText("Security code")).not.toHaveTextContent("737");
    expect(screen.getByLabelText("Key")).not.toHaveTextContent("BEGIN");
    await userEvent.click(screen.getByRole("button", { name: "Show card number" }));
    expect(screen.getByLabelText("Card number")).toHaveTextContent("4242 4242 4242 4242");
    await userEvent.click(screen.getByRole("button", { name: "Copy card number" }));
    expect(copySecret).toHaveBeenLastCalledWith("4242424242424242");
    expect(screen.getByLabelText("Hotline")).toHaveTextContent("+353 1 555");
  });
});
