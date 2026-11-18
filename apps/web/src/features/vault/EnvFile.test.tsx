import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { decryptRecord, randomBytes, type RecordBody } from "@clane-vault/crypto";
import { FILE } from "../../../../../packages/crypto/test/envFixture";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { environmentOf, keepEol, readEnvFile } from "./EnvFile";
import { RecordEditor } from "./RecordEditor";
import { RecordPanel } from "./RecordPanel";
import VaultScreen from "./VaultScreen";
import type { VaultRecord } from "./types";

vi.mock("@/lib/clipboard", () => ({ copySecret: vi.fn(async () => undefined) }));
import { copySecret } from "@/lib/clipboard";

globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;
const TOO_LARGE = "This file is too large for a .env item (32 KB). Attach it to a Secure note instead.";
const NOT_TEXT = "This file isn't UTF-8 text. Attach it to a Secure note instead.";
const BYTES = new TextEncoder().encode(FILE);
const envFile = () => new File([BYTES], ".env.production");
const drop = (files: File[]) => fireEvent.drop(screen.getByTestId("env-drop"), { dataTransfer: { files, types: ["Files"] } });
const bytesOf = async (b: Blob) => [...new Uint8Array(await b.arrayBuffer())];
const stored: RecordBody = { type: "envFile", title: "Web shop", data: { fileName: ".env.production", environment: "production", content: FILE } };
afterEach(() => vi.restoreAllMocks());

describe("readEnvFile and environmentOf", () => {
  it("reads the bytes losslessly: BOM and CRLF intact", async () => {
    expect(BYTES[0]).toBe(0xef);
    expect(await readEnvFile(envFile())).toBe(FILE);
  });

  it("refuses a file over 32 KB before reading it", async () => {
    const big = new File([new Uint8Array(32_769).fill(65)], ".env");
    const read = vi.spyOn(big, "arrayBuffer");
    await expect(readEnvFile(big)).rejects.toThrow(TOO_LARGE);
    expect(read).not.toHaveBeenCalled();
  });

  it("refuses bytes that aren't UTF-8 (UTF-16)", async () => {
    await expect(readEnvFile(new File([new Uint8Array([0xff, 0xfe, 0x41, 0x00])], ".env"))).rejects.toThrow(NOT_TEXT);
  });

  it("names the environment from the file name", () => {
    expect([".env.production", "staging.env", ".env"].map(environmentOf)).toEqual(["production", "staging", ""]);
  });

  it("puts CRLF back only when the stored text used it", () => {
    expect(keepEol("A=1\r\n", "A=1\nB=2\n")).toBe("A=1\r\nB=2\r\n");
    expect(keepEol("A=1\n", "A=1\nB=2\n")).toBe("A=1\nB=2\n");
  });

  it("converts only the changed span: a bare LF in a quoted value, a lone CR and untouched CRLFs keep their bytes", () => {
    const stored = "# key\r\nPEM=\"-----BEGIN\nabc\n-----END\"\r\nX=1\rY=2\r\n";
    const shown = stored.replace(/\r\n?/g, "\n");
    expect(keepEol(stored, shown.replace("# key", "# keys"))).toBe(stored.replace("# key", "# keys"));
    expect(keepEol(stored, shown + "Z=3\n")).toBe(stored + "Z=3\r\n");
    expect(keepEol(stored, shown)).toBe(stored);
  });
});

describe("the editor", () => {
  const editor = (o: Partial<React.ComponentProps<typeof RecordEditor>> = {}) => {
    const onSave = vi.fn(async (_b: RecordBody) => undefined);
    render(<RecordEditor mode="edit" type="envFile" initial={stored} folderId={null} folders={[]} onSave={onSave} onCancel={vi.fn()} {...o} />);
    return onSave;
  };
  const saved = (onSave: ReturnType<typeof editor>) => onSave.mock.calls[0]![0];

  it("a dropped file fills File name and Environment, and is saved byte for byte", async () => {
    const onSave = editor({ mode: "create", initial: { type: "envFile", title: "Web shop" } });
    drop([envFile()]);
    await waitFor(() => expect(screen.getByLabelText("File name")).toHaveValue(".env.production"));
    expect(screen.getByLabelText("Environment")).toHaveValue("production");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE);
  });

  it("a dropped file leaves File name and Environment alone when they are filled", async () => {
    editor({ mode: "create", initial: { type: "envFile", title: "Web shop", data: { fileName: "prod.env", environment: "live" } } });
    drop([envFile()]);
    expect(await screen.findByLabelText("STRIPE_KEY")).toBeInTheDocument();
    expect(screen.getByLabelText("File name")).toHaveValue("prod.env");
    expect(screen.getByLabelText("Environment")).toHaveValue("live");
  });

  it("opened and saved untouched, the contents are the same string", async () => {
    const onSave = editor();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE);
  });

  it("typing into an entry rewrites only that value; values are masked inputs", async () => {
    const onSave = editor();
    const input = screen.getByLabelText("STRIPE_KEY") as HTMLInputElement;
    expect(input).toHaveAttribute("type", "password");
    await userEvent.type(input, "sk_live_2", { initialSelectionStart: 0, initialSelectionEnd: input.value.length });
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE.replace("'sk_live_1'", "sk_live_2"));
  });

  it("Add entry appends a line with the file's line ending and checks the key", async () => {
    const onSave = editor();
    await userEvent.type(screen.getByLabelText("New key"), "bad key");
    await userEvent.type(screen.getByLabelText("New value"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Add entry" }));
    expect(screen.getByRole("alert")).toHaveTextContent("A key is letters, digits, _ . or -, at most 128 characters.");
    await userEvent.clear(screen.getByLabelText("New key"));
    await userEvent.type(screen.getByLabelText("New key"), "NEW");
    await userEvent.click(screen.getByRole("button", { name: "Add entry" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE + "\r\nNEW=x\r\n");
  });

  it("Edit as text: a masked text area; an appended line gets CRLF and the rest (a quoted value's bare LF too) keeps its bytes", async () => {
    const onSave = editor();
    await userEvent.click(screen.getByRole("button", { name: "Edit as text" }));
    const area = screen.getByLabelText("File contents");
    expect(area).toHaveAttribute("data-masked", "true");
    await userEvent.type(area, "{Enter}NEW=1");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE + "\r\nNEW=1");
  });

  it("a 40 KB file shows the size message and leaves the contents as they were", async () => {
    const onSave = editor();
    drop([new File([new Uint8Array(40_000).fill(65)], ".env")]);
    expect(await screen.findByRole("alert")).toHaveTextContent(TOO_LARGE);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).data!.content).toBe(FILE);
  });

  it("Agent use: the Secret list is the file's keys, and env:<KEY> is stored", async () => {
    const onSave = editor({ agentUse: true });
    await userEvent.type(screen.getByLabelText("Allowed hosts"), "api.stripe.com");
    await userEvent.click(screen.getByRole("combobox", { name: "Secret" }));
    expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual(["STRIPE_KEY", "PORT", "DB", "PW", "PW2", "A", "REF", "E", "T"]);
    await userEvent.click(screen.getByRole("option", { name: "STRIPE_KEY" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(saved(onSave).agentPolicy).toEqual({ v: 1, hosts: ["api.stripe.com"], inject: { kind: "bearer" }, secret: "env:STRIPE_KEY" });
  });

  it("removing the policy's key in Edit as text shows the validator's message and saves nothing", async () => {
    const policy = { v: 1 as const, hosts: ["api.stripe.com"], inject: { kind: "bearer" as const }, secret: "env:STRIPE_KEY" };
    const onSave = editor({ agentUse: true, initial: { ...stored, agentPolicy: policy } });
    expect(screen.queryByRole("alert")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Edit as text" }));
    fireEvent.change(screen.getByLabelText("File contents"), { target: { value: FILE.replace("export STRIPE_KEY = 'sk_live_1' # live\r\n", "") } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/^Agent policy:/);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSave).not.toHaveBeenCalled();
  });
});

describe("the record panel", () => {
  const record = (o: Partial<VaultRecord> = {}): VaultRecord => ({ id: "r1", folderId: null, type: "item", revision: 1, updatedAt: "2026-11-15T09:00:00Z", deleted: false, permission: "owner",
    recordKey: new Uint8Array(32), body: stored, ...o });
  const panel = (o?: Partial<VaultRecord>) => render(<RecordPanel record={record(o)} folderName={null} onClose={vi.fn()} onEdit={vi.fn()} onTrash={vi.fn()} />);

  it("one row per entry, keys visible, no value in the document until Show", async () => {
    panel();
    const list = screen.getByRole("list", { name: "Entries" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(10);
    expect(within(list).getByText("STRIPE_KEY")).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain("sk_live_1");
    expect(screen.queryByText("Contents")).toBeNull(); // the generic Contents row is left out
    expect(within(list).getAllByText("Overridden below")).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: "Show STRIPE_KEY" }));
    expect(within(list).getByText("sk_live_1")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy STRIPE_KEY" }));
    expect(copySecret).toHaveBeenLastCalledWith("sk_live_1");
  });

  it("Copy all copies the file; Download gives the stored bytes under the file name", async () => {
    const blobs: Blob[] = [];
    vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { blobs.push(b as Blob); return "blob:env"; });
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    const names: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { names.push(this.download); });
    panel();
    await userEvent.click(screen.getByRole("button", { name: "Copy all" }));
    expect(copySecret).toHaveBeenLastCalledWith(FILE);
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(names).toEqual([".env.production"]);
    expect(await bytesOf(blobs[0]!)).toEqual([...BYTES]);
  });

  it("Use only: Copy stays, Show and Download don't", () => {
    panel({ permission: "use" });
    expect(screen.queryByRole("button", { name: "Show STRIPE_KEY" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Download" })).toBeNull();
    expect(screen.getByRole("button", { name: "Copy STRIPE_KEY" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy all" })).toBeInTheDocument();
  });

  it("counts the lines that aren't KEY=value", () => {
    const { unmount } = panel();
    expect(screen.getByText("2 lines aren't KEY=value. They are kept as they are.")).toBeInTheDocument();
    unmount();
    panel({ body: { ...stored, data: { content: "A=1\nB=2\n" } } });
    expect(screen.queryByText(/KEY=value/)).toBeNull();
    panel({ id: "r2", body: { ...stored, data: { content: "A=1\nnope\n" } } });
    expect(screen.getByText("1 line isn't KEY=value. It is kept as it is.")).toBeInTheDocument();
  });
});

describe("New → .env file", () => {
  it("opens New record with the type chosen; the saved item is type item with the file verbatim inside", async () => {
    const userKey = randomBytes(32);
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: null, orgs: [], applyOrgs: vi.fn(), user: { id: "u1", name: "Sara" }, generation: () => 0, lock: vi.fn(), signOut: vi.fn(),
      keys: { userKey, privateKey: new Uint8Array(), publicKey: new Uint8Array() } } as never);
    let posted: { id: string; type: string; encBody: string; wrappedRecordKey: string } | null = null;
    server.use(
      http.get("/api/v1/sync", () => HttpResponse.json({ serverTime: "", folders: [], records: [] })),
      http.post("/api/v1/records", async ({ request }) => { posted = (await request.json()) as never; return HttpResponse.json({}, { status: 201 }); }),
    );
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><VaultScreen /></MemoryRouter></QueryClientProvider>);
    await userEvent.click(await screen.findByRole("button", { name: "New" }));
    await userEvent.click(screen.getByRole("menuitem", { name: ".env file" }));
    expect(await screen.findByRole("combobox", { name: "Record Type" })).toHaveTextContent(".env file");
    await userEvent.type(screen.getByLabelText("Title"), "Web shop{Enter}");
    expect(await screen.findByRole("heading", { name: "New .env file" })).toBeInTheDocument();
    drop([envFile()]);
    await waitFor(() => expect(screen.getByLabelText("File name")).toHaveValue(".env.production"));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.type).toBe("item");
    expect(posted!.encBody).not.toContain("sk_live_1");
    const { body } = await decryptRecord(posted!.id, posted!.encBody, posted!.wrappedRecordKey, userKey);
    expect(body.type).toBe("envFile");
    expect(body.data!.content).toBe(FILE);
  });
});
