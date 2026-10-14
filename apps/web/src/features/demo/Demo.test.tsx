import { clockTime } from "@/lib/time";
import { afterEach, describe, expect, it } from "vitest";
import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { normalizeRecordBody, RECORD_TYPES } from "@clane-vault/crypto";
import { SessionProvider } from "@/lib/session";
import { applyBrand } from "@/brand";
import SignIn from "@/features/auth/SignIn";
import { agreementPdf, NORTHWIND_FOLDERS, PERSONAL_RECORDS } from "./northwind";
import { colleagueMaterial, toRecordBody } from "./seed";
import { DemoBanner } from "./Demo";
import { deletedAt } from "./demoUnlock";

describe("the demo's sample data", () => {
  const all = [...NORTHWIND_FOLDERS.flatMap((f) => f.records), ...PERSONAL_RECORDS];

  it("maps every Northwind record onto its type's template, as the editor would save it", () => {
    for (const r of all) expect(() => normalizeRecordBody(toRecordBody(r))).not.toThrow();
    // Every record type is in there somewhere.
    expect(new Set(all.map((r) => toRecordBody(r).type))).toEqual(new Set(RECORD_TYPES));
  });

  it("puts core fields at the top, the rest in data, options as their values, and custom fields", () => {
    const server = toRecordBody(NORTHWIND_FOLDERS[0]!.records[0]!);
    expect(server).toMatchObject({ v: 2, type: "server", title: "Production web server", username: "deploy", password: "Qm7#vT2x!Rk9pL4w",
      data: { hostname: "10.20.0.5", port: "22", protocol: "ssh" } });
    expect(server.fields).toEqual([{ id: "demo-1", label: "Rack", kind: "text", value: "A3, unit 14" }, { id: "demo-2", label: "Hosting support PIN", kind: "secret", value: "731 904" }]);
  });

  it("refuses a label that isn't in the template", () => {
    expect(() => toRecordBody({ type: "Login", title: "x", fields: { Hostname: "y" } })).toThrow(/isn't a field/);
    expect(() => toRecordBody({ type: "Wi-Fi", title: "x", options: { Security: "WPA9" } })).toThrow(/isn't an option/);
    expect(() => toRecordBody({ type: "Spaceship", title: "x" })).toThrow(/unknown record type/);
  });

  it("has a small PDF to attach", () => {
    const pdf = agreementPdf();
    expect(new TextDecoder().decode(pdf.subarray(0, 8))).toBe("%PDF-1.4");
    expect(pdf.length).toBeLessThan(5 * 1024);
  });

  it("gives made-up colleagues a real public key and nothing anyone can open", async () => {
    const m = await colleagueMaterial();
    expect(m.publicKey).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(m.wrappedUserKey).toMatch(/^v1\./);
    expect(m.kdfParams).toMatchObject({ alg: "argon2id", m: 65536 });
  });
});

describe("the demo's screens", () => {
  afterEach(() => act(() => applyBrand(null)));

  it("the banner says when the sandbox goes and links to the code", () => {
    render(<DemoBanner expiresAt="2026-10-14T15:07:00.000Z" />);
    expect(screen.getByRole("status", { name: "Demo sandbox" })).toHaveTextContent(`Demo sandbox. Deleted at ${deletedAt("2026-10-14T15:07:00.000Z")}. Don't enter real passwords.`);
    // The same format as the status bar's "Synced" time.
    expect(deletedAt("2026-10-14T15:07:00.000Z")).toBe(clockTime("2026-10-14T15:07:00.000Z"));
    expect(screen.getByRole("link", { name: "Self-host it" })).toHaveAttribute("href", "https://github.com/clane-ai/clane-vault");
  });

  it("sign-in offers Try the demo only when the server says it's a demo", async () => {
    const page = () => render(<QueryClientProvider client={new QueryClient()}><SessionProvider><MemoryRouter><SignIn /></MemoryRouter></SessionProvider></QueryClientProvider>);
    const first = page();
    expect(await screen.findByRole("button", { name: "Next" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try the demo" })).not.toBeInTheDocument();
    first.unmount();
    act(() => applyBrand({ productName: null, shortName: null, logoVersion: null, demo: { ttlMinutes: 120 } }));
    page();
    expect(await screen.findByRole("button", { name: "Try the demo" })).toBeInTheDocument();
    expect(screen.getByText(/deleted 2 hours after you start/)).toBeInTheDocument();
  });
});
