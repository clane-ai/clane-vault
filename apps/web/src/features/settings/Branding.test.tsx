import { MemoryRouter } from "react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import { applyBrand, buildBrand, loadBrand, useBrand } from "@/brand";
import { Logo } from "@/components/brand/Logo";
import { AuthLayout } from "@/features/auth/AuthLayout";
import { OrgAvatar } from "@/features/orgs/OrgLogo";
import { OrgDetailsSection } from "@/features/orgs/OrgSettings";
import { BrandingSection } from "./BrandingSection";

// Radix switches in the org's policies measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;

const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>);
function Name() { return <p data-testid="name">{useBrand().productName}</p>; }

afterEach(() => { applyBrand(null); localStorage.clear(); vi.restoreAllMocks(); });

describe("runtime branding (GET /api/v1/brand)", () => {
  it("uses the names an instance admin set, in the page title and the logo", async () => {
    server.use(http.get("/api/v1/brand", () => HttpResponse.json({ productName: "Acme Keys", shortName: "Keys", logoVersion: null })));
    render(<><Name /><Logo /></>);
    await act(() => loadBrand());
    expect(screen.getByTestId("name")).toHaveTextContent("Acme Keys");
    expect(document.title).toBe("Acme Keys");
    // Not a "Clane …" name: plain text, no CLANE wordmark.
    expect(screen.getByRole("img", { name: "Acme Keys" })).toHaveAttribute("data-name", "text");
    expect(screen.getByText("Acme Keys", { selector: "span" })).toBeInTheDocument();
  });

  it("falls back to the build's names when the endpoint fails, is missing or sends junk", async () => {
    render(<Name />);
    server.use(http.get("/api/v1/brand", () => HttpResponse.json({ error: "server_error" }, { status: 500 })));
    await act(() => loadBrand());
    expect(screen.getByTestId("name")).toHaveTextContent(buildBrand.productName);
    server.use(http.get("/api/v1/brand", () => HttpResponse.error()));
    await act(() => loadBrand());
    expect(screen.getByTestId("name")).toHaveTextContent("Clane Vault");
    server.use(http.get("/api/v1/brand", () => HttpResponse.json({ productName: "<img src=x onerror=alert(1)>", shortName: "x".repeat(80), logoVersion: "../../etc" })));
    await act(() => loadBrand());
    expect(screen.getByTestId("name")).toHaveTextContent("Clane Vault");
    expect(document.title).toBe("Clane Vault");
  });

  it("shows the instance logo on the sign-in screen, with the name beside it", async () => {
    server.use(http.get("/api/v1/brand", () => HttpResponse.json({ productName: "Acme Keys", shortName: null, logoVersion: "abcdef0123456789" })));
    await loadBrand();
    render(<AuthLayout title="Sign in"><p>form</p></AuthLayout>);
    const logo = screen.getByTestId("instance-logo");
    expect(logo).toHaveAccessibleName("Acme Keys");
    expect(logo.querySelector("img")).toHaveAttribute("src", "/api/v1/brand/logo?v=abcdef0123456789");
  });
});

describe("Settings → Server → Branding", () => {
  it("instance admins save names (validated) and go back to the defaults", async () => {
    let body: unknown = null;
    let stored = { productName: null as string | null, shortName: null as string | null, logoVersion: null };
    server.use(
      http.get("/api/v1/admin/instance/brand", () => HttpResponse.json(stored)),
      http.put("/api/v1/admin/instance/brand", async ({ request }) => { body = await request.json(); stored = { ...stored, ...(body as object) }; return HttpResponse.json(stored); }),
    );
    wrap(<><BrandingSection /><Name /></>);
    const name = await screen.findByLabelText("Product name");
    await waitFor(() => expect(name).toBeEnabled());
    await userEvent.type(name, "Acme <b>");
    await userEvent.click(screen.getByRole("button", { name: "Save names" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Leave out < and >.");
    expect(body).toBeNull();
    await userEvent.clear(name);
    await userEvent.type(name, "Acme Keys");
    await userEvent.type(screen.getByLabelText("Short name"), "Keys");
    await userEvent.click(screen.getByRole("button", { name: "Save names" }));
    await waitFor(() => expect(body).toEqual({ productName: "Acme Keys", shortName: "Keys" }));
    expect(await screen.findByTestId("name")).toHaveTextContent("Acme Keys");
    await userEvent.click(screen.getByRole("button", { name: "Use defaults" }));
    await waitFor(() => expect(body).toEqual({ productName: null, shortName: null }));
    await waitFor(() => expect(screen.getByTestId("name")).toHaveTextContent("Clane Vault"));
  });
});

describe("organisation logo", () => {
  it("shows the logo (fetched with the token as a blob) and falls back to the initials", async () => {
    const created = vi.fn(() => "blob:logo-1");
    const orig = URL.createObjectURL;
    URL.createObjectURL = created;
    let auth: string | null = null;
    server.use(http.get("/api/v1/orgs/o1/logo", ({ request }) => { auth = request.headers.get("x-org-id"); return new HttpResponse(new Uint8Array([0x89, 0x50]), { headers: { "content-type": "image/png" } }); }));
    server.use(http.get("/api/v1/orgs/o2/logo", () => HttpResponse.json({ error: "not_found" }, { status: 404 })));
    wrap(<><OrgAvatar org={{ id: "o1", name: "Acme Ltd", logoVersion: "v1" }} /><span data-testid="b"><OrgAvatar org={{ id: "o2", name: "Beta Corp", logoVersion: "v2" }} /></span><span data-testid="c"><OrgAvatar org={{ id: "o3", name: "Gamma" }} /></span></>);
    const img = await screen.findByTestId("org-logo");
    expect(img.querySelector("img")).toHaveAttribute("src", "blob:logo-1");
    expect(auth).toBeNull(); // the logo URL names the org; no X-Org-Id needed
    await waitFor(() => expect(screen.getByTestId("b")).toHaveTextContent("BC"));
    expect(screen.getByTestId("c")).toHaveTextContent("G");
    expect(created).toHaveBeenCalledOnce();
    URL.createObjectURL = orig;
  });

  it("owners and admins upload one in Organisation settings; SVG and big files are refused before upload", async () => {
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ org: { id: "o1", name: "Acme", slug: "acme", role: "admin", isDefault: true }, orgs: [], applyOrgs: vi.fn(), user: { id: "u1", name: "Sara", email: "s@a.test", role: "admin" } } as never);
    let uploaded: string | null = null;
    server.use(
      http.get("/api/v1/org", () => HttpResponse.json({ id: "o1", name: "Acme", slug: "acme", createdAt: "", isDefault: true, myRole: "admin", memberCount: 2, teamFolderCount: 0, owner: null, logoVersion: null })),
      http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
      http.put("/api/v1/org/logo", async ({ request }) => { uploaded = request.headers.get("content-type"); return HttpResponse.json({ logoVersion: "abc" }); }),
    );
    wrap(<OrgDetailsSection />);
    const group = await screen.findByRole("group", { name: "Organisation logo" });
    expect(within(group).getByText(/PNG, JPEG or WebP, up to 256 KB/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rename" })).toBeInTheDocument();
    const input = within(group).getByLabelText("Upload organisation logo");
    expect(input).toHaveAttribute("accept", "image/png,image/jpeg,image/webp");
    await userEvent.upload(input, new File(["<svg/>"], "logo.svg", { type: "image/svg+xml" }), { applyAccept: false });
    expect(await within(group).findByRole("alert")).toHaveTextContent("SVG isn't accepted");
    await userEvent.upload(input, new File([new Uint8Array(300 * 1024)], "big.png", { type: "image/png" }));
    expect(await within(group).findByRole("alert")).toHaveTextContent("over 256 KB");
    expect(uploaded).toBeNull();
    await userEvent.upload(input, new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], "logo.png", { type: "image/png" }));
    await waitFor(() => expect(uploaded).toBe("image/png"));
  });
});
