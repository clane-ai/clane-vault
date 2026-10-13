import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { configureKdfFloor, createAccount, encryptNewRecord, type KdfParams } from "@clane-vault/crypto";
import { server } from "@/test/server";
import { openAccountMenu } from "@/test/nav";
import { AppRoutes } from "@/routes";
import { SessionProvider } from "@/lib/session";

// Multiple organisations in the app: the switcher, X-Org-Id on every request, per-org caches
// (docs/design/2026-10-07-multi-org-design.md §8).
const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
const user = { id: "u1", email: "sara@clane.ai", name: "Sara" };
const A = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Alpha", slug: "alpha", role: "member", isDefault: true };
const B = { id: "bbbbbbbb-0000-4000-8000-000000000002", name: "Beta", slug: "beta", role: "admin", isDefault: false };

async function recordFor(userKey: Uint8Array, title: string) {
  const id = crypto.randomUUID();
  const enc = await encryptNewRecord(id, { type: "login", title, password: "pw" }, userKey);
  return { id, folderId: null, type: "login", encBody: enc.encBody, revision: 1, updatedAt: new Date().toISOString(), deletedAt: null, permission: "owner",
    holderType: "user", wrappedRecordKey: enc.wrappedRecordKey, keyFolderId: null, ownerId: "u1", ownerName: "Sara" };
}

/** Shows where the app is, and goes back like the browser's Back button. */
function Where() {
  const l = useLocation();
  const nav = useNavigate();
  return <><output data-testid="where">{l.pathname}</output><button type="button" onClick={() => void nav(-1)}>History back</button><button type="button" onClick={() => void nav(1)}>History forward</button></>;
}
const where = () => screen.getByTestId("where").textContent;

/**
 * A signed-in session in two orgs; /sync answers per space with a record named after it: no X-Org-Id (Personal) "My
 * secret", an org's ("?space=org") "<Org> secret".
 */
async function setup(opts: { invitations?: unknown[]; at?: string } = {}) {
  const acct = await createAccount("two orgs pw", FAST);
  const byOrg: Record<string, unknown> = { [A.id]: await recordFor(acct.keys.userKey, "Alpha secret"), [B.id]: await recordFor(acct.keys.userKey, "Beta secret"), "-": await recordFor(acct.keys.userKey, "My secret") };
  const seen: (string | null)[] = [];
  const spaces: (string | null)[] = [];
  const accepted: string[] = [];
  let orgs = [A, B];
  let invitations = opts.invitations ?? [];
  server.use(
    http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material, orgs })),
    http.get("/api/v1/sync", ({ request }) => {
      const org = request.headers.get("x-org-id");
      seen.push(org);
      spaces.push(new URL(request.url).searchParams.get("space"));
      const r = byOrg[org ?? "-"];
      return HttpResponse.json({ serverTime: "", folders: [], records: r ? [r] : [] });
    }),
    http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs, invitations, allowOrgCreation: true, instanceAdmin: false })),
    http.post("/api/v1/me/invitations/:orgId/accept", ({ params }) => {
      accepted.push(params.orgId as string);
      orgs = [...orgs, { id: params.orgId as string, name: "Gamma", slug: "gamma", role: "member", isDefault: false }];
      invitations = [];
      return HttpResponse.json({ orgs });
    }),
    http.get("/api/v1/admin/people", () => HttpResponse.json({ users: [], invites: [], invitedMembers: [] })),
    http.get("/api/v1/pending-members", () => HttpResponse.json({ pending: [] })),
    http.get("/api/v1/users", () => HttpResponse.json({ users: [] })),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}><SessionProvider><MemoryRouter initialEntries={[opts.at ?? "/"]}><AppRoutes /><Where /></MemoryRouter></SessionProvider></QueryClientProvider>);
  await userEvent.type(await screen.findByLabelText("Master password"), "two orgs pw");
  await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
  return { qc, seen, spaces, accepted };
}
/** Flat list, so record titles show without opening folder groups. */
const flat = async () => userEvent.click(await screen.findByRole("button", { name: "List" }));

/** Records every moment the page shows `text` while the address is in `prefix` (checked on every DOM change). */
function neverShows(text: string, prefix: string) {
  const bad: string[] = [];
  const check = () => { if (where()?.startsWith(prefix) && document.body.textContent?.includes(text)) bad.push(where()!); };
  const mo = new MutationObserver(check);
  mo.observe(document.body, { subtree: true, childList: true, characterData: true });
  return { bad, stop: () => mo.disconnect() };
}
const switchTo = async (name: RegExp) => {
  await userEvent.click(screen.getByRole("button", { name: /^Space:/ }));
  await userEvent.click(within(await screen.findByRole("menu")).getByRole("menuitem", { name }));
};

describe("spaces in the app: Personal and each organisation", () => {
  beforeEach(() => localStorage.clear());

  it("a new device opens Personal: private items only, no X-Org-Id; the switcher lists Personal and each org", async () => {
    const { seen, spaces } = await setup();
    await flat();
    expect(await screen.findByText("My secret")).toBeInTheDocument();
    expect(where()).toBe("/p/vault");
    expect(screen.getByTestId("active-org")).toHaveTextContent("Personal");
    expect(seen).toEqual([null]);
    expect(spaces).toEqual([null]);
    expect(screen.queryByText("Alpha secret")).not.toBeInTheDocument();
    // Personal has no "Shared with me" (direct shares belong to an organisation).
    expect(screen.queryByRole("link", { name: /^Shared with me/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Space: Personal" }));
    const menu = await screen.findByRole("menu");
    const items = within(menu).getAllByRole("menuitem").map((i) => i.textContent ?? "");
    expect(items[0]).toMatch(/^Personal/);
    expect(items.some((t) => t.includes("Alpha"))).toBe(true);
    expect(items.some((t) => t.includes("Beta"))).toBe(true);
    expect(within(menu).getByRole("menuitem", { name: /^Personal/ })).toHaveAttribute("aria-current", "true");
  });

  it("switching navigates to the org's URL, asks for the org's space only, and never shows another space's data, not even for a frame", async () => {
    const { qc, seen, spaces } = await setup();
    await flat();
    await screen.findByText("My secret");
    const watchA = neverShows("My secret", "/o/");
    await switchTo(/^Alpha/);
    await flat();
    expect(await screen.findByText("Alpha secret")).toBeInTheDocument();
    expect(where()).toBe("/o/alpha/vault");
    expect(screen.getByTestId("active-org")).toHaveTextContent("Alpha");
    expect(seen.at(-1)).toBe(A.id);
    expect(spaces.at(-1)).toBe("org");
    // A member in Alpha: Settings, but no Admin in the account menu.
    let account = await openAccountMenu();
    expect(within(account).getByRole("menuitem", { name: "Settings" })).toBeInTheDocument();
    expect(within(account).queryByRole("menuitem", { name: "Admin" })).not.toBeInTheDocument();
    await userEvent.keyboard("{Escape}");

    const watchB = neverShows("Alpha secret", "/o/beta");
    await switchTo(/^Beta/);
    await flat();
    expect(await screen.findByText("Beta secret")).toBeInTheDocument();
    expect(where()).toBe("/o/beta/vault");
    expect(screen.queryByText("Alpha secret")).not.toBeInTheDocument();
    expect(screen.queryByText("My secret")).not.toBeInTheDocument();
    expect(seen.at(-1)).toBe(B.id);
    // Admin in Beta: Admin appears.
    account = await openAccountMenu();
    expect(within(account).getByRole("menuitem", { name: "Admin" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    // Nothing cached for Alpha (or Personal) survives the switch.
    const keys = qc.getQueryCache().getAll().map((q) => JSON.stringify(q.queryKey));
    expect(keys.some((k) => k.includes(A.id))).toBe(false);
    expect(keys.some((k) => k.includes("u1:-"))).toBe(false);
    expect(keys.some((k) => k.includes(B.id))).toBe(true);
    // Remembered for this user on this device.
    expect(localStorage.getItem("cv.org.u1")).toBe(B.id);

    // Back and forward move between spaces too, each showing only its own data.
    await userEvent.click(screen.getByRole("button", { name: "History back" }));
    await flat();
    expect(await screen.findByText("Alpha secret")).toBeInTheDocument();
    expect(where()).toBe("/o/alpha/vault");
    expect(screen.queryByText("Beta secret")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "History back" }));
    await flat();
    expect(await screen.findByText("My secret")).toBeInTheDocument();
    expect(where()).toBe("/p/vault");
    expect(screen.getByTestId("active-org")).toHaveTextContent("Personal");
    expect(screen.queryByText("Alpha secret")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "History forward" }));
    await flat();
    expect(await screen.findByText("Alpha secret")).toBeInTheDocument();
    expect(screen.queryByText("My secret")).not.toBeInTheDocument();
    watchA.stop(); watchB.stop();
    expect(watchA.bad).toEqual([]);
    expect(watchB.bad).toEqual([]);
    expect(localStorage.getItem("cv.org.u1")).toBe(A.id);
  });

  it("a link into an org opens that org (the URL decides)", async () => {
    await setup({ at: "/o/beta/vault" });
    await flat();
    expect(await screen.findByText("Beta secret")).toBeInTheDocument();
    expect(screen.getByTestId("active-org")).toHaveTextContent("Beta");
  });

  it("an org the user isn't in gets the same page whether it exists or not, and nothing of any space", async () => {
    await setup({ at: "/o/not-mine/vault" });
    expect(await screen.findByTestId("no-space-access")).toBeInTheDocument();
    expect(screen.queryByText("Beta secret")).not.toBeInTheDocument();
    expect(screen.queryByText("My secret")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("link", { name: "Go to your Personal vault" }));
    await flat();
    expect(await screen.findByText("My secret")).toBeInTheDocument();
  });

  it("old paths go to the space used last on this device", async () => {
    localStorage.setItem("cv.org.u1", B.id);
    const { seen } = await setup({ at: "/vault" });
    await flat();
    expect(await screen.findByText("Beta secret")).toBeInTheDocument();
    expect(where()).toBe("/o/beta/vault");
    expect(seen).not.toContain(A.id);
  });

  it("shows pending invitations with a badge; accepting joins and goes to the org", async () => {
    const gamma = "cccccccc-0000-4000-8000-000000000003";
    const { accepted, seen } = await setup({ invitations: [{ orgId: gamma, orgName: "Gamma", role: "member", invitedBy: "Olga", invitedAt: new Date().toISOString() }] });
    await flat();
    await screen.findByText("My secret");
    const trigger = await screen.findByRole("button", { name: "Space: Personal, 1 invitation" });
    await userEvent.click(trigger);
    const menu = await screen.findByRole("menu");
    expect(within(menu).getByText("Gamma")).toBeInTheDocument();
    expect(within(menu).getByText(/from Olga/)).toBeInTheDocument();
    await userEvent.click(within(menu).getByRole("menuitem", { name: "Accept and switch" }));
    await waitFor(() => expect(accepted).toEqual([gamma]));
    await waitFor(() => expect(screen.getByTestId("active-org")).toHaveTextContent("Gamma"));
    expect(where()).toBe("/o/gamma/vault");
    await waitFor(() => expect(seen.at(-1)).toBe(gamma));
  });
});
