import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import OAuthAuthorize from "./OAuthAuthorize";
import { oauthNav } from "./oauthNav";

afterEach(() => vi.restoreAllMocks());

const Q = "?client_id=c1&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&response_type=code&code_challenge=abc&code_challenge_method=S256&state=st1";
const A1 = { id: "a1", name: "Billing bot", orgId: "o1", orgName: "Acme" };
const A2 = { id: "a2", name: "Ops bot", orgId: "o2", orgName: "Globex" };
const INFO = "/api/v1/oauth/authorize/info";

function Where() { const l = useLocation(); return <p data-testid="where">{l.pathname}{l.search}|{JSON.stringify(l.state)}</p>; }
function renderPage(session: object = { state: "unlocked", orgs: [{ id: "o1", role: "admin" }] }, query = Q) {
  vi.spyOn(sessionModule, "useSession").mockReturnValue(session as never);
  const go = vi.spyOn(oauthNav, "go").mockImplementation(() => undefined);
  render(<MemoryRouter initialEntries={["/oauth/authorize" + query]}><Routes>
    <Route path="/oauth/authorize" element={<OAuthAuthorize />} /><Route path="*" element={<Where />} />
  </Routes></MemoryRouter>);
  return go;
}

describe("OAuth consent page", () => {
  it("shows the client and redirect host, and Allow posts the chosen agent with its org", async () => {
    let seen: { org: string | null; body: unknown } | null = null;
    server.use(
      http.get(INFO, () => HttpResponse.json({ client: { name: "Claude" }, agents: [A1, A2] })),
      http.post("/api/v1/oauth/authorize", async ({ request }) => { seen = { org: request.headers.get("x-org-id"), body: await request.json() }; return HttpResponse.json({ redirectTo: "https://claude.ai/cb?code=XYZ&state=st1" }); }),
    );
    const go = renderPage();
    expect(await screen.findByText(/Claude wants to use vault credentials/)).toBeInTheDocument();
    expect(screen.getByTestId("redirect-host")).toHaveTextContent("claude.ai");
    expect(screen.getByRole("button", { name: "Allow" })).toBeDisabled();
    await userEvent.click(screen.getByRole("radio", { name: /Ops bot/ }));
    await userEvent.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("https://claude.ai/cb?code=XYZ&state=st1"));
    expect(seen).toEqual({ org: "o2", body: { clientId: "c1", redirectUri: "https://claude.ai/cb", codeChallenge: "abc", codeChallengeMethod: "S256", state: "st1", agentId: "a2" } });
  });

  it("refuses a consent answer that points somewhere else", async () => {
    server.use(
      http.get(INFO, () => HttpResponse.json({ client: { name: "Claude" }, agents: [A1] })),
      http.post("/api/v1/oauth/authorize", () => HttpResponse.json({ redirectTo: "https://evil.test/cb?code=XYZ" })),
    );
    const go = renderPage();
    await userEvent.click(await screen.findByRole("radio", { name: /Billing bot/ }));
    await userEvent.click(screen.getByRole("button", { name: "Allow" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't connect");
    expect(go).not.toHaveBeenCalled();
  });

  it("Deny redirects with access_denied and the state, only after info succeeded", async () => {
    server.use(http.get(INFO, () => HttpResponse.json({ client: { name: "Claude" }, issuer: "https://vault.test", agents: [A1] })));
    const go = renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Deny" }));
    expect(go).toHaveBeenCalledWith("https://claude.ai/cb?error=access_denied&state=st1&iss=https%3A%2F%2Fvault.test");
  });

  it("an invalid request says so and never redirects", async () => {
    server.use(http.get(INFO, () => HttpResponse.json({ error: "invalid_redirect_uri" }, { status: 400 })));
    const go = renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("This connection request isn't valid. Start again from your AI app.");
    expect(screen.queryByRole("button", { name: "Deny" })).not.toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
  });

  it("agents off (404) says so", async () => {
    server.use(http.get(INFO, () => HttpResponse.json({ error: "not_found" }, { status: 404 })));
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("Agent access isn't turned on for this server.");
  });

  it("a member gets the ask-an-admin line and no Allow", async () => {
    server.use(http.get(INFO, () => HttpResponse.json({ client: { name: "Claude" }, agents: [] })));
    renderPage({ state: "unlocked", orgs: [{ id: "o1", role: "member" }] });
    expect(await screen.findByText(/Only owners and admins can connect agents/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow" })).not.toBeInTheDocument();
  });

  it("signed out goes to sign-in and comes back with the query", async () => {
    renderPage({ state: "signed_out", orgs: [] });
    const where = await screen.findByTestId("where");
    expect(where).toHaveTextContent("/sign-in");
    expect(where.textContent).toContain(JSON.stringify({ from: { pathname: "/oauth/authorize", search: Q } }));
  });

  it("a repeated parameter is invalid: no info call, no redirect, no Deny", async () => {
    const info = vi.fn();
    server.use(http.get(INFO, () => { info(); return HttpResponse.json({ client: { name: "C" }, agents: [A1] }); }));
    const go = renderPage(undefined, Q + "&redirect_uri=https%3A%2F%2Fevil.test%2Fcb");
    expect(await screen.findByRole("alert")).toHaveTextContent("isn't valid");
    expect(screen.queryByRole("button", { name: "Deny" })).not.toBeInTheDocument();
    expect(info).not.toHaveBeenCalled();
    expect(go).not.toHaveBeenCalled();
  });

  it.each(["javascript:alert(1)", "data:text/html,x"])("refuses a %s redirect_uri without calling info", async (u) => {
    const info = vi.fn();
    server.use(http.get(INFO, () => { info(); return HttpResponse.json({ client: { name: "C" }, agents: [A1] }); }));
    renderPage(undefined, `?client_id=c1&redirect_uri=${encodeURIComponent(u)}`);
    expect(await screen.findByRole("alert")).toHaveTextContent("isn't valid");
    expect(info).not.toHaveBeenCalled();
  });

  it("an admin with no agents is pointed to the Agents page, and Cancel denies", async () => {
    server.use(http.get(INFO, () => HttpResponse.json({ client: { name: "Claude" }, agents: [] })));
    const go = renderPage();
    expect(await screen.findByText(/no verified agents yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(go).toHaveBeenCalledWith("https://claude.ai/cb?error=access_denied&state=st1");
  });
});
