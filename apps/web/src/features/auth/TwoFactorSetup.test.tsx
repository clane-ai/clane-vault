import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { describe, expect, it, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { server } from "@/test/server";
import { SessionProvider } from "@/lib/session";
import TwoFactorSetup from "./TwoFactorSetup";
import Register from "./Register";

vi.mock("@clane-vault/crypto", async (orig) => ({
  ...(await orig<typeof import("@clane-vault/crypto")>()),
  createAccount: vi.fn(async () => ({ authKey: "ak", material: { kdfSalt: "s" } })),
}));

const shell = (ui: React.ReactNode, entry: unknown) => (
  <StrictMode><QueryClientProvider client={new QueryClient()}><SessionProvider>
    <MemoryRouter initialEntries={[entry as string]}>{ui}</MemoryRouter>
  </SessionProvider></QueryClientProvider></StrictMode>
);

describe("TwoFactorSetup", () => {
  it("posts the setup call once under StrictMode", async () => {
    let posts = 0;
    server.use(http.post("/api/v1/auth/totp/setup", () => { posts++; return HttpResponse.json({ otpauthUrl: "otpauth://totp/x?secret=ABC", secret: "ABC" }); }));
    render(shell(<Routes><Route path="/setup-2fa" element={<TwoFactorSetup />} /></Routes>, { pathname: "/setup-2fa", state: { setupToken: "t" } }));
    await screen.findByText("ABC");
    expect(posts).toBe(1);
  });

  it("shows an error with a way back when setup fails", async () => {
    server.use(http.post("/api/v1/auth/totp/setup", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })));
    render(shell(<Routes><Route path="/setup-2fa" element={<TwoFactorSetup />} /></Routes>, { pathname: "/setup-2fa", state: { setupToken: "t" } }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Setup didn't start");
    expect(screen.getByRole("link", { name: "Back to sign in" })).toBeInTheDocument();
  });
});

describe("Register", () => {
  it("keeps the master password out of history.state", async () => {
    server.use(
      http.get("/api/v1/auth/invite/tok", () => HttpResponse.json({ email: "sara@clane.ai" })),
      http.post("/api/v1/auth/register", () => HttpResponse.json({ setupToken: "st" })),
      http.post("/api/v1/auth/totp/setup", () => HttpResponse.json({ otpauthUrl: "otpauth://totp/x?secret=ABC", secret: "ABC" })),
    );
    window.history.replaceState(null, "", "/invite/tok");
    const { BrowserRouter } = await import("react-router");
    render(<QueryClientProvider client={new QueryClient()}><SessionProvider><BrowserRouter>
      <Routes><Route path="/invite/:token" element={<Register />} /><Route path="/setup-2fa" element={<TwoFactorSetup />} /></Routes>
    </BrowserRouter></SessionProvider></QueryClientProvider>);
    await userEvent.type(await screen.findByLabelText("Your name"), "Sara");
    await userEvent.type(screen.getByLabelText("Master password"), "a long master password");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(window.location.pathname).toBe("/setup-2fa"));
    expect(JSON.stringify(window.history.state)).not.toContain("a long master password");
    expect(JSON.stringify(window.history.state)).toContain("st");
  });

  it("shows an error instead of hanging when creating keys fails", async () => {
    const crypto = await import("@clane-vault/crypto");
    vi.mocked(crypto.createAccount).mockRejectedValueOnce(new Error("boom"));
    server.use(http.get("/api/v1/auth/invite/tok", () => HttpResponse.json({ email: "sara@clane.ai" })));
    render(shell(<Routes><Route path="/invite/:token" element={<Register />} /></Routes>, "/invite/tok"));
    await userEvent.type(await screen.findByLabelText("Your name"), "Sara");
    await userEvent.type(screen.getByLabelText("Master password"), "a long master password");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't create your account");
    expect(screen.getByRole("button", { name: "Create account" })).toBeEnabled();
  });
});
