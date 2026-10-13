import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { configureKdfFloor, createAccount, type KdfParams } from "@clane-vault/crypto";
import { server } from "@/test/server";
import { AppRoutes } from "@/routes";
import { api } from "./api";
import { SessionProvider, useSession } from "./session";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
const user = { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" };

function mount(initial = "/") {
  const qc = new QueryClient();
  return render(<QueryClientProvider client={qc}><SessionProvider><MemoryRouter initialEntries={[initial]}><AppRoutes /></MemoryRouter></SessionProvider></QueryClientProvider>);
}

describe("session boot", () => {
  it("resumes a refresh-cookie session into the Unlock screen after a loading state", async () => {
    const acct = await createAccount("resume pw", FAST);
    server.use(http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material })));
    mount();
    expect(screen.getByText("Opening Clane Vault…")).toBeInTheDocument();
    expect(await screen.findByText("Vault locked")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Master password"), "resume pw");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(screen.queryByText("Vault locked")).not.toBeInTheDocument());
  });

  it("falls back to sign-in when the refresh cookie is missing or expired", async () => {
    mount();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("Your session ended. Sign in again.")).not.toBeInTheDocument();
  });

  it("shows the session-ended message on sign-in when the session expires mid-use", async () => {
    const acct = await createAccount("resume pw", FAST);
    server.use(
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material })),
      http.get("/api/v1/me", () => HttpResponse.json({ error: "session_expired" }, { status: 401 })),
    );
    mount();
    await screen.findByText("Vault locked");
    server.use(http.post("/api/v1/auth/refresh", () => HttpResponse.json({ error: "session_expired" }, { status: 401 })));
    await act(async () => { await api.get("/me").catch(() => undefined); });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Your session ended. Sign in again.");
  });

  it("wipes the previous keys and cache before installing new keys on re-sign-in", async () => {
    const acct = await createAccount("pw pw pw pw", FAST);
    server.use(
      http.post("/api/v1/auth/prelogin", () => HttpResponse.json({ kdfSalt: acct.material.kdfSalt, kdfParams: FAST })),
      http.post("/api/v1/auth/login", () => HttpResponse.json({ accessToken: "t", user, material: acct.material })),
    );
    const qc = new QueryClient();
    const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}><SessionProvider>{children}</SessionProvider></QueryClientProvider>;
    const { result } = renderHook(() => useSession(), { wrapper });
    await waitFor(() => expect(result.current.state).toBe("signed_out"));
    await act(() => result.current.signIn("sara@clane.ai", "pw pw pw pw", "123456"));
    const oldKey = result.current.keys!.userKey;
    const stale = new Uint8Array(32).fill(9);
    qc.setQueryData(["vault", "u1"], { folders: [], records: [{ recordKey: stale }] });
    await act(() => result.current.signIn("sara@clane.ai", "pw pw pw pw", "123456"));
    expect(oldKey.every((b) => b === 0)).toBe(true);
    expect(stale.every((b) => b === 0)).toBe(true);
    expect(qc.getQueryData(["vault", "u1"])).toBeUndefined();
    expect(result.current.keys!.userKey.every((b) => b === 0)).toBe(false);
  });

  it("redirects /sign-in to the vault when already signed in", async () => {
    const acct = await createAccount("resume pw", FAST);
    server.use(http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "t", user, material: acct.material })));
    mount("/sign-in");
    expect(await screen.findByText("Vault locked")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });
});
