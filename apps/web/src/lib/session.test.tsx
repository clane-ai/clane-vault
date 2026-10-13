import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { configureKdfFloor, createAccount, type KdfParams } from "@clane-vault/crypto";
import { server } from "@/test/server";
import { SessionProvider, useSession, IDLE_LOCK_MS } from "./session";

const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
configureKdfFloor({ m: 1024, t: 1 });
const qc = new QueryClient();
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}><SessionProvider>{children}</SessionProvider></QueryClientProvider>;

async function mockAccount(password: string) {
  const acct = await createAccount(password, FAST);
  const user = { id: "u1", email: "sara@clane.ai", name: "Sara", role: "member" };
  server.use(
    http.post("/api/v1/auth/prelogin", () => HttpResponse.json({ kdfSalt: acct.material.kdfSalt, kdfParams: FAST })),
    http.post("/api/v1/auth/login", async ({ request }) => {
      const b = (await request.json()) as { authKey: string; code?: string };
      if (b.authKey !== acct.authKey) return HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
      if (!b.code) return HttpResponse.json({ error: "totp_required" }, { status: 401 });
      return HttpResponse.json({ accessToken: "t", user, material: acct.material });
    }),
    http.post("/api/v1/auth/logout", () => new HttpResponse(null, { status: 204 })),
  );
  return acct;
}

describe("session security", () => {
  it("wipes cached vault data and zeroes record keys on lock and sign-out", async () => {
    await mockAccount("pw pw pw pw");
    const { result } = renderHook(() => useSession(), { wrapper });
    await act(() => result.current.signIn("sara@clane.ai", "pw pw pw pw", "123456"));
    const k1 = new Uint8Array(32).fill(7);
    qc.setQueryData(["vault", "u1"], { folders: [], records: [{ recordKey: k1 }] });
    act(() => result.current.lock());
    expect(qc.getQueryData(["vault", "u1"])).toBeUndefined();
    expect(k1.every((b) => b === 0)).toBe(true);
    await act(() => result.current.unlock("pw pw pw pw"));
    const k2 = new Uint8Array(32).fill(7);
    qc.setQueryData(["vault", "u1"], { folders: [], records: [{ recordKey: k2 }] });
    await act(() => result.current.signOut());
    expect(qc.getQueryData(["vault", "u1"])).toBeUndefined();
    expect(k2.every((b) => b === 0)).toBe(true);
  });

  it("does not auto-lock when there was activity just before the idle time", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await mockAccount("pw pw pw pw");
    const { result } = renderHook(() => useSession(), { wrapper });
    await act(() => result.current.signIn("sara@clane.ai", "pw pw pw pw", "123456"));
    act(() => { vi.advanceTimersByTime(IDLE_LOCK_MS - 1000); window.dispatchEvent(new KeyboardEvent("keydown")); });
    act(() => { vi.advanceTimersByTime(5000); });
    expect(result.current.state).toBe("unlocked");
    vi.useRealTimers();
  });

  it("returns a result (not a throw) when prelogin is rate limited", async () => {
    server.use(http.post("/api/v1/auth/prelogin", () => HttpResponse.json({ error: "rate_limited" }, { status: 429 })));
    const { result } = renderHook(() => useSession(), { wrapper });
    expect(await act(() => result.current.signIn("a@b.co", "x"))).toEqual({ kind: "error", code: "rate_limited" });
  });
});

describe("session", () => {
  it("signs in, unlocks keys, locks and unlocks again", async () => {
    const acct = await mockAccount("the right password");
    const { result } = renderHook(() => useSession(), { wrapper });
    expect((await act(() => result.current.signIn("sara@clane.ai", "the right password"))) ).toEqual({ kind: "error", code: "totp_required" });
    await act(() => result.current.signIn("sara@clane.ai", "the right password", "123456"));
    expect(result.current.state).toBe("unlocked");
    expect(result.current.keys!.userKey).toEqual(acct.keys.userKey);
    act(() => result.current.lock());
    expect(result.current.state).toBe("locked");
    expect(result.current.keys).toBeNull();
    await expect(act(() => result.current.unlock("wrong password"))).rejects.toThrow("That master password is not right");
    expect(result.current.state).toBe("locked");
    await act(() => result.current.unlock("the right password"));
    expect(result.current.state).toBe("unlocked");
  });

  it("auto-locks after the idle time", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await mockAccount("pw pw pw pw");
    const { result } = renderHook(() => useSession(), { wrapper });
    await act(() => result.current.signIn("sara@clane.ai", "pw pw pw pw", "123456"));
    act(() => { vi.advanceTimersByTime(IDLE_LOCK_MS + 1000); });
    await waitFor(() => expect(result.current.state).toBe("locked"));
    vi.useRealTimers();
  });
});

describe("session: recovery kit", () => {
  it("after 2FA setup without a kit, asks for one and keeps the auth key as proof until it is saved", async () => {
    const acct = await createAccount("pw pw pw pw", FAST);
    const { result } = renderHook(() => useSession(), { wrapper });
    act(() => result.current.beginTwoFactor("setup", "pw pw pw pw"));
    await act(() => result.current.completeTwoFactor({ accessToken: "t", user: { id: "u1", email: "s@c.ai", name: "S", role: "member", recoveryKit: false }, material: acct.material }));
    expect(result.current.state).toBe("unlocked");
    expect(result.current.kitRequired).toBe("signup");
    expect(result.current.kitProof()).toBe(acct.authKey);
    act(() => result.current.kitCreated());
    expect(result.current.kitRequired).toBeNull();
    expect(result.current.kitProof()).toBeNull();
    expect(result.current.user?.recoveryKit).toBe(true);
  });

  it("no kit screen when the account already has one; proveMaster checks the password locally", async () => {
    const acct = await createAccount("pw pw pw pw", FAST);
    const { result } = renderHook(() => useSession(), { wrapper });
    act(() => result.current.beginTwoFactor("setup", "pw pw pw pw"));
    await act(() => result.current.completeTwoFactor({ accessToken: "t", user: { id: "u1", email: "s@c.ai", name: "S", role: "member", recoveryKit: true }, material: acct.material }));
    expect(result.current.kitRequired).toBeNull();
    expect(await result.current.proveMaster("pw pw pw pw")).toBe(acct.authKey);
    await expect(result.current.proveMaster("nope nope nope")).rejects.toThrow("That master password is not right");
  });

  it("completeRecovery installs the recovered keys and requires a new kit; locking drops the proof", async () => {
    const acct = await createAccount("pw pw pw pw", FAST);
    const { result } = renderHook(() => useSession(), { wrapper });
    await waitFor(() => expect(result.current.state).toBe("signed_out"));
    act(() => result.current.completeRecovery({ accessToken: "t", user: { id: "u1", email: "s@c.ai", name: "S", role: "member", recoveryKit: false }, material: acct.material }, acct.keys, "AK", { requireKit: true }));
    expect(result.current.state).toBe("unlocked");
    expect(result.current.keys?.userKey).toEqual(acct.keys.userKey);
    expect(result.current.kitRequired).toBe("recovery");
    expect(result.current.kitProof()).toBe("AK");
    act(() => result.current.lock());
    expect(result.current.kitProof()).toBeNull();
  });
});
