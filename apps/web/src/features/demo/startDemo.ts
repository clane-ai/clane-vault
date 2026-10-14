import { b64url, createAccount, randomBytes, type UnlockedKeys } from "@clane-vault/crypto";
import { api } from "@/lib/api";
import { apiUrl, storageKey } from "@/lib/base";
import type { AuthResponse } from "@/lib/session";
import { colleagueMaterial, seedDemo, type Colleague } from "./seed";
import { DEMO_COLLEAGUES } from "./northwind";

/**
 * "Try the demo" (docs/demo.md). Everything secret is made here, in the browser, as in a normal sign-up: a random master
 * password (never shown), the KDF salt, the key pairs and the wrapped keys. The server only makes the sandbox and its
 * one-time invite; the account is created by the normal POST /auth/register, then POST /auth/demo/session lets this
 * demo account in without an authenticator (both checked on the server).
 */

/**
 * The sandbox's master password lives in this tab's sessionStorage only, so a reload (which locks the vault) can unlock
 * it again. Nobody types it; it goes when the tab closes, and the sandbox is deleted on schedule anyway.
 */
const PW_KEY = (userId: string) => storageKey(`cv.demo-password.${userId}`);
export function demoPassword(userId: string): string | null {
  try { return sessionStorage.getItem(PW_KEY(userId)); } catch { return null; }
}
function keepDemoPassword(userId: string, password: string) {
  try { sessionStorage.setItem(PW_KEY(userId), password); } catch { /* private mode: a reload then means a new sandbox */ }
}

async function withSetupToken<T>(path: string, token: string, body: unknown): Promise<T> {
  const res = await fetch(apiUrl(path), { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error((data as { error?: string } | null)?.error ?? "server_error");
  return data as T;
}

export type DemoStep = "account" | "data";

/** Creates, signs in to and fills a sandbox. Returns the sign-in answer and the unlocked keys for the session to install. */
export async function startDemo(onStep: (s: DemoStep) => void = () => {}): Promise<{ res: AuthResponse; keys: UnlockedKeys; authKey: string; orgSlug: string | null; seeded: boolean }> {
  onStep("account");
  const { inviteToken } = await api.post<{ inviteToken: string }>("/auth/demo");
  const password = b64url.encode(randomBytes(32));
  const acct = await createAccount(password);
  const { setupToken } = await api.post<{ setupToken: string }>("/auth/register", { inviteToken, name: "Demo visitor", authKey: acct.authKey, material: acct.material });
  const colleagues = await Promise.all(DEMO_COLLEAGUES.map(async (p) => ({ name: p.name, material: await colleagueMaterial() })));
  const res = await withSetupToken<AuthResponse & { colleagues: Colleague[] }>("/auth/demo/session", setupToken, { colleagues });
  keepDemoPassword(res.user.id, password);
  const org = res.orgs?.[0];
  let seeded = false;
  if (org) {
    onStep("data");
    api.setAccessToken(res.accessToken);
    // The sandbox works without its sample data: a failure here still opens it (the caller says what's missing).
    try { await seedDemo({ orgId: org.id, userId: res.user.id, keys: acct.keys, colleagues: res.colleagues }); seeded = true; } catch { seeded = false; }
  }
  return { res, keys: acct.keys, authKey: acct.authKey, orgSlug: org?.slug ?? null, seeded };
}
