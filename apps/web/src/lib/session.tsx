import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { deriveLoginKeys, unlockAccount, type AccountMaterial, type KdfParams, type UnlockedKeys } from "@clane-vault/crypto";
import { toast } from "sonner";
import { api, ApiError } from "./api";
import type { OrgPolicies } from "./policies";
import { isUnreachable, loadCopy, saveAccount, setOfflineEnabled, wipeOffline } from "./offline";
import { storageKey } from "@/lib/base";
import { cancelAllTransfers } from "@/features/attachments/transfers";

export const IDLE_LOCK_MS = 15 * 60_000;
/**
 * `recoveryKit`: whether the account has a recovery kit (docs/recovery.md). `role`: the role in the active organisation
 * (owners count as admins); `orgRole` tells owners apart.
 */
export interface User { id: string; email: string; name: string; role: "admin" | "member"; orgRole?: OrgRole | null; recoveryKit?: boolean;
  /** A public demo sandbox account (docs/demo.md): when it and everything in it is deleted (ISO time). */ demoExpiresAt?: string }
export type OrgRole = "owner" | "admin" | "member";
/** An organisation the user is an active member of (docs/design/2026-10-07-multi-org-design.md). */
/** `policies`: the org's policies for clients (docs/policies.md); read them with useOrgPolicies() in lib/policies. */
export interface Org { id: string; name: string; slug: string; role: OrgRole; isDefault: boolean;
  /** Version of the org logo (docs/branding.md); null or absent: none. */ logoVersion?: string | null; policies?: Partial<OrgPolicies> & { links?: Partial<OrgPolicies["links"]>; attachments?: Partial<OrgPolicies["attachments"]> } }
export type SignInResult = { kind: "ok" } | { kind: "needs_totp_setup"; setupToken: string } | { kind: "error"; code: string; retryAfterSeconds?: number };
export interface AuthResponse { accessToken: string; user: Omit<User, "role"> & { role?: string }; material: AccountMaterial; orgs?: Org[] }
/** Why the app must show the recovery-kit screen before the vault: right after sign-up (2FA setup) or after a recovery. */
export type KitRequired = "signup" | "recovery" | null;

interface SessionValue {
  state: "loading" | "signed_out" | "locked" | "unlocked";
  reason: "expired" | null;
  user: User | null;
  keys: UnlockedKeys | null;
  signIn(email: string, password: string, code?: string): Promise<SignInResult>;
  beginTwoFactor(setupToken: string, password: string): void;
  completeTwoFactor(res: AuthResponse): Promise<void>;
  generation(): number;
  unlock(password: string): Promise<void>;
  lock(): void;
  signOut(): Promise<void>;
  kitRequired: KitRequired;
  /** Installs a session from a finished recovery (keys already recovered on this device). */
  completeRecovery(res: AuthResponse, keys: UnlockedKeys, authKey: string, opts: { requireKit: boolean }): void;
  /** The master password's auth key, checked locally first; the server asks for it before changing the recovery kit. */
  proveMaster(password: string): Promise<string>;
  /** The auth key from the sign-up or recovery that just happened (so the kit screen needn't ask again); cleared on lock and once the kit is saved. */
  kitProof(): string | null;
  /** The kit screen is done: the account now has a kit. */
  kitCreated(): void;
  /**
   * The active space's organisation (null: the Personal space) and every org the user is active in. The URL decides the
   * space (lib/paths, SpaceGate in routes.tsx); this is what the app renders for.
   */
  org: Org | null;
  orgs: Org[];
  /** Makes an org (or null: Personal) the active space: space-scoped caches (and decrypted keys in them) are dropped first. Navigation calls this, through the URL. */
  switchOrg(id: string | null): void;
  /** Installs a fresh list of orgs (after accepting, creating, leaving...); keeps the active space if it's still there (else Personal). Opening another space is navigation. */
  applyOrgs(orgs: Org[]): void;
  /** Finishes an SSO sign-in (docs/sso.md): the IdP's proof plus the master password (and a 2FA code unless the org trusts its IdP's MFA). */
  signInWithSso(proof: string, email: string, password: string, code?: string, kdf?: { kdfSalt: string; kdfParams: KdfParams }): Promise<SignInResult>;
  /** A request answered `totp_step_up_required`: this session skipped the authenticator code (trusted IdP MFA). */
  stepUpRequired: boolean;
  /** Proves the authenticator code for this session; afterwards every organisation and the private vault work. */
  stepUp(code: string): Promise<void>;
  /** Shows the step-up prompt (e.g. from the locked "Private items" row). */
  requestStepUp(): void;
  /** The active org answered `sso_required`: this session must come from that org's SSO. */
  ssoBlocked: string | null;
  /** The server can't be reached: the account and vault come from this device's offline copy, read-only (docs/install-app.md). */
  offline: boolean;
  /** The per-device "offline copy" setting: off wipes the copy now, on saves one from the next sync. */
  setOfflineCopy(on: boolean): void;
}

/** The space used last on this device, per user: an org id, or "-" for Personal. */
const ORG_KEY = (userId: string) => storageKey(`cv.org.${userId}`);
const PERSONAL_MARK = "-";
const readOrg = (userId: string) => { try { return localStorage.getItem(ORG_KEY(userId)); } catch { return null; } };
const writeOrg = (userId: string, id: string | null) => { try { localStorage.setItem(ORG_KEY(userId), id ?? PERSONAL_MARK); } catch { /* private mode */ } };
/** Makes this org the space a new sign-in of `userId` on this device opens first (the demo opens its sandbox's org). */
export const rememberSpace = (userId: string, orgId: string | null) => writeOrg(userId, orgId);
/** Which space to open: an org id, null (Personal), or the one used last on this device ("remembered"; Personal when there is none). */
export type SpaceChoice = string | null | "remembered";
/** The org of that space, among the user's orgs; null (Personal) when it isn't one of them. */
function pickOrg(orgs: Org[], userId: string, want: SpaceChoice): Org | null {
  const id = want === "remembered" ? readOrg(userId) : want;
  return (id && orgs.find((o) => o.id === id)) || null;
}
/** Query keys that don't depend on the active org (kept when switching). */
const GLOBAL_QUERIES = new Set(["security", "recovery-options", "me-orgs", "admin-backups"]);

const LOGOUT_PENDING = storageKey("cv.logout-pending");
const flag = { get: () => { try { return localStorage.getItem(LOGOUT_PENDING) === "1"; } catch { return false; } },
  set: (on: boolean) => { try { if (on) localStorage.setItem(LOGOUT_PENDING, "1"); else localStorage.removeItem(LOGOUT_PENDING); } catch { /* private mode */ } } };
/** Refresh answers that mean "no session here" (not "can't reach the server"): the offline copy goes too. */
const refused = (e: unknown) => e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 429;

const Ctx = createContext<SessionValue | null>(null);
/** The account from a sign-in response; its role is filled in from the active org. */
const toUser = (u: AuthResponse["user"]): User => ({ id: u.id, email: u.email, name: u.name, role: "member", ...(u.recoveryKit !== undefined ? { recoveryKit: u.recoveryKit } : {}),
  ...(u.demoExpiresAt ? { demoExpiresAt: u.demoExpiresAt } : {}) });
const wipe = (k: UnlockedKeys | null) => { k?.userKey.fill(0); k?.privateKey.fill(0); };

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [material, setMaterial] = useState<AccountMaterial | null>(null);
  const [keys, setKeys] = useState<UnlockedKeys | null>(null);
  const [booting, setBooting] = useState(true);
  const [reason, setReason] = useState<"expired" | null>(null);
  const bootedRef = useRef(false);
  const keysRef = useRef<UnlockedKeys | null>(null);
  keysRef.current = keys;

  const qc = useQueryClient();
  const genRef = useRef(0);
  const pendingRef = useRef<string | null>(null);
  const kitProofRef = useRef<string | null>(null);
  const [kitRequired, setKitRequired] = useState<KitRequired>(null);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [ssoBlocked, setSsoBlocked] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);
  useEffect(() => api.onSsoRequired((id) => setSsoBlocked(id)), []);
  const [stepUpRequired, setStepUpRequired] = useState(false);
  useEffect(() => api.onStepUpRequired(() => setStepUpRequired(true)), []);

  /** Zeroes the record and folder keys held in the vault cache and drops it. */
  const wipeVaultCache = useCallback(() => {
    for (const q of qc.getQueryCache().findAll({ queryKey: ["vault"] })) {
      const d = q.state.data as { records?: { recordKey: Uint8Array | null }[]; folders?: { folderKey?: Uint8Array | null }[] } | undefined;
      d?.records?.forEach((r) => r.recordKey?.fill(0));
      d?.folders?.forEach((f) => f.folderKey?.fill(0));
    }
    qc.removeQueries({ queryKey: ["vault"] });
  }, [qc]);
  const lock = useCallback(() => {
    genRef.current++;
    // File uploads and downloads stop and zero their keys with everything else (docs/attachments.md).
    cancelAllTransfers();
    kitProofRef.current = null;
    wipe(keysRef.current); setKeys(null);
    wipeVaultCache();
  }, [wipeVaultCache]);

  /** Makes `id` the active org: nothing cached for another org survives (keys included). */
  const activate = useCallback((userId: string, id: string | null) => {
    if (api.org() !== id) {
      genRef.current++; // in-flight decryptions for the old org are discarded
      wipeVaultCache();
      qc.removeQueries({ predicate: (q) => !GLOBAL_QUERIES.has(String(q.queryKey[0])) });
      setSsoBlocked(null);
    }
    api.setOrg(id);
    setOrgId(id);
    writeOrg(userId, id);
  }, [qc, wipeVaultCache]);
  const installOrgs = useCallback((userId: string, list: Org[], want?: SpaceChoice) => {
    setOrgs((cur) => (JSON.stringify(cur) === JSON.stringify(list) ? cur : list));
    // undefined: keep the current space (Personal if its org went away); "remembered" (a new sign-in): the last one used here.
    activate(userId, pickOrg(list, userId, want === undefined ? api.org() : want)?.id ?? null);
  }, [activate]);

  const clear = useCallback(() => {
    lock(); setUser(null); setMaterial(null); setKitRequired(null); api.setAccessToken(null); pendingRef.current = null;
    api.setOrg(null); setOrgId(null); setOrgs([]);
    qc.removeQueries({ predicate: (q) => String(q.queryKey[0]) !== "recovery-options" });
    setOffline(false); void wipeOffline();
  }, [lock, qc]);
  useEffect(() => api.onSessionEnded(() => { clear(); setReason("expired"); toast.info("Your session ended. Sign in again."); }), [clear]);

  // Resume after a reload: the httpOnly refresh cookie gives a new access token plus the encrypted key material, so only the master password is needed.
  useEffect(() => {
    if (bootedRef.current) return;
    bootedRef.current = true;
    // Signed out while offline: end that server session first; nothing resumes until it's done.
    if (flag.get()) { void api.post("/auth/logout").then(() => flag.set(false)).catch(() => undefined).finally(() => setBooting(false)); return; }
    api.post<AuthResponse>("/auth/refresh")
      .then((res) => { api.setAccessToken(res.accessToken); installOrgs(res.user.id, res.orgs ?? [], "remembered"); setUser(toUser(res.user)); setMaterial(res.material); void saveAccount(res.user, res.material, res.orgs ?? []); })
      .catch(async (e) => {
        if (refused(e)) { await wipeOffline(); return; }
        if (!isUnreachable(e)) return;
        // Can't reach the server: offer the offline copy (unlock with the master password, read-only).
        const c = await loadCopy();
        if (!c) return;
        const o = pickOrg(c.orgs, c.userId, "remembered");
        api.setOrg(o?.id ?? null); setOrgId(o?.id ?? null); setOrgs(c.orgs);
        setOffline(true); setUser(toUser({ id: c.userId, email: c.email, name: c.name, ...(c.recoveryKit !== undefined ? { recoveryKit: c.recoveryKit } : {}) })); setMaterial(c.material);
      })
      .finally(() => setBooting(false));
  }, []);

  const install = useCallback((res: AuthResponse, k: UnlockedKeys) => {
    lock(); // wipe any keys and vault cache left from a previous session before installing the new ones
    setReason(null); setSsoBlocked(null); setStepUpRequired(false);
    api.setAccessToken(res.accessToken);
    installOrgs(res.user.id, res.orgs ?? [], "remembered");
    setUser(toUser(res.user)); setMaterial(res.material); setKeys(k);
    setOffline(false); void saveAccount(res.user, res.material, res.orgs ?? []);
  }, [lock, installOrgs]);

  const open = useCallback(async (res: AuthResponse, password: string): Promise<string> => {
    const { wrapKey, authKey } = await deriveLoginKeys(password, res.material.kdfSalt, res.material.kdfParams as KdfParams);
    const k = await unlockAccount(wrapKey, res.material);
    wrapKey.fill(0);
    install(res, k);
    return authKey;
  }, [install]);

  const signIn = useCallback(async (email: string, password: string, code?: string): Promise<SignInResult> => {
    let pre: { kdfSalt: string; kdfParams: KdfParams };
    try { pre = await api.post<{ kdfSalt: string; kdfParams: KdfParams }>("/auth/prelogin", { email }); }
    catch (e) { if (e instanceof ApiError) return { kind: "error", code: e.code }; throw e; }
    const { authKey, wrapKey } = await deriveLoginKeys(password, pre.kdfSalt, pre.kdfParams);
    wrapKey.fill(0);
    try {
      const res = await api.post<AuthResponse | { needsTotpSetup: true; setupToken: string }>("/auth/login", { email, authKey, ...(code ? { code } : {}) });
      if ("needsTotpSetup" in res) return { kind: "needs_totp_setup", setupToken: res.setupToken };
      await open(res, password);
      return { kind: "ok" };
    } catch (e) {
      if (e instanceof ApiError) {
        const r = (e.body as { retryAfterSeconds?: number } | null)?.retryAfterSeconds;
        return r === undefined ? { kind: "error", code: e.code } : { kind: "error", code: e.code, retryAfterSeconds: r };
      }
      throw e;
    }
  }, [open]);

  const signInWithSso = useCallback(async (proof: string, email: string, password: string, code?: string, kdf?: { kdfSalt: string; kdfParams: KdfParams }): Promise<SignInResult> => {
    // The proof says which account (and its KDF salt): the identity provider's address may differ from the account's.
    let pre: { kdfSalt: string; kdfParams: KdfParams };
    if (kdf) pre = kdf;
    else {
      try { pre = await api.post<{ kdfSalt: string; kdfParams: KdfParams }>("/auth/prelogin", { email }); }
      catch (e) { if (e instanceof ApiError) return { kind: "error", code: e.code }; throw e; }
    }
    const { authKey, wrapKey } = await deriveLoginKeys(password, pre.kdfSalt, pre.kdfParams);
    wrapKey.fill(0);
    try {
      const res = await api.post<AuthResponse | { needsTotpSetup: true; setupToken: string }>("/auth/sso/login", { proof, authKey, ...(code ? { code } : {}) });
      if ("needsTotpSetup" in res) return { kind: "needs_totp_setup", setupToken: res.setupToken };
      await open(res, password);
      return { kind: "ok" };
    } catch (e) {
      if (e instanceof ApiError) {
        const r = (e.body as { retryAfterSeconds?: number } | null)?.retryAfterSeconds;
        return r === undefined ? { kind: "error", code: e.code } : { kind: "error", code: e.code, retryAfterSeconds: r };
      }
      throw e;
    }
  }, [open]);

  const stepUp = useCallback(async (code: string) => {
    await api.post("/auth/totp/step-up", { code });
    setStepUpRequired(false);
    void qc.invalidateQueries();
  }, [qc]);

  const requestStepUp = useCallback(() => setStepUpRequired(true), []);

  const unlock = useCallback(async (password: string) => {
    if (!material) throw new Error("Sign in first");
    const { wrapKey } = await deriveLoginKeys(password, material.kdfSalt, material.kdfParams as KdfParams);
    try { setKeys(await unlockAccount(wrapKey, material)); }
    catch { throw new Error("That master password is not right"); }
    finally { wrapKey.fill(0); }
  }, [material]);

  const beginTwoFactor = useCallback((_setupToken: string, password: string) => { pendingRef.current = password; }, []);
  const completeTwoFactor = useCallback(async (res: AuthResponse) => {
    const pw = pendingRef.current; pendingRef.current = null;
    if (pw === null) throw new Error("Sign in again");
    const authKey = await open(res, pw);
    // Fresh account (or a new authenticator after a reset) without a recovery kit: make one before the vault opens.
    if (!res.user.recoveryKit) { kitProofRef.current = authKey; setKitRequired("signup"); }
  }, [open]);

  const completeRecovery = useCallback((res: AuthResponse, k: UnlockedKeys, authKey: string, opts: { requireKit: boolean }) => {
    install(res, k);
    if (opts.requireKit) { kitProofRef.current = authKey; setKitRequired("recovery"); } else setKitRequired(null);
  }, [install]);

  const proveMaster = useCallback(async (password: string) => {
    if (!material) throw new Error("Sign in first");
    const { wrapKey, authKey } = await deriveLoginKeys(password, material.kdfSalt, material.kdfParams as KdfParams);
    try { const k = await unlockAccount(wrapKey, material); k.privateKey.fill(0); k.userKey.fill(0); }
    catch { throw new Error("That master password is not right"); }
    finally { wrapKey.fill(0); }
    return authKey;
  }, [material]);
  const kitProof = useCallback(() => kitProofRef.current, []);
  const kitCreated = useCallback(() => { kitProofRef.current = null; setKitRequired(null); setUser((u) => (u ? { ...u, recoveryKit: true } : u)); }, []);
  const generation = useCallback(() => genRef.current, []);
  const userId = user?.id ?? null;
  // Lost the active org mid-session (removed, disabled, org deleted): reload the list, which picks another.
  useEffect(() => {
    if (!userId) return;
    let busy = false;
    api.onOrgForbidden(() => {
      if (busy) return;
      busy = true;
      api.get<{ orgs: Org[] }>("/me/orgs").then((r) => installOrgs(userId, r.orgs)).catch(() => undefined).finally(() => { busy = false; });
    });
    return () => api.onOrgForbidden(() => {});
  }, [userId, installOrgs]);
  const switchOrg = useCallback((id: string | null) => { if (userId && (id === null || orgs.some((o) => o.id === id))) activate(userId, id); }, [userId, orgs, activate]);
  /** Installs a fresh org list, keeping the active space (Personal when its org went away). */
  const applyOrgs = useCallback((list: Org[]) => { if (userId) installOrgs(userId, list); }, [userId, installOrgs]);
  const org = orgs.find((o) => o.id === orgId) ?? null;
  const idleLockMinutes = org?.policies?.autoLockMinutes ?? null;
  const viewUser = useMemo<User | null>(() => (user ? { ...user, role: org && org.role !== "member" ? "admin" : "member", orgRole: org?.role ?? null } : null), [user, org]);

  const signOut = useCallback(async () => {
    // Offline the server can't end the session now: remember to, before anything resumes on this device.
    await api.post("/auth/logout").catch((e) => { if (isUnreachable(e)) flag.set(true); });
    clear();
  }, [clear]);

  // Offline: keep trying the server (every 15 s and when the browser says it's back). Same account and key material:
  // carry on online with the keys already unlocked; anything else locks; a refusal signs out (and wipes the copy).
  const materialRef = useRef(material);
  materialRef.current = material;
  useEffect(() => {
    if (!offline || !userId) return;
    let stop = false, busy = false;
    const attempt = () => {
      if (busy) return;
      busy = true;
      api.post<AuthResponse>("/auth/refresh").then((res) => {
        if (stop) return;
        const same = res.user.id === userId && JSON.stringify(res.material) === JSON.stringify(materialRef.current);
        if (!same) lock(); else { genRef.current++; wipeVaultCache(); }
        api.setAccessToken(res.accessToken);
        installOrgs(res.user.id, res.orgs ?? [], res.user.id === userId ? undefined : "remembered");
        setUser(toUser(res.user)); setMaterial(res.material); setOffline(false);
        void saveAccount(res.user, res.material, res.orgs ?? []);
      }).catch((e) => { if (!stop && refused(e)) { clear(); setReason("expired"); } }).finally(() => { busy = false; });
    };
    const t = window.setInterval(attempt, 15_000);
    window.addEventListener("online", attempt);
    return () => { stop = true; window.clearInterval(t); window.removeEventListener("online", attempt); };
  }, [offline, userId, lock, clear, installOrgs, wipeVaultCache]);

  const setOfflineCopy = useCallback((on: boolean) => {
    setOfflineEnabled(on);
    if (!on) { void wipeOffline(); return; }
    if (user && material) void saveAccount(user, material, orgs).then(() => qc.invalidateQueries({ queryKey: ["vault"] }));
  }, [user, material, orgs, qc]);

  useEffect(() => {
    if (!keys) return;
    // The active org's auto-lock policy replaces the default.
    const idle = idleLockMinutes ? idleLockMinutes * 60_000 : IDLE_LOCK_MS;
    let timer = window.setTimeout(lock, idle);
    const reset = () => { window.clearTimeout(timer); timer = window.setTimeout(lock, idle); };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => { window.clearTimeout(timer); events.forEach((e) => window.removeEventListener(e, reset)); };
  }, [keys, lock, idleLockMinutes]);

  const value = useMemo<SessionValue>(() => ({
    state: booting ? "loading" : keys ? "unlocked" : user ? "locked" : "signed_out", reason, user: viewUser, keys, signIn, beginTwoFactor, completeTwoFactor, generation, unlock, lock, signOut,
    kitRequired, completeRecovery, proveMaster, kitProof, kitCreated, org, orgs, switchOrg, applyOrgs, signInWithSso, ssoBlocked, stepUpRequired, stepUp, requestStepUp,
    offline, setOfflineCopy,
  }), [booting, reason, keys, viewUser, signIn, beginTwoFactor, completeTwoFactor, generation, unlock, lock, signOut, kitRequired, completeRecovery, proveMaster, kitProof, kitCreated, org, orgs, switchOrg, applyOrgs, signInWithSso, ssoBlocked, stepUpRequired, stepUp, requestStepUp, offline, setOfflineCopy]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}
