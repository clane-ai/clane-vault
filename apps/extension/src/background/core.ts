import {
  b64url, deriveLoginKeys, encryptNewRecord, encryptRecordBody, totpCode, totpSecondsLeft, unlockAccount,
  type AccountMaterial, type KdfParams, type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
// The web app's sync decryption, reused as is: the same key hierarchy, refusals and per-item failures.
import { decryptSync } from "../../../web/src/features/vault/decrypt";
import type { SyncResponse, VaultFolder, VaultRecord } from "../../../web/src/features/vault/types";
import { matchUrl, normaliseServerUrl, parsePageUrl, parseUrl, siteOf } from "../shared/domain";
import type { FillResult } from "../shared/forms";
import type { Blocked, ContentMessage, FillResponse, ItemView, Org, PopupMessage, PromptView, SignInResult, StateView } from "../shared/messages";
import { ApiError, createClient } from "./client";

export const DEFAULT_AUTOLOCK_MIN = 15;
/** A pending save offer lives this long (one sign-in round trip with a redirect or two). */
const PENDING_TTL_MS = 5 * 60_000;
/** The decrypted vault is re-synced when older than this. */
const STALE_MS = 30_000;
/**
 * Save-offer submissions a page may make: whether one gets an offer says whether a username/password pair is already
 * stored, so a hostile page on the same site must not be able to use it as a fast guessing oracle.
 */
const SUBMIT_WINDOW_MS = 60_000, SUBMITS_PER_TAB = 5, SUBMITS_TOTAL = 20;

export interface KV { get<T>(key: string): Promise<T | undefined>; set(key: string, value: unknown): Promise<void>; remove(key: string): Promise<void> }
/** Browser APIs the core needs, injected so the handlers run in tests without a browser. */
export interface Platform {
  /** chrome.storage.session: memory only, extension pages and the service worker only. Keys live here. */
  session: KV;
  /** chrome.storage.local: settings only, never keys or tokens. */
  local: KV;
  tabUrl(tabId: number): Promise<string | undefined>;
  /** Injects the fill script into the tab's top frame; it re-checks the origin before touching the page. */
  fill(tabId: number, origin: string, username: string | null, password: string | null): Promise<FillResult>;
  /** (Re)arms the idle auto-lock alarm. */
  armAutoLock(minutes: number): void;
  scheduleClipboardClear(): void;
  fetch?: typeof fetch;
  now?: () => number;
}

interface Settings { serverUrl: string | null; autoLockMinutes: number; saveOffers: boolean; neverSites: string[]; lastEmail: string; lastOrg: Record<string, string> }
interface Auth { accessToken: string | null; refreshToken: string | null; user: { id: string; email: string; name: string }; material: AccountMaterial; orgs: Org[]; orgId: string | null }
interface StoredKeys { userKey: string; privateKey: string; publicKey: string }
interface Pending { tabId: number; kind: "save" | "update"; site: string; host: string; origin: string; username: string; password: string; recordId?: string; at: number }
interface Vault { orgId: string | null; folders: VaultFolder[]; records: VaultRecord[]; privateLocked: boolean; at: number }
type AuthResponse = { accessToken: string; refreshToken?: string; user: Auth["user"]; material: AccountMaterial; orgs?: Org[] };

const DEFAULTS: Settings = { serverUrl: null, autoLockMinutes: DEFAULT_AUTOLOCK_MIN, saveOffers: false, neverSites: [], lastEmail: "", lastOrg: {} };
const isLogin = (r: VaultRecord): r is VaultRecord & { body: RecordBody } => !r.deleted && !!r.body && r.body.type === "login";
const canEdit = (r: VaultRecord) => r.permission === "owner" || r.permission === "edit";
const wipeVault = (v: Vault | null) => { v?.records.forEach((r) => r.recordKey?.fill(0)); v?.folders.forEach((f) => f.folderKey?.fill(0)); };
const errorOf = (e: unknown) => (e instanceof ApiError ? e.code : e instanceof Error ? e.message : "error");

export function createCore(p: Platform) {
  const now = p.now ?? Date.now;
  let settings: Settings = { ...DEFAULTS };
  let auth: Auth | null = null;
  let keys: UnlockedKeys | null = null;
  let vault: Vault | null = null;
  let blocked: Blocked = null;
  let gen = 0;
  let hydrated: Promise<void> | null = null;
  let submits: { tabId: number; at: number }[] = [];

  const client = createClient({
    serverUrl: () => settings.serverUrl,
    tokens: () => ({ accessToken: auth?.accessToken ?? null, refreshToken: auth?.refreshToken ?? null }),
    saveTokens: async (t, body) => {
      if (!auth) return;
      auth = { ...auth, ...t, ...(Array.isArray(body.orgs) ? { orgs: body.orgs as Org[] } : {}) };
      if (auth.orgId && !auth.orgs.some((o) => o.id === auth!.orgId)) auth.orgId = pickOrg(auth.orgs, auth.user.id);
      await p.session.set("auth", auth);
    },
    sessionEnded: () => clearSession(),
    ...(p.fetch ? { fetch: p.fetch } : {}),
  });

  /** Loads what the storage holds once per service-worker life (the worker is stopped and restarted often). */
  function hydrate() {
    hydrated ??= (async () => {
      settings = { ...DEFAULTS, ...((await p.local.get<Partial<Settings>>("settings")) ?? {}) };
      auth = (await p.session.get<Auth>("auth")) ?? null;
      const k = await p.session.get<StoredKeys>("keys");
      if (auth && k) {
        keys = { userKey: b64url.decode(k.userKey), privateKey: b64url.decode(k.privateKey), publicKey: b64url.decode(k.publicKey) };
        await checkIdle();
      }
    })();
    return hydrated;
  }
  const saveSettings = async (s: Partial<Settings>) => { settings = { ...settings, ...s }; await p.local.set("settings", settings); };

  /**
   * The space to open (docs/design/2026-10-07-multi-org-design.md §11): the one used last here (an org id, or
   * "-" for Personal), else Personal (null). Personal shows private items; an org only that org's items.
   */
  function pickOrg(orgs: Org[], userId: string): string | null {
    const last = settings.lastOrg[userId];
    return orgs.find((o) => o.id === last)?.id ?? null;
  }

  async function lock() {
    gen++;
    keys?.userKey.fill(0); keys?.privateKey.fill(0);
    keys = null;
    wipeVault(vault); vault = null;
    await p.session.remove("keys");
    await p.session.remove("pending");
  }
  async function clearSession() {
    await lock();
    auth = null; blocked = null;
    await p.session.remove("auth");
  }
  async function installKeys(k: UnlockedKeys) {
    await lock();
    keys = k;
    await p.session.set("keys", { userKey: b64url.encode(k.userKey), privateKey: b64url.encode(k.privateKey), publicKey: b64url.encode(k.publicKey) } satisfies StoredKeys);
    await touch();
  }

  /** The strictest auto-lock any of my orgs sets (the keys open every org's items), or null. */
  const lockPolicy = () => {
    const m = (auth?.orgs ?? []).map((o) => o.policies?.autoLockMinutes).filter((x): x is number => typeof x === "number" && x > 0);
    return m.length ? Math.min(...m) : null;
  };
  const lockMinutes = () => Math.min(settings.autoLockMinutes, lockPolicy() ?? Infinity);

  /** User activity in the popup: pushes the idle auto-lock out. Pages never count as activity. */
  async function touch() {
    await p.session.set("activity", now());
    p.armAutoLock(lockMinutes());
  }
  /** Locks when the idle time has run out (alarm fired, or the worker woke up after a long sleep). */
  async function checkIdle() {
    if (!keys) return;
    const last = (await p.session.get<number>("activity")) ?? 0;
    if (now() - last >= lockMinutes() * 60_000 - 1000) await lock();
  }

  function phase(): StateView["phase"] {
    if (!settings.serverUrl) return "setup";
    if (!auth) return "signed_out";
    return keys ? "unlocked" : "locked";
  }
  const state = (): StateView => ({
    phase: phase(), serverUrl: settings.serverUrl, webVaultUrl: settings.serverUrl ? `${settings.serverUrl}/` : null,
    user: auth?.user ?? null, orgs: auth?.orgs ?? [], orgId: auth?.orgId ?? null,
    autoLockMinutes: lockMinutes(), autoLockPolicy: lockPolicy(), saveOffers: settings.saveOffers, lastEmail: settings.lastEmail, blocked,
  });

  // ---- vault ----

  /** Decrypts a fresh sync for the active org on copies of the keys; a lock mid-way discards the result. */
  async function loadVault(force = false): Promise<Vault> {
    if (!auth || !keys) throw new Error("locked");
    const orgId = auth.orgId;
    // The org turned the browser extension off (docs/policies.md): none of its items here.
    if (auth.orgs.find((o) => o.id === orgId)?.policies?.extensionAllowed === false) { blocked = "extension_disabled"; throw new ApiError(403, "extension_disabled", null); }
    if (!force && vault && vault.orgId === orgId && now() - vault.at < STALE_MS) return vault;
    const g = gen;
    const copy: UnlockedKeys = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
    try {
      // One space: the org's items only (?space=org), or Personal (no X-Org-Id: private items only).
      const sync = await client.get<SyncResponse>(orgId ? "/sync?space=org" : "/sync", orgId);
      blocked = null;
      // The org this client asked for: membership keys and what is sealed to them are bound to it (per-org key pairs).
      const d = await decryptSync(sync, copy, auth.user.id, orgId);
      const next: Vault = { orgId, ...d, privateLocked: !!sync.privateLocked, at: now() };
      if (g !== gen || auth?.orgId !== orgId) { wipeVault(next); throw new Error("locked"); }
      wipeVault(vault);
      vault = next;
      return next;
    } catch (e) {
      if (e instanceof ApiError && (e.code === "sso_required" || e.code === "totp_step_up_required" || e.code === "extension_disabled")) blocked = e.code;
      throw e;
    } finally { copy.userKey.fill(0); copy.privateKey.fill(0); }
  }
  const record = async (id: string) => {
    const r = (await loadVault()).records.find((x) => x.id === id);
    if (!r || !isLogin(r)) throw new Error("not_found");
    return r;
  };

  async function items(pageUrl?: string): Promise<{ items: ItemView[]; privateLocked: boolean }> {
    const v = await loadVault();
    const folderName = new Map(v.folders.map((f) => [f.id, f.name]));
    const rank = { exact: 0, site: 1, none: 2 } as const;
    const list = v.records.filter(isLogin).map((r): ItemView => {
      const b = r.body;
      return {
        id: r.id, title: b.title, username: b.username, url: b.url, host: parseUrl(b.url)?.hostname, folder: r.folderId ? folderName.get(r.folderId) ?? null : null,
        permission: r.permission, hasPassword: !!b.password, hasTotp: !!b.totpSecret, match: matchUrl(b.url, pageUrl),
      };
    });
    list.sort((a, b) => rank[a.match] - rank[b.match] || a.title.localeCompare(b.title));
    return { items: list, privateLocked: v.privateLocked };
  }

  // ---- popup handlers ----

  async function signIn(email: string, password: string, code?: string): Promise<SignInResult> {
    try {
      const pre = await client.post<{ kdfSalt: string; kdfParams: KdfParams }>("/auth/prelogin", { email });
      const { authKey, wrapKey } = await deriveLoginKeys(password, pre.kdfSalt, pre.kdfParams);
      try {
        const res = await client.post<AuthResponse | { needsTotpSetup: true }>("/auth/login", { email, authKey, ...(code ? { code } : {}), client: "extension" });
        if ("needsTotpSetup" in res) return { ok: false, error: "setup_on_web" };
        const k = await unlockAccount(wrapKey, res.material);
        await clearSession();
        const orgs = res.orgs ?? [];
        auth = { accessToken: res.accessToken, refreshToken: res.refreshToken ?? null, user: { id: res.user.id, email: res.user.email, name: res.user.name }, material: res.material, orgs, orgId: pickOrg(orgs, res.user.id) };
        await p.session.set("auth", auth);
        await saveSettings({ lastEmail: email });
        await installKeys(k);
        return { ok: true };
      } finally { wrapKey.fill(0); }
    } catch (e) {
      const r = e instanceof ApiError ? (e.body as { retryAfterSeconds?: number } | null)?.retryAfterSeconds : undefined;
      return r === undefined ? { ok: false, error: errorOf(e) } : { ok: false, error: errorOf(e), retryAfterSeconds: r };
    }
  }

  async function unlock(password: string): Promise<SignInResult> {
    if (!auth) return { ok: false, error: "signed_out" };
    const { wrapKey } = await deriveLoginKeys(password, auth.material.kdfSalt, auth.material.kdfParams);
    try { await installKeys(await unlockAccount(wrapKey, auth.material)); return { ok: true }; }
    catch { return { ok: false, error: "wrong_password" }; }
    finally { wrapKey.fill(0); }
  }

  async function copy(id: string, field: "username" | "password" | "totp"): Promise<{ value: string; secondsLeft?: number } | { error: string }> {
    const r = await record(id);
    if (field === "username") return r.body.username ? { value: r.body.username } : { error: "empty" };
    // "Use only": the password (and its one-time codes) can be filled, never shown or copied.
    if (r.permission === "use") return { error: "use_only" };
    if (field === "password") return r.body.password ? { value: r.body.password } : { error: "empty" };
    if (!r.body.totpSecret) return { error: "empty" };
    return { value: await totpCode(r.body.totpSecret, now()), secondsLeft: totpSecondsLeft(now()) };
  }

  async function fill(id: string, tabId: number, confirm?: string, confirmedOrigin?: string): Promise<FillResponse> {
    const r = await record(id);
    const page = parsePageUrl(await p.tabUrl(tabId));
    if (!page) return { ok: false, error: "unsupported_page" };
    const mismatch = matchUrl(r.body.url, page.href) === "none";
    // "Use only": filling into a site the item isn't for would hand the password to any page the user picks.
    if (mismatch && r.permission === "use") return { ok: false, error: "use_only_mismatch" };
    const insecure = page.protocol === "http:";
    const need = mismatch && insecure ? "both" : mismatch ? "mismatch" : insecure ? "insecure" : null;
    // The confirmation is for the page the user was shown: a tab that navigated since asks again.
    if (need && (confirm !== need || confirmedOrigin !== page.origin))
      return { ok: false, confirm: need, pageHost: page.hostname, pageOrigin: page.origin, itemHost: parseUrl(r.body.url)?.hostname ?? null };
    const res = await p.fill(tabId, page.origin, r.body.username ?? null, r.body.password ?? null);
    return res.ok ? { ok: true } : { ok: false, error: res.reason };
  }

  async function onPopup(m: PopupMessage): Promise<unknown> {
    await hydrate();
    await checkIdle();
    switch (m.type) {
      case "state": if (keys) await touch(); return state();
      case "setServer": {
        const url = normaliseServerUrl(m.url);
        if (!url) return { ok: false, error: "bad_url" };
        if (url !== settings.serverUrl) { await client.logout(); await clearSession(); }
        await saveSettings({ serverUrl: url });
        return { ok: true, serverUrl: url };
      }
      case "signIn": return signIn(m.email.trim().toLowerCase(), m.password, m.code);
      case "unlock": return unlock(m.password);
      case "lock": await lock(); return state();
      case "signOut": await client.logout(); await clearSession(); return state();
      case "settings": {
        const min = m.autoLockMinutes;
        await saveSettings({
          ...(min !== undefined && Number.isInteger(min) && min >= 1 && min <= 480 ? { autoLockMinutes: min } : {}),
          ...(m.saveOffers !== undefined ? { saveOffers: m.saveOffers } : {}),
        });
        if (keys) await touch();
        return state();
      }
      case "copied": p.scheduleClipboardClear(); return { ok: true };
    }
    // Everything below needs a signed-in, unlocked session.
    if (!auth) return { error: "signed_out" };
    if (!keys) return { error: "locked" };
    await touch();
    try {
      switch (m.type) {
        case "switchOrg": {
          // null: the Personal space.
          const to = m.orgId || null;
          if (to !== null && !auth.orgs.some((o) => o.id === to)) return { error: "org_forbidden" };
          auth = { ...auth, orgId: to }; blocked = null;
          wipeVault(vault); vault = null;
          await p.session.set("auth", auth);
          await saveSettings({ lastOrg: { ...settings.lastOrg, [auth.user.id]: to ?? "-" } });
          return state();
        }
        case "stepUp": {
          await client.post("/auth/totp/step-up", { code: m.code });
          blocked = null; wipeVault(vault); vault = null;
          return { ok: true };
        }
        case "items": return await items(m.pageUrl);
        case "copy": return await copy(m.id, m.field);
        case "fill": return await fill(m.id, m.tabId, m.confirm, m.origin);
      }
    } catch (e) {
      return { error: errorOf(e), blocked };
    }
    return { error: "unknown_message" };
  }

  // ---- content-script handlers (save / update offers) ----

  async function pendingFor(tabId: number, pageUrl: string): Promise<Pending | null> {
    const all = (await p.session.get<Record<string, Pending>>("pending")) ?? {};
    const x = all[String(tabId)];
    const page = parsePageUrl(pageUrl);
    if (!x || !page || now() - x.at > PENDING_TTL_MS || siteOf(page.hostname) !== x.site) return null;
    return x;
  }
  async function setPending(tabId: number, x: Pending | null) {
    const all = (await p.session.get<Record<string, Pending>>("pending")) ?? {};
    for (const [k, v] of Object.entries(all)) if (now() - v.at > PENDING_TTL_MS) delete all[k];
    if (x) all[String(tabId)] = x; else delete all[String(tabId)];
    await p.session.set("pending", all);
  }
  const view = (x: Pending): PromptView => ({ kind: x.kind, host: x.host, username: x.username });

  async function submitted(tabId: number, pageUrl: string, username: string, password: string): Promise<PromptView | null> {
    const page = parsePageUrl(pageUrl);
    if (!page || !keys || !auth || !settings.saveOffers || !password || password.length > 1024 || username.length > 512) return null;
    // Never the vault's own pages: that form holds the master password.
    if (settings.serverUrl && page.origin === new URL(settings.serverUrl).origin) return null;
    const site = siteOf(page.hostname);
    if (settings.neverSites.includes(site)) return null;
    const t = now();
    submits = submits.filter((s) => t - s.at < SUBMIT_WINDOW_MS);
    if (submits.length >= SUBMITS_TOTAL || submits.filter((s) => s.tabId === tabId).length >= SUBMITS_PER_TAB) return null;
    submits.push({ tabId, at: t });
    const v = await loadVault().catch(() => null);
    if (!v) return null;
    const same = v.records.filter(isLogin).filter((r) => matchUrl(r.body.url, page.href) !== "none" && (r.body.username ?? "").toLowerCase() === username.toLowerCase());
    if (same.some((r) => r.body.password === password)) { await setPending(tabId, null); return null; }
    const editable = same.find(canEdit);
    if (same.length && !editable) return null; // only someone else's copy: nothing we may change
    const x: Pending = { tabId, kind: editable ? "update" : "save", site, host: page.hostname, origin: page.origin, username, password, ...(editable ? { recordId: editable.id } : {}), at: now() };
    await setPending(tabId, x);
    return view(x);
  }

  async function answer(tabId: number, pageUrl: string, action: "save" | "update" | "never" | "dismiss"): Promise<{ ok: boolean; error?: string }> {
    const x = await pendingFor(tabId, pageUrl);
    if (!x) return { ok: false, error: "nothing_pending" };
    await setPending(tabId, null);
    if (action === "dismiss") return { ok: true };
    if (action === "never") { await saveSettings({ neverSites: [...new Set([...settings.neverSites, x.site])] }); return { ok: true }; }
    if (!keys || !auth) return { ok: false, error: "locked" };
    try {
      if (action === "save" && x.kind === "save") {
        // A new item in my private vault (the Personal space, whatever space the popup shows), encrypted exactly like the
        // web app's "New login" (useVault.createRecord).
        const id = crypto.randomUUID();
        const userKey = keys.userKey.slice();
        try {
          const enc = await encryptNewRecord(id, { type: "login", title: x.host.replace(/^www\./, ""), username: x.username, password: x.password, url: x.origin }, userKey);
          enc.recordKey.fill(0);
          await client.post("/records", { id, folderId: null, type: "login", encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey }, null);
        } finally { userKey.fill(0); }
      } else if (action === "update" && x.kind === "update" && x.recordId) {
        const r = await record(x.recordId);
        if (!canEdit(r) || !r.recordKey) return { ok: false, error: "forbidden" };
        const rk = r.recordKey.slice();
        try {
          const encBody = await encryptRecordBody(r.id, { ...r.body, password: x.password }, rk);
          await client.put(`/records/${r.id}`, { encBody, revision: r.revision, type: "login" }, auth.orgId);
        } finally { rk.fill(0); }
      } else return { ok: false, error: "bad_action" };
      if (vault) vault.at = 0;
      return { ok: true };
    } catch (e) { return { ok: false, error: errorOf(e) }; }
  }

  /** Content scripts speak for a page: only the top frame of a tab, and the page URL comes from the browser, never the message. */
  async function onContent(m: ContentMessage, sender: { tabId: number; frameId: number; url: string }): Promise<unknown> {
    await hydrate();
    await checkIdle();
    if (sender.frameId !== 0) return null;
    switch (m.type) {
      case "login.submitted": return submitted(sender.tabId, sender.url, String(m.username ?? "").trim(), String(m.password ?? ""));
      case "prompt.pending": { const x = await pendingFor(sender.tabId, sender.url); return x && keys ? view(x) : null; }
      case "prompt.answer": return answer(sender.tabId, sender.url, m.action);
    }
    return null;
  }

  return {
    onPopup, onContent, hydrate, lock,
    /** The auto-lock alarm fired. */
    onAlarm: async () => { await hydrate(); await checkIdle(); },
    /** The screen was locked or the machine went idle: lock now. */
    onSystemLocked: async () => { await hydrate(); await lock(); },
    state: () => state(),
  };
}
export type Core = ReturnType<typeof createCore>;
