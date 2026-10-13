import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Check, Copy, ExternalLink, KeyRound, Lock, LogOut, RefreshCw, Search, Settings, ShieldAlert, Timer, User, Wand2 } from "lucide-react";
import { DEFAULT_GENERATOR, generatePassword, type GeneratorOptions } from "@clane-vault/crypto";
import { VaultMark } from "@/components/brand/VaultMark";
import { DEFAULT_SERVER, normaliseServerUrl, originPattern } from "../shared/domain";
import { ext, send } from "../shared/ext";
import type { FillResponse, ItemView, SignInResult, StateView } from "../shared/messages";
import { Button, Field, IconButton, Notice } from "./ui";

const ERRORS: Record<string, string> = {
  invalid_credentials: "Email or master password is not right.",
  totp_required: "Enter the 6-digit code from your authenticator app.",
  totp_invalid: "That authenticator code is not right.",
  wrong_password: "That master password is not right.",
  setup_on_web: "Finish setting up your account in the web vault first, then sign in here.",
  offline: "Can't reach the server. Check the address and your connection.",
  rate_limited: "Too many tries. Wait a minute and try again.",
  session_expired: "Your session ended. Sign in again.",
  use_only: "Use only: you can fill this password, not copy it.",
  use_only_mismatch: "Use only: this login can be filled only on its own site.",
  unsupported_page: "This page can't be filled.",
  no_fields: "No sign-in fields found on this page.",
  navigated: "The page changed before filling. Try again.",
  frame: "Only the main page can be filled.",
  bad_url: "Use an https:// address (http:// only for localhost).",
  permission_denied: "The extension needs access to the server to sign in.",
};
const message = (code: string, retryAfterSeconds?: number) =>
  code === "locked" ? `Too many tries. Try again in ${Math.ceil((retryAfterSeconds ?? 900) / 60)} minutes.` : ERRORS[code] ?? `Something went wrong (${code}).`;
const asPage = new URLSearchParams(location.search).has("tab");

/** The tab the popup acts on: the active tab of the window it was opened from (or ?tab=<id> when opened as a page). */
async function activeTab(): Promise<{ id: number; url?: string } | null> {
  const q = new URLSearchParams(location.search).get("tab");
  const t = q ? await ext.tabs.get(Number(q)).catch(() => null) : (await ext.tabs.query({ active: true, currentWindow: true }))[0];
  return t?.id !== undefined ? { id: t.id, url: t.url } : null;
}

/** Copies, then asks the background to clear the clipboard in 30 s (it outlives the popup). */
async function copyText(text: string) {
  await navigator.clipboard.writeText(text);
  await send({ type: "copied" });
}

export function App() {
  const [st, setSt] = useState<StateView | null>(null);
  const reload = useCallback(() => send<StateView>({ type: "state" }).then(setSt), []);
  useEffect(() => { void reload(); }, [reload]);
  if (!st) return <Shell><div className="flex flex-1 items-center justify-center"><VaultMark size={36} state="working" decorative /></div></Shell>;
  if (st.phase === "setup") return <Setup onDone={reload} />;
  if (st.phase === "signed_out") return <SignIn st={st} onDone={reload} />;
  if (st.phase === "locked") return <Unlock st={st} onDone={reload} />;
  return <Vault st={st} reload={reload} />;
}

function Shell({ children, header }: { children: ReactNode; header?: ReactNode }) {
  return (
    <div className="flex min-h-[480px] flex-col">
      {header ?? <div className="flex items-center gap-2 px-4 pt-4"><VaultMark size={27} wordmark wordmarkUnit={2} textSize={20} /></div>}
      {children}
    </div>
  );
}

function Setup({ onDone }: { onDone: () => void }) {
  const [url, setUrl] = useState(DEFAULT_SERVER);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    const server = normaliseServerUrl(url);
    if (!server) { setError("bad_url"); return; }
    // Asked from the click itself (a user gesture); only this one server, nothing else.
    const granted = await ext.permissions.request({ origins: [originPattern(server)] }).catch(() => false);
    if (!granted) { setError("permission_denied"); return; }
    const r = await send<{ ok: boolean; error?: string }>({ type: "setServer", url: server });
    if (!r.ok) setError(r.error ?? "bad_url"); else onDone();
  }
  return (
    <Shell>
      <form onSubmit={submit} className="flex flex-1 flex-col gap-4 p-4">
        <div>
          <h1 className="text-[18px]">Connect to your vault</h1>
          <p className="mt-1 text-text-secondary">The address of your vault server. Self-hosted? Use your own address.</p>
        </div>
        <Field label="Server address" value={url} onChange={(e) => setUrl(e.target.value)} autoFocus spellCheck={false} inputMode="url" />
        {error && <Notice tone="error">{message(error)}</Notice>}
        <Button type="submit" variant="primary" className="mt-auto">Continue</Button>
      </form>
    </Shell>
  );
}

function ServerLine({ st }: { st: StateView }) {
  async function change() {
    if (!confirm("Change the server? You will be signed out.")) return;
    const url = prompt("Server address", st.serverUrl ?? DEFAULT_SERVER);
    const server = url && normaliseServerUrl(url);
    if (!server) return;
    if (!(await ext.permissions.request({ origins: [originPattern(server)] }).catch(() => false))) return;
    await send({ type: "setServer", url: server });
    location.reload();
  }
  return (
    <div className="flex items-center justify-between gap-2 text-[12px] text-text-tertiary">
      <span className="truncate">{st.serverUrl}</span>
      <button type="button" className="text-blue-500 hover:underline" onClick={() => void change()}>Change</button>
    </div>
  );
}

function SignIn({ st, onDone }: { st: StateView; onDone: () => void }) {
  const [email, setEmail] = useState(st.lastEmail);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; retry?: number } | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    const r = await send<SignInResult>({ type: "signIn", email, password, code: code.replace(/\s/g, "") || undefined });
    setBusy(false);
    if (r.ok) { setPassword(""); onDone(); } else setError({ code: r.error, retry: r.retryAfterSeconds });
  }
  return (
    <Shell>
      <form onSubmit={submit} className="flex flex-1 flex-col gap-3 p-4">
        <h1 className="text-[18px]">Sign in</h1>
        <Field label="Email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus={!st.lastEmail} />
        <Field label="Master password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus={!!st.lastEmail} />
        <Field label="Authenticator code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} />
        {error && <Notice tone="error">{message(error.code, error.retry)}{error.code === "setup_on_web" && <> <WebLink st={st}>Open web vault</WebLink></>}</Notice>}
        <Button type="submit" variant="primary" disabled={busy}>{busy ? <><VaultMark size={18} state="working" decorative /> Signing in…</> : "Sign in"}</Button>
        <p className="text-[12px] text-text-tertiary">Your organisation signs in with single sign-on? Sign in on the <WebLink st={st}>web vault</WebLink> for now.</p>
        <div className="mt-auto"><ServerLine st={st} /></div>
      </form>
    </Shell>
  );
}

function WebLink({ st, children }: { st: StateView; children: ReactNode }) {
  return <a href={st.webVaultUrl ?? "#"} target="_blank" rel="noreferrer" className="text-blue-500 hover:underline">{children}</a>;
}

function Unlock({ st, onDone }: { st: StateView; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    const r = await send<SignInResult>({ type: "unlock", password });
    setBusy(false);
    if (r.ok) { setPassword(""); onDone(); } else setError(r.error);
  }
  return (
    <Shell>
      <form onSubmit={submit} className="flex flex-1 flex-col gap-3 p-4">
        <div>
          <h1 className="text-[18px]">Vault locked</h1>
          <p className="mt-1 text-text-secondary">{st.user?.email}</p>
        </div>
        <Field label="Master password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
        {error && <Notice tone="error">{message(error)}</Notice>}
        <Button type="submit" variant="primary" disabled={busy}>{busy ? <><VaultMark size={18} state="working" decorative /> Unlocking…</> : "Unlock"}</Button>
        <Button variant="ghost" className="mt-auto" onClick={() => void send({ type: "signOut" }).then(onDone)}><LogOut className="size-4" /> Sign out</Button>
      </form>
    </Shell>
  );
}

type View = "items" | "generator" | "settings";

function Vault({ st, reload }: { st: StateView; reload: () => Promise<void> }) {
  const [view, setView] = useState<View>("items");
  const [toast, setToast] = useState<string | null>(null);
  const flash = useCallback((t: string) => { setToast(t); window.setTimeout(() => setToast((x) => (x === t ? null : x)), 2500); }, []);
  const header = (
    <div className="flex items-center gap-1 border-b border-border-default bg-card px-3 py-2">
      <VaultMark size={27} decorative />
      {st.orgs.length > 0 ? (
        <select aria-label="Space" value={st.orgId ?? ""} onChange={(e) => void send({ type: "switchOrg", orgId: e.target.value || null }).then(reload)}
          className="ml-1 h-8 min-w-0 flex-1 truncate rounded-md border border-border-mid bg-card px-2 text-[13px] font-medium text-text-primary">
          <option value="">Personal</option>
          {st.orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
        </select>
      ) : <span className="ml-1 flex-1 truncate font-display text-[14px] font-semibold">Personal</span>}
      <IconButton label="Items" aria-pressed={view === "items"} onClick={() => setView("items")} className={view === "items" ? "bg-well text-text-primary" : ""}><KeyRound className="size-4" /></IconButton>
      <IconButton label="Password generator" aria-pressed={view === "generator"} onClick={() => setView("generator")} className={view === "generator" ? "bg-well text-text-primary" : ""}><Wand2 className="size-4" /></IconButton>
      <IconButton label="Settings" aria-pressed={view === "settings"} onClick={() => setView("settings")} className={view === "settings" ? "bg-well text-text-primary" : ""}><Settings className="size-4" /></IconButton>
      <IconButton label="Lock" onClick={() => void send({ type: "lock" }).then(reload)}><Lock className="size-4" /></IconButton>
    </div>
  );
  return (
    <Shell header={header}>
      {view === "items" && <Items st={st} reload={reload} flash={flash} />}
      {view === "generator" && <Generator flash={flash} />}
      {view === "settings" && <SettingsView st={st} reload={reload} />}
      {toast && <div role="status" className="pointer-events-none fixed inset-x-3 bottom-3 rounded-lg bg-navy-900 px-3 py-2 text-[12px] text-white shadow-lg">{toast}</div>}
    </Shell>
  );
}

function Items({ st, reload, flash }: { st: StateView; reload: () => Promise<void>; flash: (t: string) => void }) {
  const [tab, setTab] = useState<{ id: number; url?: string } | null>(null);
  const [data, setData] = useState<{ items: ItemView[]; privateLocked: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const load = useCallback(async () => {
    const t = await activeTab();
    setTab(t);
    const r = await send<{ items: ItemView[]; privateLocked: boolean } | { error: string }>({ type: "items", pageUrl: t?.url });
    if ("error" in r) { setError(r.error); if (r.error === "session_expired" || r.error === "locked") void reload(); } else { setError(null); setData(r); }
  }, [reload]);
  useEffect(() => { void load(); }, [load, st.orgId]);

  const org = st.orgs.find((o) => o.id === st.orgId);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const all = data?.items ?? [];
    return s ? all.filter((i) => `${i.title} ${i.username ?? ""} ${i.host ?? ""} ${i.folder ?? ""}`.toLowerCase().includes(s)) : all;
  }, [data, q]);
  const here = shown.filter((i) => i.match !== "none");
  const rest = shown.filter((i) => i.match === "none");

  if (error === "sso_required" || st.blocked === "sso_required") return (
    <div className="flex flex-col gap-3 p-4">
      <Notice tone="warn">{org?.name ?? "This organisation"} requires single sign-on. Sign in on the web vault to open its items.</Notice>
      <a className="inline-flex items-center gap-1.5 text-blue-500 hover:underline" href={st.webVaultUrl ?? "#"} target="_blank" rel="noreferrer"><ExternalLink className="size-4" /> Open web vault</a>
    </div>
  );
  if (error === "extension_disabled" || st.blocked === "extension_disabled") return (
    <div className="flex flex-col gap-3 p-4">
      <Notice tone="warn">{org?.name ?? "This organisation"} doesn't allow the browser extension. Use the web vault for its items.</Notice>
      <a className="inline-flex items-center gap-1.5 text-blue-500 hover:underline" href={st.webVaultUrl ?? "#"} target="_blank" rel="noreferrer"><ExternalLink className="size-4" /> Open web vault</a>
    </div>
  );
  if (error === "totp_step_up_required" || st.blocked === "totp_step_up_required") return <StepUp onDone={() => void reload().then(load)} />;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="p-3 pb-2">
        <label className="flex h-9 items-center gap-2 rounded-lg border border-border-mid bg-card px-3 focus-within:border-blue-500">
          <Search className="size-4 text-text-tertiary" />
          <input type="search" aria-label="Search" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} autoFocus className="min-w-0 flex-1 bg-transparent text-[13px] outline-none placeholder:text-text-tertiary" />
        </label>
      </div>
      {error && <div className="px-3"><Notice tone="error">{message(error)} <button type="button" className="text-blue-500 underline" onClick={() => void load()}>Retry</button></Notice></div>}
      {data?.privateLocked && <div className="px-3"><Notice>Private items are hidden until you confirm your authenticator code in the web vault.</Notice></div>}
      <div className="max-h-[440px] flex-1 overflow-y-auto px-2 pb-3">
        {!data && !error && <div className="flex justify-center py-10"><VaultMark size={27} state="working" decorative /></div>}
        {data && shown.length === 0 && <p className="px-2 py-8 text-center text-text-tertiary">{q ? "Nothing matches." : "No logins in this vault yet."}</p>}
        {here.length > 0 && <Section title={tab?.url ? `For ${new URL(tab.url).hostname}` : "This site"}>{here.map((i) => <Row key={i.id} item={i} tab={tab} flash={flash} primary />)}</Section>}
        {rest.length > 0 && <Section title={here.length ? "All items" : "Items"}>{rest.map((i) => <Row key={i.id} item={i} tab={tab} flash={flash} />)}</Section>}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return <section className="mt-1"><h2 className="px-2 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">{title}</h2><ul className="flex flex-col gap-0.5">{children}</ul></section>;
}

function Row({ item, tab, flash, primary }: { item: ItemView; tab: { id: number; url?: string } | null; flash: (t: string) => void; primary?: boolean }) {
  const [ask, setAsk] = useState<Extract<FillResponse, { confirm: string }> | null>(null);
  const [totp, setTotp] = useState<{ value: string; left: number } | null>(null);
  const useOnly = item.permission === "use";

  async function fill(confirm?: { confirm: "mismatch" | "insecure" | "both"; pageOrigin: string }) {
    if (!tab) return;
    const r = await send<FillResponse | { error: string }>({ type: "fill", id: item.id, tabId: tab.id, ...(confirm ? { confirm: confirm.confirm, origin: confirm.pageOrigin } : {}) });
    if ("confirm" in r) { setAsk(r); return; }
    setAsk(null);
    if ("ok" in r && r.ok) { if (!asPage) window.close(); else flash("Filled."); }
    else flash(message("error" in r ? r.error : "error"));
  }
  async function copy(field: "username" | "password" | "totp") {
    const r = await send<{ value: string; secondsLeft?: number } | { error: string }>({ type: "copy", id: item.id, field });
    if ("error" in r) { flash(message(r.error)); return; }
    await copyText(r.value);
    if (field === "totp") setTotp({ value: r.value, left: r.secondsLeft ?? 30 });
    flash(field === "username" ? "Username copied." : `${field === "totp" ? "Code" : "Password"} copied. Clipboard clears in 30 s.`);
  }
  return (
    <li className="group rounded-lg px-2 py-2 hover:bg-card">
      <div className="flex items-center gap-2.5">
        <span aria-hidden="true" className="flex size-8 shrink-0 items-center justify-center rounded-md bg-well font-display text-[13px] font-semibold text-text-secondary">{(item.title[0] ?? "?").toUpperCase()}</span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium">{item.title}</div>
          <div className="truncate text-[12px] text-text-tertiary">{item.username || item.host || "No username"}{useOnly && " · Use only"}</div>
        </div>
        <IconButton label={`Copy username for ${item.title}`} disabled={!item.username} onClick={() => void copy("username")}><User className="size-4" /></IconButton>
        <IconButton label={useOnly ? "Use only: can't copy the password" : `Copy password for ${item.title}`} disabled={!item.hasPassword || useOnly} onClick={() => void copy("password")}><Copy className="size-4" /></IconButton>
        {item.hasTotp && !useOnly && <IconButton label={`Copy one-time code for ${item.title}`} onClick={() => void copy("totp")}><Timer className="size-4" /></IconButton>}
        <Button variant={primary ? "primary" : "secondary"} className="h-8 px-2.5" disabled={!tab || (!item.username && !item.hasPassword)} onClick={() => void fill()}>Fill</Button>
      </div>
      {totp && <TotpLine id={item.id} initial={totp} />}
      {ask && (
        <div className="mt-2 flex flex-col gap-2 rounded-lg border border-border-default bg-orange-tint p-2.5 text-[12px] text-orange-ink" role="alertdialog" aria-label="Confirm fill">
          <div className="flex gap-2"><ShieldAlert className="mt-0.5 size-4 shrink-0" />
            <div>
              {(ask.confirm === "mismatch" || ask.confirm === "both") && <p>This login is for <b>{ask.itemHost ?? "no site"}</b>, but this page is <b>{ask.pageHost}</b>.</p>}
              {(ask.confirm === "insecure" || ask.confirm === "both") && <p>This page is not secure (http). Others on the network could read what you fill in.</p>}
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" className="h-8" onClick={() => setAsk(null)}>Cancel</Button>
            <Button variant="danger" className="h-8" onClick={() => void fill(ask)}>Fill anyway</Button>
          </div>
        </div>
      )}
    </li>
  );
}

/** The current one-time code with its countdown; fetches the next code when the period rolls over. */
function TotpLine({ id, initial }: { id: string; initial: { value: string; left: number } }) {
  const [t, setT] = useState(initial);
  const busy = useRef(false);
  useEffect(() => {
    const iv = window.setInterval(() => {
      setT((x) => ({ ...x, left: x.left - 1 }));
    }, 1000);
    return () => window.clearInterval(iv);
  }, []);
  useEffect(() => {
    if (t.left > 0 || busy.current) return;
    busy.current = true;
    void send<{ value: string; secondsLeft: number } | { error: string }>({ type: "copy", id, field: "totp" })
      .then((r) => { if ("value" in r) setT({ value: r.value, left: r.secondsLeft }); })
      .finally(() => { busy.current = false; });
  }, [t.left, id]);
  return (
    <div className="ml-[42px] mt-1 flex items-center gap-2 font-mono text-[13px]">
      <span data-testid="totp-code">{t.value.slice(0, 3)} {t.value.slice(3)}</span>
      <span className={t.left <= 5 ? "text-red-500" : "text-text-tertiary"}>{Math.max(t.left, 0)} s</span>
    </div>
  );
}

function StepUp({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    const r = await send<{ ok?: boolean; error?: string }>({ type: "stepUp", code: code.replace(/\s/g, "") });
    if (r.ok) onDone(); else setError(r.error ?? "totp_invalid");
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-3 p-4">
      <Notice>Confirm your authenticator code to open this organisation and your private items.</Notice>
      <Field label="Authenticator code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus required />
      {error && <Notice tone="error">{message(error)}</Notice>}
      <Button type="submit" variant="primary">Confirm</Button>
    </form>
  );
}

function Generator({ flash }: { flash: (t: string) => void }) {
  const [opts, setOpts] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [pw, setPw] = useState(() => generatePassword(DEFAULT_GENERATOR));
  const regen = (o: GeneratorOptions) => { setOpts(o); try { setPw(generatePassword(o)); } catch { /* no character set chosen */ } };
  const toggle = (k: "lower" | "upper" | "digits" | "symbols" | "avoidAmbiguous", label: string) => (
    <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={opts[k]} onChange={(e) => regen({ ...opts, [k]: e.target.checked })} className="size-4 accent-[var(--blue-500)]" />{label}</label>
  );
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="break-all rounded-lg border border-border-mid bg-card px-3 py-3 font-mono text-[14px]" data-testid="generated">{pw}</div>
      <div className="flex gap-2">
        <Button variant="primary" className="flex-1" onClick={() => void copyText(pw).then(() => flash("Password copied. Clipboard clears in 30 s."))}><Copy className="size-4" /> Copy</Button>
        <Button onClick={() => regen(opts)}><RefreshCw className="size-4" /> New</Button>
      </div>
      <label className="flex flex-col gap-1.5 text-[12px] font-medium text-text-secondary">
        Length: {opts.length}
        <input type="range" min={8} max={64} value={opts.length} onChange={(e) => regen({ ...opts, length: Number(e.target.value) })} className="accent-[var(--orange-500)]" />
      </label>
      <div className="grid grid-cols-2 gap-2">
        {toggle("lower", "a–z")}{toggle("upper", "A–Z")}{toggle("digits", "0–9")}{toggle("symbols", "!#$%")}{toggle("avoidAmbiguous", "No look-alikes")}
      </div>
    </div>
  );
}

function SettingsView({ st, reload }: { st: StateView; reload: () => Promise<void> }) {
  const [note, setNote] = useState<string | null>(null);
  async function saveOffers(on: boolean) {
    // Save offers need to see sign-in forms on every site: asked only when switched on (off unregisters the script).
    if (on && !(await ext.permissions.request({ origins: ["<all_urls>"] }).catch(() => false))) { setNote("Save offers need access to the sites you sign in to."); return; }
    await send({ type: "settings", saveOffers: on });
    setNote(null);
    await reload();
  }
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="text-text-secondary">Signed in as <span className="font-medium text-text-primary">{st.user?.email}</span></div>
      <label className="flex items-center justify-between gap-3">
        <span>Lock after idle</span>
        <select aria-label="Lock after idle" value={st.autoLockMinutes} onChange={(e) => void send({ type: "settings", autoLockMinutes: Number(e.target.value) }).then(reload)}
          className="h-8 rounded-md border border-border-mid bg-card px-2">
          {[...new Set([1, 5, 15, 30, 60, 240, st.autoLockMinutes])].filter((m) => !st.autoLockPolicy || m <= st.autoLockPolicy).sort((a, b) => a - b)
            .map((m) => <option key={m} value={m}>{m < 60 || m % 60 ? `${m} min` : `${m / 60} h`}</option>)}
        </select>
      </label>
      {st.autoLockPolicy && <p className="-mt-2 text-[12px] text-text-tertiary">Your organisation locks the vault after {st.autoLockPolicy} min at most.</p>}
      <label className="flex items-start justify-between gap-3">
        <span>Offer to save logins<span className="block text-[12px] text-text-tertiary">After you sign in to a site, offer to save or update the password.</span></span>
        <input type="checkbox" checked={st.saveOffers} onChange={(e) => void saveOffers(e.target.checked)} className="mt-1 size-4 accent-[var(--blue-500)]" />
      </label>
      {note && <Notice tone="warn">{note}</Notice>}
      <div className="flex flex-col gap-2 border-t border-border-default pt-4">
        <a href={st.webVaultUrl ?? "#"} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-blue-500 hover:underline"><ExternalLink className="size-4" /> Open web vault</a>
        <ServerLine st={st} />
      </div>
      <Button variant="danger" onClick={() => void send({ type: "signOut" }).then(reload)}><LogOut className="size-4" /> Sign out</Button>
      <p className="text-center text-[11px] text-text-tertiary"><Check className="mr-1 inline size-3" />End-to-end encrypted · v{ext.runtime.getManifest().version}</p>
    </div>
  );
}
