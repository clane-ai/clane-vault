import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, LogIn, Mail, Send } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError, type OrgApi } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import { browser, m365ConnectError } from "./m365Connect";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

export type Provider = "resend" | "smtp" | "m365";
export type Security = "none" | "starttls" | "tls";
export type M365AuthMode = "app" | "delegated";
/** Microsoft 365 delegated sign-in as the API shows it (never the refresh token). */
export interface M365Delegated {
  account: string | null; connectedAt: string | null; connectedBy: { id: string; name: string } | null;
  /** Microsoft refused the saved sign-in: an admin has to sign in again. */
  reconnect: { at: string; reason: string | null } | null;
  /** A shared mailbox is the sender but the sign-in didn't grant Mail.Send.Shared. */
  sharedScopeMissing: boolean;
}
export interface EmailSettingsView {
  scope: "instance" | "org";
  settings: null | {
    provider: Provider; fromName: string | null; fromAddress: string;
    smtp: { host: string; port: number; security: Security; username: string | null } | null;
    m365?: { tenantId: string; clientId: string; authMode?: M365AuthMode; delegated?: M365Delegated | null } | null;
    secret: { set: boolean; last4: string | null };
    updatedAt: string; updatedBy: { id: string; name: string } | null;
  };
  /** What applies while this scope has no settings of its own. */
  fallback: "instance" | "env" | "none";
  env?: { from?: string } | null;
  /** The redirect URI to register in Entra for delegated sign-in (from PUBLIC_URL, base path included). */
  m365RedirectUri?: string;
}

const FALLBACK: Record<EmailSettingsView["fallback"], string> = {
  instance: "Emails use the server's email settings.",
  env: "Emails use the server's RESEND_API_KEY and EMAIL_FROM.",
  none: "Email isn't set up: nobody is emailed, and admins copy invite links by hand.",
};
const DEFAULT_PORT: Record<Security, number> = { none: 25, starttls: 587, tls: 465 };

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/i;
/** smtp.office365.com and friends: Microsoft has retired password sign-in (basic auth) for SMTP there. */
const MS_SMTP = /(^|\.)(office365\.com|outlook\.com)$/i;

const ERRORS: Record<string, string> = {
  secret_required: "Enter the Resend API key.",
  private_host: "That SMTP server is on a private network, which isn't allowed on this server.",
  host_not_found: "That SMTP server name can't be found.",
  invalid_request: "Check the fields: a valid from address, host and port.",
  forbidden: "You can't change these settings.",
  rate_limited: "Too many changes. Wait a minute and try again.",
  insecure_auth: "This server doesn't send an SMTP password without encryption: choose STARTTLS or TLS.",
  port_not_allowed: "Use port 25, 465, 587 or 2525.",
};

function Radio<T extends string>({ name, legend, value, options, onChange }: { name: string; legend: string; value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="pb-1.5 text-[13px] font-medium text-text-primary">{legend}</legend>
      <div className="flex flex-wrap gap-2">
        {options.map(([v, label]) => (
          <label key={v} className={cn("flex cursor-pointer items-center gap-2 rounded-[9px] border px-3 py-1.5 text-[13px]",
            value === v ? "border-blue-500 bg-blue-500/10 text-text-primary" : "border-border-default text-text-secondary hover:border-border-strong")}>
            <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} className="accent-blue-500" />{label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

const TENANT_HELP = "Enter the Directory (tenant) ID: a GUID or a verified domain such as contoso.onmicrosoft.com.";
const CLIENT_HELP = "Enter the Application (client) ID: a GUID.";

/** The Microsoft Entra steps for the Microsoft 365 provider (docs/email.md, "Microsoft 365 (Graph)"). */
function M365Help() {
  return (
    <details className="rounded-[10px] border border-border-default px-3 py-2 text-[13px] leading-relaxed text-text-secondary">
      <summary className="cursor-pointer font-medium text-text-primary">How to set this up in Microsoft Entra</summary>
      <ol className="mt-2 list-decimal space-y-1 pl-5">
        <li>In the Microsoft Entra admin center (entra.microsoft.com), open <b>App registrations</b> → <b>New registration</b>. Name it (e.g. "Clane Vault mail"), single tenant, no redirect URI → <b>Register</b>.</li>
        <li>On its Overview page, copy the <b>Application (client) ID</b> and the <b>Directory (tenant) ID</b> into the fields above.</li>
        <li><b>Certificates &amp; secrets</b> → <b>New client secret</b> → copy its <b>Value</b> (not the Secret ID) into Client secret. Note when it expires.</li>
        <li><b>API permissions</b> → <b>Add a permission</b> → <b>Microsoft Graph</b> → <b>Application permissions</b> → <b>Mail.Send</b> → <b>Add permissions</b>, then <b>Grant admin consent</b>.</li>
        <li>Save here and use <b>Send test email</b>.</li>
      </ol>
      <p className="mt-2">Recommended: Mail.Send lets the app send as any mailbox, so restrict it to the sender. In Exchange Online PowerShell, with a mail-enabled security group that contains only the sender mailbox:</p>
      <pre className="mt-1 whitespace-pre-wrap break-all rounded-[8px] bg-well p-2 font-mono text-[12px] text-text-primary">New-ApplicationAccessPolicy -AppId &lt;clientId&gt; -PolicyScopeGroupId vault-senders@yourdomain.com -AccessRight RestrictAccess -Description "Clane Vault mail"</pre>
      <p className="mt-1">Check it with <code className="rounded bg-well px-1 font-mono text-[12px]">Test-ApplicationAccessPolicy -Identity vault@yourdomain.com -AppId &lt;clientId&gt;</code>; changes can take up to an hour. RBAC for Applications in Exchange Online is Microsoft's newer replacement for Application Access Policies.</p>
    </details>
  );
}

/** The Entra steps for delegated sign-in (docs/email.md, "Microsoft 365 — delegated sign-in"). */
function M365DelegatedHelp({ redirectUri }: { redirectUri?: string }) {
  return (
    <details className="rounded-[10px] border border-border-default px-3 py-2 text-[13px] leading-relaxed text-text-secondary">
      <summary className="cursor-pointer font-medium text-text-primary">How to set up delegated sign-in in Microsoft Entra</summary>
      <ol className="mt-2 list-decimal space-y-1 pl-5">
        <li>In the Microsoft Entra admin center (entra.microsoft.com), open <b>App registrations</b> → <b>New registration</b>. Name it (e.g. "Clane Vault mail"), single tenant → <b>Register</b>.</li>
        <li><b>Authentication</b> → <b>Add a platform</b> → <b>Web</b> (not single-page application) → Redirect URI: <code className="break-all rounded bg-well px-1 font-mono text-[12px]">{redirectUri ?? "the Redirect URI above"}</code> → <b>Configure</b>.</li>
        <li><b>API permissions</b> → <b>Add a permission</b> → <b>Microsoft Graph</b> → <b>Delegated permissions</b>: <b>Mail.Send</b>, <b>offline_access</b>, <b>User.Read</b>, <b>openid</b>, <b>email</b>, <b>profile</b>; for a shared mailbox also <b>Mail.Send.Shared</b>.</li>
        <li>Optional: <b>Grant admin consent</b> (needed when your tenant doesn't let users consent to apps).</li>
        <li><b>Certificates &amp; secrets</b> → <b>New client secret</b> → copy its <b>Value</b> into Client secret. Copy the <b>Application (client) ID</b> and <b>Directory (tenant) ID</b> from Overview.</li>
        <li>Save here, then <b>Sign in with Microsoft</b> with the mailbox's account (or an account with Send As on the shared mailbox), then <b>Send test email</b>.</li>
      </ol>
      <p className="mt-2">No application permission and no tenant-wide access: the server only ever sends as the account that signed in (or the shared mailbox it may send as). To revoke, use Disconnect here and remove the app in My Apps (myapps.microsoft.com) or Entra.</p>
    </details>
  );
}

/** Delegated sign-in status and actions: Sign in with Microsoft, or Connected as … · Reconnect · Disconnect. */
function M365Connection({ d, busy, onSignIn, onDisconnect }: { d: M365Delegated; busy: boolean; onSignIn: () => void; onDisconnect: () => void }) {
  if (d.reconnect) return (
    <div role="alert" className="flex flex-col gap-2 rounded-[10px] bg-red-tint px-3 py-2 text-[13px] text-text-primary">
      <p><b>Microsoft 365 sign-in needs reconnecting.</b> {d.account ? `Email can't be sent as ${d.account}: ` : ""}{d.reconnect.reason ?? "Microsoft refused the saved sign-in."} Until you reconnect, emails use the next settings available, if any.</p>
      <div><Button type="button" size="sm" onClick={onSignIn} disabled={busy}><LogIn className="size-3.5" />Reconnect</Button></div>
    </div>
  );
  if (!d.account) return (
    <div className="flex flex-wrap items-center gap-2 rounded-[10px] bg-amber-500/10 px-3 py-2 text-[13px] text-text-primary">
      <span>Not connected yet: sign in with the Microsoft account emails are sent from.</span>
      <Button type="button" size="sm" onClick={onSignIn} disabled={busy}><LogIn className="size-3.5" />Sign in with Microsoft</Button>
    </div>
  );
  return (
    <div className="flex flex-col gap-1.5">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-text-primary">
        <span>Connected as <b>{d.account}</b></span>
        {d.connectedAt && <span className="text-text-tertiary">· {relativeTime(d.connectedAt) || new Date(d.connectedAt).toLocaleString()}{d.connectedBy ? ` by ${d.connectedBy.name}` : ""}</span>}
        <span aria-hidden>·</span>
        <button type="button" className="text-blue-500 hover:underline disabled:opacity-50" onClick={onSignIn} disabled={busy}>Reconnect</button>
        <span aria-hidden>·</span>
        <button type="button" className="text-red-500 hover:underline disabled:opacity-50" onClick={onDisconnect} disabled={busy}>Disconnect</button>
      </p>
      {d.sharedScopeMissing && <p role="note" className="rounded-[10px] bg-amber-500/10 px-3 py-2 text-[13px] text-text-primary">The sender is a shared mailbox: reconnect to grant Mail.Send.Shared (add it to the app's API permissions first).</p>}
    </div>
  );
}

/**
 * Email settings for one scope: the server's (instance admins: Settings → Email) or the active organisation's override
 * (its owners and admins). Secrets are write-only: the form shows whether one is set and replaces it only when typed.
 */
export function EmailSettingsSection({ scope }: { scope: "instance" | "org" }) {
  const { user } = useSession();
  const oapi = useOrgApi();
  const orgScope = useScope();
  const qc = useQueryClient();
  const client: OrgApi | typeof api = scope === "org" ? oapi : api;
  const path = scope === "org" ? "/admin/settings/email" : "/admin/instance/email";
  const KEY = scope === "org" ? ["email-settings", orgScope] : ["instance-email-settings", user?.id ?? ""];
  const q = useQuery({ queryKey: KEY, queryFn: () => client.get<EmailSettingsView>(path) });
  const s = q.data?.settings ?? null;

  const [editing, setEditing] = useState(false);
  const [provider, setProvider] = useState<Provider>("resend");
  const [fromName, setFromName] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("587");
  const [security, setSecurity] = useState<Security>("starttls");
  const [username, setUsername] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [authMode, setAuthMode] = useState<M365AuthMode>("app");
  /** The result of a Microsoft sign-in, from the callback's redirect (?m365=connected or ?m365_error=…). */
  const [connectMsg, setConnectMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: true; to: string } | { ok: false; detail: string } | null>(null);

  // The form starts from the saved settings each time it opens.
  function startEdit() {
    setEditing(true);
    setProvider(s?.provider ?? "resend"); setFromName(s?.fromName ?? ""); setFromAddress(s?.fromAddress ?? "");
    setHost(s?.smtp?.host ?? ""); setPort(String(s?.smtp?.port ?? 587)); setSecurity(s?.smtp?.security ?? "starttls"); setUsername(s?.smtp?.username ?? "");
    setTenantId(s?.m365?.tenantId ?? ""); setClientId(s?.m365?.clientId ?? ""); setAuthMode(s?.m365?.authMode ?? "app");
    setSecret(""); setError(null);
  }

  const save = useMutation({
    mutationFn: () => client.put<EmailSettingsView>(path, {
      provider, fromName: fromName.trim() || null, fromAddress: fromAddress.trim(),
      ...(provider === "smtp" ? { smtp: { host: host.trim(), port: Number(port), security, username: username.trim() || null } } : {}),
      ...(provider === "m365" ? { m365: { tenantId: tenantId.trim(), clientId: clientId.trim(), authMode } } : {}),
      ...(secret ? { secret } : {}),
    }),
    onSuccess: (d) => { qc.setQueryData(KEY, d); setEditing(false); setSecret(""); setTest(null); toast.success("Email settings saved"); },
    onError: (e) => setError(e instanceof ApiError ? saveError(e) : "Couldn't save. Try again."),
  });
  const remove = useMutation({
    mutationFn: () => client.del(path),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: KEY }); setTest(null); toast.success(scope === "org" ? "This organisation uses the server's email settings again" : "Email settings removed"); },
  });
  const sendTest = useMutation({
    mutationFn: () => client.post<{ ok: true; to: string }>(`${path}/test`),
    onSuccess: (r) => setTest({ ok: true, to: r.to }),
    onError: (e) => setTest({ ok: false, detail: e instanceof ApiError
      ? ((e.body as { detail?: string } | null)?.detail ?? (e.code === "rate_limited" ? "Too many test emails. Wait a minute." : e.code === "m365_not_connected" ? "Sign in with Microsoft first." : e.code === "m365_reconnect" ? "The Microsoft 365 sign-in needs reconnecting." : e.code === "secret_missing" ? "The stored secret can't be read any more (the server secret changed). Enter it again." : "Couldn't send the test email."))
      : "Couldn't reach the server." }),
  });

  // Back from Microsoft: show the outcome once and take the flag out of the URL.
  const redirectUri = q.data?.m365RedirectUri;
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const ok = p.get("m365"), err = p.get("m365_error");
    if (!ok && !err) return;
    if (ok === "connected") { setConnectMsg({ ok: true, text: "Signed in with Microsoft. Send a test email to check." }); void qc.invalidateQueries({ queryKey: KEY }); }
    else if (err) setConnectMsg({ ok: false, text: m365ConnectError(err, p.get("aadsts"), redirectUri) });
    if (!redirectUri && err === "redirect_uri_mismatch") return; // wait for the URI to name it
    for (const k of ["m365", "m365_error", "aadsts"]) p.delete(k);
    const rest = p.toString();
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${rest ? `?${rest}` : ""}${window.location.hash}`);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [redirectUri]);

  const connect = useMutation({
    mutationFn: () => client.post<{ url: string }>(`${path}/m365/connect`),
    onSuccess: (r) => browser.go(r.url),
    onError: (e) => setConnectMsg({ ok: false, text: e instanceof ApiError && e.code === "secret_missing" ? "The stored client secret can't be read any more. Edit, enter it again and save."
      : e instanceof ApiError && e.code === "rate_limited" ? "Too many sign-in attempts. Wait a minute." : "Couldn't start the Microsoft sign-in. Try again." }),
  });
  const disconnect = useMutation({
    mutationFn: () => client.del(`${path}/m365/connection`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: KEY }); setConnectMsg(null); setTest(null); toast.success("Disconnected from Microsoft 365"); },
  });

  function saveError(e: ApiError): string {
    if (e.code === "secret_required" && provider === "m365") return "Enter the client secret (a new one is needed when the tenant or client ID changes).";
    const issues = (e.body as { issues?: string[] } | null)?.issues ?? [];
    if (e.code === "invalid_request" && issues.includes("m365.tenantId")) return TENANT_HELP;
    if (e.code === "invalid_request" && issues.includes("m365.clientId")) return CLIENT_HELP;
    return ERRORS[e.code] ?? "Couldn't save. Try again.";
  }

  function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    const senderOptional = provider === "m365" && authMode === "delegated";
    if (!(senderOptional && !fromAddress.trim()) && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fromAddress.trim())) return setError(provider === "m365" ? "Enter the sender mailbox." : "Enter the from address.");
    if (provider === "resend" && !secret && !(s?.provider === "resend" && s.secret.set)) return setError("Enter the Resend API key.");
    if (provider === "smtp" && (!host.trim() || !(Number(port) >= 1 && Number(port) <= 65535))) return setError("Enter the SMTP host and port.");
    if (provider === "m365") {
      if (!GUID.test(tenantId.trim()) && !DOMAIN.test(tenantId.trim())) return setError(TENANT_HELP);
      if (!GUID.test(clientId.trim())) return setError(CLIENT_HELP);
      if (!secret && !m365SecretKept) return setError("Enter the client secret.");
    }
    save.mutate();
  }

  const title = scope === "org" ? "Email for this organisation" : "Email";
  // A stored Microsoft 365 secret stays only with the same tenant and app (the server drops it otherwise).
  const m365SecretKept = !!s && s.provider === "m365" && s.secret.set && s.m365?.tenantId === tenantId.trim().toLowerCase() && s.m365?.clientId === clientId.trim().toLowerCase();
  const secretSet = !!s && s.provider === provider && s.secret.set && (provider === "resend" || (provider === "m365" ? m365SecretKept : (s.smtp?.username ?? "") === username.trim()));
  const secretHint = secretSet ? `Set${s?.secret.last4 ? ` (ends in ${s.secret.last4})` : ""}. Leave empty to keep it.` : undefined;
  const id = (x: string) => `${scope}-email-${x}`;
  const delegatedView = s?.provider === "m365" && s.m365?.authMode === "delegated" ? s.m365.delegated ?? null : null;
  const sender = s ? s.fromAddress || delegatedView?.account || "" : "";
  const delegatedForm = provider === "m365" && authMode === "delegated";

  return (
    <section className="flex flex-col gap-3" aria-label={title}>
      <h2 className={h2}>{title}</h2>
      <div className={cn(card, "flex flex-col gap-3")}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Mail className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-text-primary">
              {s ? (s.provider === "smtp" ? `SMTP · ${s.smtp?.host}:${s.smtp?.port}` : s.provider === "m365" ? `Microsoft 365 · ${sender || "not connected"}` : "Resend") : scope === "org" ? "No override" : "Not set in the app"}
              {s && (delegatedView?.reconnect ? <Chip tone="red">Reconnect</Chip> : delegatedView && !delegatedView.account ? <Chip tone="orange">Not connected</Chip> : <Chip tone="green">On</Chip>)}
            </p>
            <p className="text-[13px] leading-relaxed text-text-secondary">
              {scope === "org" ? "Invites and notices about this organisation go out with these settings instead of the server's. " : "Sign-up codes, security notices and invites (unless an organisation has its own settings). "}
              {s ? (sender ? `From ${s.fromName ? `${s.fromName} <${sender}>` : sender}.` : "Sends as the Microsoft account that signs in.") : q.data ? FALLBACK[q.data.fallback] : ""}
            </p>
            {s && <p className="mt-1 font-mono text-[11.5px] text-text-tertiary">Changed {relativeTime(s.updatedAt) || new Date(s.updatedAt).toLocaleString()}{s.updatedBy ? ` by ${s.updatedBy.name}` : ""}</p>}
          </div>
          {!editing && <Button type="button" variant="outline" size="sm" onClick={startEdit} disabled={!q.data}>{s ? "Edit" : "Set up"}</Button>}
        </div>

        {editing && (
          <form onSubmit={submit} className="flex flex-col gap-3 border-t border-border-default pt-3" noValidate aria-label={`${title} settings`}>
            <Radio name={id("provider")} legend="Provider" value={provider} onChange={setProvider} options={[["resend", "Resend"], ["smtp", "SMTP server"], ["m365", "Microsoft 365 (recommended for Office 365)"]]} />
            {provider === "m365" && (
              <Radio name={id("m365-mode")} legend="Connection" value={authMode} onChange={setAuthMode}
                options={[["delegated", "Sign in with Microsoft (delegated)"], ["app", "App-only (client credentials)"]]} />
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5"><Label htmlFor={id("from-name")}>From name</Label>
                <Input id={id("from-name")} maxLength={80} placeholder="Clane Vault" value={fromName} onChange={(e) => setFromName(e.target.value)} /></div>
              <div className="flex flex-col gap-1.5"><Label htmlFor={id("from-address")}>{provider === "m365" ? (delegatedForm ? "Sender mailbox (optional)" : "Sender mailbox") : "From address"}</Label>
                <Input id={id("from-address")} type="email" placeholder={delegatedForm ? "The signed-in account" : "vault@yourdomain.com"} value={fromAddress} onChange={(e) => setFromAddress(e.target.value)}
                  aria-describedby={provider === "m365" ? id("sender-hint") : undefined} />
                {provider === "m365" && <p id={id("sender-hint")} className="text-[12px] text-text-tertiary">{delegatedForm
                  ? "Empty: send as the account that signs in. A shared mailbox here needs Send As (or Send on behalf) for that account, and Mail.Send.Shared."
                  : "The mailbox emails are sent as (a user or shared mailbox in Exchange Online); also the From address."}</p>}</div>
            </div>
            {provider === "m365" ? (<>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("tenant")}>Directory (tenant) ID</Label>
                  <Input id={id("tenant")} autoComplete="off" spellCheck={false} placeholder="GUID or contoso.onmicrosoft.com" value={tenantId} onChange={(e) => setTenantId(e.target.value)} /></div>
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("client")}>Application (client) ID</Label>
                  <Input id={id("client")} autoComplete="off" spellCheck={false} placeholder="00000000-0000-0000-0000-000000000000" value={clientId} onChange={(e) => setClientId(e.target.value)} /></div>
              </div>
              <div className="flex flex-col gap-1.5"><Label htmlFor={id("client-secret")}>Client secret</Label>
                <Input id={id("client-secret")} type="password" autoComplete="off" placeholder={secretSet ? "••••••••" : "The secret's Value"} value={secret} onChange={(e) => setSecret(e.target.value)} aria-describedby={secretHint ? id("secret-hint") : undefined} />
                {secretHint && <p id={id("secret-hint")} className="text-[12px] text-text-tertiary">{secretHint}</p>}</div>
              {delegatedForm ? (<>
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("redirect-uri")}>Redirect URI (register it in Entra as a Web platform)</Label>
                  <div className="flex gap-2">
                    <Input id={id("redirect-uri")} readOnly value={redirectUri ?? ""} className="font-mono text-[12px]" onFocus={(e) => e.currentTarget.select()} />
                    <Button type="button" variant="outline" size="sm" aria-label="Copy redirect URI" disabled={!redirectUri}
                      onClick={() => { void navigator.clipboard?.writeText(redirectUri ?? "").then(() => toast.success("Redirect URI copied"), () => undefined); }}><Copy className="size-3.5" /></Button>
                  </div>
                  <p className="text-[12px] text-text-tertiary">Save, then use <b>Sign in with Microsoft</b>. Changing the tenant or client ID needs signing in again.</p></div>
                <M365DelegatedHelp redirectUri={redirectUri} />
              </>) : <M365Help />}
            </>) : provider === "resend" ? (
              <div className="flex flex-col gap-1.5"><Label htmlFor={id("api-key")}>Resend API key</Label>
                <Input id={id("api-key")} type="password" autoComplete="off" placeholder={secretSet ? "••••••••" : "re_…"} value={secret} onChange={(e) => setSecret(e.target.value)} aria-describedby={secretHint ? id("secret-hint") : undefined} />
                {secretHint && <p id={id("secret-hint")} className="text-[12px] text-text-tertiary">{secretHint}</p>}</div>
            ) : (<>
              <div className="grid gap-3 sm:grid-cols-[1fr_120px]">
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("host")}>SMTP host</Label>
                  <Input id={id("host")} placeholder="smtp.yourdomain.com" value={host} onChange={(e) => setHost(e.target.value)} aria-describedby={MS_SMTP.test(host.trim()) ? id("ms-smtp") : undefined} /></div>
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("port")}>Port</Label>
                  <Input id={id("port")} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, "").slice(0, 5))} /></div>
              </div>
              {MS_SMTP.test(host.trim()) && (
                <div id={id("ms-smtp")} role="note" className="flex flex-wrap items-center gap-2 rounded-[10px] bg-amber-500/10 px-3 py-2 text-[13px] text-text-primary">
                  <span>Microsoft has retired password sign-in for SMTP — use Microsoft 365 instead.</span>
                  <Button type="button" variant="outline" size="sm" onClick={() => { setProvider("m365"); setSecret(""); }}>Switch to Microsoft 365</Button>
                </div>
              )}
              <Radio name={id("security")} legend="Security" value={security} onChange={(v) => { if (Number(port) === DEFAULT_PORT[security]) setPort(String(DEFAULT_PORT[v])); setSecurity(v); }}
                options={[["starttls", "STARTTLS"], ["tls", "TLS"], ["none", "None"]]} />
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("username")}>Username</Label>
                  <Input id={id("username")} autoComplete="off" placeholder="Optional" value={username} onChange={(e) => setUsername(e.target.value)} /></div>
                <div className="flex flex-col gap-1.5"><Label htmlFor={id("password")}>Password</Label>
                  <Input id={id("password")} type="password" autoComplete="off" disabled={!username.trim()} placeholder={secretSet ? "••••••••" : ""} value={secret} onChange={(e) => setSecret(e.target.value)} aria-describedby={secretHint ? id("secret-hint") : undefined} />
                  {secretHint && <p id={id("secret-hint")} className="text-[12px] text-text-tertiary">{secretHint}</p>}</div>
              </div>
            </>)}
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
              <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button>
            </div>
          </form>
        )}

        {s && !editing && delegatedView && (
          <div className="border-t border-border-default pt-3">
            <M365Connection d={delegatedView} busy={connect.isPending || disconnect.isPending} onSignIn={() => { setConnectMsg(null); connect.mutate(); }} onDisconnect={() => disconnect.mutate()} />
          </div>
        )}
        {connectMsg && (connectMsg.ok
          ? <p role="status" className="rounded-[10px] bg-green-tint px-3 py-2 text-[13px] text-text-primary">{connectMsg.text}</p>
          : <p role="alert" className="rounded-[10px] bg-red-tint px-3 py-2 text-[13px] text-red-500">Microsoft sign-in failed: {connectMsg.text}</p>)}

        {s && !editing && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border-default pt-3">
            <Button type="button" variant="outline" size="sm" onClick={() => { setTest(null); sendTest.mutate(); }} disabled={sendTest.isPending}><Send className="size-3.5" />{sendTest.isPending ? "Sending…" : "Send test email"}</Button>
            <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {scope === "org" ? "Use the server's settings" : "Remove"}</Button>
          </div>
        )}
        {test && (test.ok
          ? <p role="status" className="rounded-[10px] bg-green-tint px-3 py-2 text-[13px] text-text-primary">Test email sent to {test.to}. Check that inbox (and spam).</p>
          : <p role="alert" className="rounded-[10px] bg-red-tint px-3 py-2 text-[13px] text-red-500">Test email failed: {test.detail}</p>)}
      </div>
    </section>
  );
}
