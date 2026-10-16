import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Copy, Globe, KeyRound, Plus, Trash2, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { DomainJoinSection } from "./DomainJoinSection";
import { PlanGate } from "@/features/admin/PlanLock";
import { Chip } from "@/features/vault/people";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

export interface SsoDomainView { domain: string; verified: boolean; verifiedAt: string | null; txtRecord: { name: string; value: string } }
export interface SsoSettingsView {
  config: null | { issuer: string; clientId: string; clientSecret: { set: boolean; last4: string | null }; requireSso: boolean; trustIdpMfa: boolean; autoJoin: boolean; updatedAt: string; updatedBy: { id: string; name: string } | null };
  domains: SsoDomainView[];
  redirectUri: string; orgSlug: string; scopes: string; linkedAccounts: number;
}
interface TestResult { ok: boolean; checks: { name: string; ok: boolean; detail: string }[] }

const ERRORS: Record<string, string> = {
  secret_required: "Enter the client secret.",
  issuer_insecure: "The issuer URL must start with https://.",
  issuer_invalid: "Enter the issuer URL (for example https://login.microsoftonline.com/<tenant-id>/v2.0).",
  private_host: "That issuer is on a private network, which isn't allowed on this server.",
  domain_not_verified: "Verify a domain first: \"Require SSO\" and automatic joining only apply to verified domains.",
  invalid_domain: "Enter a domain such as company.com.",
  domain_limit: "An organisation can have up to 20 domains.",
  invalid_request: "Check the fields.",
  owner_only: "Only the organisation's owner can set up single sign-on, change the identity provider, \"Require SSO\" or trusting the provider's MFA.",
  public_domain: "Public email providers (Gmail, Outlook…) can't be SSO domains.",
  domain_taken: "Another organisation on this server has already verified this domain.",
  owner_only_last_domain: "Only the organisation's owner can remove the last verified domain while \"Require SSO\" or email domain auto-join is on: removing it switches them off.",
};
const errorText = (e: unknown) => (e instanceof ApiError ? (e.body as { detail?: string } | null)?.detail ?? ERRORS[e.code] ?? "Couldn't save. Try again." : "Couldn't reach the server.");
const CHECK_LABEL: Record<string, string> = { discovery: "Discovery", metadata: "Provider settings", client: "Client ID and secret" };

function Copyable({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="text-[12px] text-text-tertiary">{label}</span>
      <div className="flex min-w-0 items-center gap-2 rounded-[9px] border border-border-default bg-well px-2.5 py-1.5">
        <code className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-text-primary" title={value}>{value}</code>
        <button type="button" aria-label={`Copy ${label}`} className="text-text-tertiary hover:text-text-primary" onClick={() => { void navigator.clipboard?.writeText(value).then(() => toast.success("Copied"), () => undefined); }}><Copy className="size-3.5" /></button>
      </div>
    </div>
  );
}

/** Organisation settings → Single sign-on (the active organisation's owners and admins). */
export function SsoSettingsSection() {
  return <PlanGate feature="sso"><SsoSettingsForm /></PlanGate>;
}

function SsoSettingsForm() {
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const KEY = ["sso-settings", useScope()];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<SsoSettingsView>("/admin/settings/sso") });
  const d = q.data;
  const c = d?.config ?? null;
  const anyVerified = !!d?.domains.some((x) => x.verified);
  const isOwner = useSession().org?.role === "owner";

  const [editing, setEditing] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [requireSso, setRequireSso] = useState(false);
  const [trustIdpMfa, setTrustIdpMfa] = useState(false);
  const [autoJoin, setAutoJoin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState("");
  const [domainMsg, setDomainMsg] = useState<{ domain: string; ok: boolean; text: string } | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);

  function startEdit() {
    setEditing(true);
    setIssuer(c?.issuer ?? ""); setClientId(c?.clientId ?? ""); setSecret(""); setError(null);
    setRequireSso(!!c?.requireSso); setTrustIdpMfa(!!c?.trustIdpMfa); setAutoJoin(!!c?.autoJoin);
  }

  const apply = (v: SsoSettingsView) => qc.setQueryData(KEY, v);
  const save = useMutation({
    mutationFn: (b: object) => oapi.put<SsoSettingsView>("/admin/settings/sso", b),
    onSuccess: (v) => { apply(v); setEditing(false); setSecret(""); toast.success("Single sign-on saved"); },
    onError: (e) => setError(errorText(e)),
  });
  /** Options switch straight away when SSO is already set up. */
  const toggle = useMutation({
    mutationFn: (patch: Partial<Pick<NonNullable<SsoSettingsView["config"]>, "requireSso" | "trustIdpMfa" | "autoJoin">>) =>
      oapi.put<SsoSettingsView>("/admin/settings/sso", { issuer: c!.issuer, clientId: c!.clientId, requireSso: c!.requireSso, trustIdpMfa: c!.trustIdpMfa, autoJoin: c!.autoJoin, ...patch }),
    onSuccess: apply, onError: (e) => toast.error(errorText(e)),
  });
  const remove = useMutation({ mutationFn: () => oapi.del("/admin/settings/sso"), onSuccess: () => { void qc.invalidateQueries({ queryKey: KEY }); setTest(null); toast.success("Single sign-on removed"); } });
  const runTest = useMutation({
    mutationFn: (b: object) => oapi.post<TestResult>("/admin/settings/sso/test", b),
    onSuccess: setTest, onError: (e) => setTest({ ok: false, checks: [{ name: e instanceof ApiError && e.code === "secret_required" ? "client" : "discovery", ok: false,
      detail: e instanceof ApiError && e.code === "secret_required" ? "Enter the client secret to test another issuer or client ID." : errorText(e) }] }),
  });
  const addDomain = useMutation({
    mutationFn: (domain: string) => oapi.post<SsoSettingsView>("/admin/settings/sso/domains", { domain }),
    onSuccess: (v) => { apply(v); setNewDomain(""); }, onError: (e) => setDomainMsg({ domain: "", ok: false, text: errorText(e) }),
  });
  const verify = useMutation({
    mutationFn: (domain: string) => oapi.post<SsoSettingsView>(`/admin/settings/sso/domains/${encodeURIComponent(domain)}/verify`),
    onSuccess: (v, domain) => { apply(v); setDomainMsg({ domain, ok: true, text: `${domain} is verified.` }); },
    onError: (e, domain) => setDomainMsg({ domain, ok: false, text: errorText(e) }),
  });
  const dropDomain = useMutation({ mutationFn: (domain: string) => oapi.del(`/admin/settings/sso/domains/${encodeURIComponent(domain)}`), onSuccess: () => void qc.invalidateQueries({ queryKey: KEY }),
    onError: (e, domain) => setDomainMsg({ domain, ok: false, text: errorText(e) }) });

  function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    if (!issuer.trim() || !clientId.trim()) return setError("Enter the issuer URL and the client ID.");
    if (!secret && !c?.clientSecret.set) return setError("Enter the client secret.");
    save.mutate({ issuer: issuer.trim(), clientId: clientId.trim(), ...(secret ? { clientSecret: secret } : {}), requireSso, trustIdpMfa, autoJoin });
  }

  const option = (id: "requireSso" | "trustIdpMfa" | "autoJoin", label: string, text: string, needsVerified: boolean) => {
    const value = editing ? { requireSso, trustIdpMfa, autoJoin }[id] : !!c?.[id];
    const set = editing ? { requireSso: setRequireSso, trustIdpMfa: setTrustIdpMfa, autoJoin: setAutoJoin }[id] : (v: boolean) => toggle.mutate({ [id]: v });
    const ownerOnly = id !== "autoJoin" && !isOwner;
    const disabled = (!editing && (!c || toggle.isPending)) || (needsVerified && !anyVerified && !value) || ownerOnly;
    return (
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <label htmlFor={`sso-${id}`} className="text-[13.5px] font-medium text-text-primary">{label}</label>
          <p className="text-[12.5px] leading-relaxed text-text-secondary">{text}</p>
        </div>
        <Switch id={`sso-${id}`} checked={value} disabled={disabled} onCheckedChange={set} aria-label={label} />
      </div>
    );
  };

  return (<>
    <section className="flex flex-col gap-3" aria-label="Single sign-on">
      <h2 className={h2}>Single sign-on</h2>
      <div className={cn(card, "flex flex-col gap-4")}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><KeyRound className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-text-primary">
              OpenID Connect {c ? <Chip tone="green">On</Chip> : <Chip>Off</Chip>}{c?.requireSso && <Chip tone="blue">Required</Chip>}
            </p>
            <p className="text-[13px] leading-relaxed text-text-secondary">
              People sign in with your identity provider (Microsoft Entra ID, Google Workspace, Okta…) and then unlock with their master password: the provider never sees vault keys.
            </p>
            {c && <p className="mt-1 truncate font-mono text-[11.5px] text-text-tertiary" title={c.issuer}>{c.issuer} · client {c.clientId} · secret {c.clientSecret.set ? `set${c.clientSecret.last4 ? ` (…${c.clientSecret.last4})` : ""}` : "missing"}
              {c.updatedBy ? ` · changed ${relativeTime(c.updatedAt) || ""} by ${c.updatedBy.name}` : ""} · {d!.linkedAccounts} linked</p>}
          </div>
          {!editing && <Button type="button" variant="outline" size="sm" onClick={startEdit} disabled={!d}>{c ? "Edit" : "Set up"}</Button>}
        </div>

        {d && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Copyable label="Redirect URI (add it at your identity provider)" value={d.redirectUri} />
            <Copyable label="Organisation ID (for “Sign in with SSO”)" value={d.orgSlug} />
          </div>
        )}

        {editing && (
          <form onSubmit={submit} noValidate aria-label="Single sign-on settings" className="flex flex-col gap-3 border-t border-border-default pt-3">
            <div className="flex flex-col gap-1.5"><Label htmlFor="sso-issuer">Issuer URL</Label>
              <Input id="sso-issuer" spellCheck={false} placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0" value={issuer} onChange={(e) => setIssuer(e.target.value)} /></div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5"><Label htmlFor="sso-client-id">Client ID</Label>
                <Input id="sso-client-id" spellCheck={false} value={clientId} onChange={(e) => setClientId(e.target.value)} /></div>
              <div className="flex flex-col gap-1.5"><Label htmlFor="sso-client-secret">Client secret</Label>
                <Input id="sso-client-secret" type="password" autoComplete="off" placeholder={c?.clientSecret.set ? "••••••••" : ""} value={secret} onChange={(e) => setSecret(e.target.value)} />
                {c?.clientSecret.set && <p className="text-[12px] text-text-tertiary">Set{c.clientSecret.last4 ? ` (ends in ${c.clientSecret.last4})` : ""}. Leave empty to keep it.</p>}</div>
            </div>
            <p className="text-[12px] text-text-tertiary">Scopes: <span className="font-mono">{d?.scopes}</span>. The provider must send a verified <span className="font-mono">email</span> claim.</p>
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => runTest.mutate({ issuer: issuer.trim(), clientId: clientId.trim(), ...(secret ? { clientSecret: secret } : {}) })} disabled={runTest.isPending || !issuer.trim() || !clientId.trim()}>
                {runTest.isPending ? "Testing…" : "Test connection"}</Button>
              <Button type="button" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
              <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button>
            </div>
          </form>
        )}
        {!editing && c && (
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => runTest.mutate({})} disabled={runTest.isPending}>{runTest.isPending ? "Testing…" : "Test connection"}</Button>
            <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => remove.mutate()} disabled={remove.isPending}>Turn off single sign-on</Button>
          </div>
        )}
        {test && (
          <ul aria-label="Connection test" className="flex flex-col gap-1.5 rounded-[10px] border border-border-default bg-well px-3 py-2.5">
            {test.checks.map((x) => (
              <li key={x.name} className="flex items-start gap-2 text-[13px]">
                {x.ok ? <CheckCircle2 aria-label="Passed" className="mt-px size-4 shrink-0 text-green-600" /> : <XCircle aria-label="Failed" className="mt-px size-4 shrink-0 text-red-500" />}
                <span><span className="font-medium text-text-primary">{CHECK_LABEL[x.name] ?? x.name}:</span> <span className="text-text-secondary">{x.detail}</span></span>
              </li>
            ))}
          </ul>
        )}

        <div className="flex flex-col gap-2 border-t border-border-default pt-3">
          <p className="text-[13.5px] font-medium text-text-primary">Domains</p>
          <p className="text-[12.5px] text-text-secondary">SSO accepts addresses in these domains. Verify each with a DNS TXT record: sign-in suggestions, automatic joining and "Require SSO" only apply to verified domains.</p>
          <ul className="flex flex-col gap-2" aria-label="SSO domains">
            {(d?.domains ?? []).map((x) => (
              <li key={x.domain} aria-label={x.domain} className="flex flex-col gap-2 rounded-[10px] border border-border-default px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Globe className="size-4 text-text-tertiary" /><span className="font-mono text-[13px] text-text-primary">{x.domain}</span>
                  {x.verified ? <Chip tone="green">Verified</Chip> : <Chip tone="orange">Not verified</Chip>}
                  <span className="ml-auto flex gap-1">
                    {!x.verified && <Button type="button" size="sm" variant="outline" onClick={() => verify.mutate(x.domain)} disabled={verify.isPending}>Verify</Button>}
                    <Button type="button" size="sm" variant="ghost" aria-label={`Remove ${x.domain}`} onClick={() => dropDomain.mutate(x.domain)}><Trash2 className="size-3.5" /></Button>
                  </span>
                </div>
                {!x.verified && <Copyable label={`Add this TXT record to ${x.txtRecord.name}`} value={x.txtRecord.value} />}
                {domainMsg?.domain === x.domain && <p role={domainMsg.ok ? "status" : "alert"} className={cn("text-[12.5px]", domainMsg.ok ? "text-green-600" : "text-red-500")}>{domainMsg.text}</p>}
              </li>
            ))}
          </ul>
          <form className="flex gap-2" noValidate onSubmit={(e) => { e.preventDefault(); setDomainMsg(null); if (newDomain.trim()) addDomain.mutate(newDomain.trim()); }}>
            <Label htmlFor="sso-domain" className="sr-only">Domain</Label>
            <Input id="sso-domain" placeholder="company.com" spellCheck={false} value={newDomain} onChange={(e) => setNewDomain(e.target.value)} className="h-9" />
            <Button type="submit" size="sm" variant="outline" className="h-9" disabled={!newDomain.trim() || addDomain.isPending}><Plus className="size-3.5" />Add domain</Button>
          </form>
          {domainMsg && !domainMsg.domain && <p role="alert" className="text-[12.5px] text-red-500">{domainMsg.text}</p>}
        </div>

        <div className="flex flex-col gap-3 border-t border-border-default pt-3">
          {option("requireSso", "Require SSO for members", "Members with an address in a verified domain reach this organisation only after signing in with SSO. Their password sign-in still works for their private vault and other organisations. The owner is exempt.", true)}
          {option("trustIdpMfa", "Trust the identity provider's MFA", "Skip the authenticator code after SSO for members with an address in a verified domain. Only turn on if your provider enforces MFA.", false)}
          {option("autoJoin", "Auto-join verified domain users", "People with an address in a verified domain join this organisation as members on their first SSO sign-in (and can create an account through SSO).", true)}
        </div>
      </div>
    </section>
    {/* Without SSO too: verified domains also let people join by email (docs/provisioning.md). */}
    <DomainJoinSection />
  </>);
}
