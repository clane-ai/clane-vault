import { useState } from "react";
import { templateOf, validateAgentPolicy, type AgentInject, type AgentPolicy, type RecordBody } from "@clane-vault/crypto";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { LockLine } from "../admin/PlanLock";

const DEFAULT_SECRET = "__default__";
const ENCODED = /%(2f|5c|2e)/i;
const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

/** The message to show under the section, or null when the policy is fine. Unicode hosts are refused, not converted: the gateway only matches punycode. */
export function agentPolicyError(p: AgentPolicy | undefined, body: Pick<RecordBody, "type" | "fields">): string | null {
  if (!p) return null;
  if (p.hosts.some((h) => /[^\x00-\x7f]/.test(h))) return "Agent policy: write international host names in punycode (xn--…). The gateway only matches that form.";
  try { validateAgentPolicy(p, body); return null; } catch (e) { return (e as Error).message.replace(/^agent policy:/, "Agent policy:"); }
}

interface S { hosts: string; kind: AgentInject["kind"]; name: string; prefix: string; secret: string; methods: string; paths: string }
// An empty list means deny all, so it shows as "none"; an omitted one is blank (any).
const listText = (a?: string[]) => (a === undefined ? "" : a.length ? a.join("\n") : "none");

function build(s: S, base: AgentPolicy | undefined, locked: boolean): AgentPolicy | undefined {
  const hosts = lines(s.hosts);
  if (!hosts.length) return undefined;
  const inject: AgentInject = s.kind === "header" ? { kind: "header", name: s.name.trim(), ...(s.prefix ? { prefix: s.prefix } : {}) }
    : s.kind === "query" ? { kind: "query", name: s.name.trim() } : { kind: s.kind };
  // Keeps what the form doesn't show (approval, and methods/paths while locked).
  const p: AgentPolicy = { ...base, v: 1, hosts, inject };
  if (s.secret === DEFAULT_SECRET) delete p.secret; else p.secret = s.secret;
  if (!locked) {
    const m = s.methods.split(/[,\s]+/).filter(Boolean).map((x) => x.toUpperCase());
    const ph = lines(s.paths);
    delete p.methods; delete p.paths;
    if (m.length) p.methods = (m.length === 1 && m[0] === "NONE" ? [] : m) as AgentPolicy["methods"];
    if (ph.length) p.paths = ph.length === 1 && ph[0] === "none" ? [] : ph;
  }
  return p;
}

export function AgentPolicyEditor({ body, value, onChange, pathsLocked = false }: {
  /** The record as it stands in the editor: its type and secret custom fields decide what can be injected. */
  body: Pick<RecordBody, "type" | "fields">; value: AgentPolicy | undefined; onChange: (p: AgentPolicy | undefined) => void;
  /** Methods and paths are a Business feature: shown, not editable. */ pathsLocked?: boolean;
}) {
  const [s, setS] = useState<S>(() => ({
    hosts: value?.hosts.join("\n") ?? "", kind: value?.inject.kind ?? "bearer",
    name: value && "name" in value.inject ? value.inject.name : "", prefix: value?.inject.kind === "header" ? value.inject.prefix ?? "" : "",
    secret: value?.secret ?? DEFAULT_SECRET, methods: listText(value?.methods).replace(/\n/g, ", "), paths: listText(value?.paths),
  }));
  const set = (patch: Partial<S>) => { const n = { ...s, ...patch }; setS(n); onChange(build(n, value, pathsLocked)); };
  const secrets = [
    ...templateOf(body.type).filter((f) => !f.core || f.key === "password").map((f) => ({ ref: f.core ? f.key : `data.${f.key}`, label: f.label })),
    ...(body.fields ?? []).filter((f) => f.kind === "secret").map((f) => ({ ref: `field:${f.id}`, label: f.label || "Custom field" })),
  ];
  const known = s.secret === DEFAULT_SECRET || secrets.some((x) => x.ref === s.secret);
  const methodsText = pathsLocked ? listText(value?.methods).replace(/\n/g, ", ") : s.methods;
  const pathsText = pathsLocked ? listText(value?.paths) : s.paths;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-hosts" className="text-[13px] text-text-primary">Allowed hosts</Label>
        <Textarea id="ag-hosts" rows={2} value={s.hosts} spellCheck={false} placeholder="api.stripe.com" className="font-mono text-[13.5px]" onChange={(e) => set({ hosts: e.target.value })} />
        <p className="text-[12px] leading-snug text-text-tertiary">One per line. Leave empty for no agent use. <code>*.example.com</code> matches subdomains only, never <code>example.com</code> itself or an IP address.</p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-kind" className="text-[13px] text-text-primary">Send it as</Label>
        <Select value={s.kind} onValueChange={(k) => set({ kind: k as S["kind"] })}>
          <SelectTrigger id="ag-kind" className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="bearer">Bearer token</SelectItem>
            <SelectItem value="basic">Basic auth</SelectItem>
            <SelectItem value="header">Custom header</SelectItem>
            <SelectItem value="query">Query parameter (weaker)</SelectItem>
          </SelectContent>
        </Select>
        {s.kind === "query" && <p className="text-[12px] leading-snug text-amber-700 dark:text-amber-500">Weaker: URLs end up in logs.</p>}
      </div>
      {(s.kind === "header" || s.kind === "query") && (
        <div className="flex gap-2">
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <Label htmlFor="ag-name" className="text-[13px] text-text-primary">{s.kind === "header" ? "Header name" : "Parameter name"}</Label>
            <Input id="ag-name" value={s.name} spellCheck={false} placeholder={s.kind === "header" ? "X-Api-Key" : "api_key"} onChange={(e) => set({ name: e.target.value })} />
          </div>
          {s.kind === "header" && (
            <div className="flex w-[130px] flex-col gap-1.5">
              <Label htmlFor="ag-prefix" className="text-[13px] text-text-primary">Header prefix</Label>
              <Input id="ag-prefix" value={s.prefix} spellCheck={false} placeholder="Token " onChange={(e) => set({ prefix: e.target.value })} />
            </div>
          )}
        </div>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-secret" className="text-[13px] text-text-primary">Secret</Label>
        <Select value={s.secret} onValueChange={(v) => set({ secret: v })}>
          <SelectTrigger id="ag-secret" className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={DEFAULT_SECRET}>Default for this record type</SelectItem>
            {secrets.map((x) => <SelectItem key={x.ref} value={x.ref}>{x.label}</SelectItem>)}
            {!known && <SelectItem value={s.secret}>{s.secret} (not on this record)</SelectItem>}
          </SelectContent>
        </Select>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-methods" className="text-[13px] text-text-primary">Allowed methods</Label>
        <Input id="ag-methods" value={methodsText} disabled={pathsLocked} spellCheck={false} placeholder="GET, POST" onChange={(e) => set({ methods: e.target.value })} />
        <p className="text-[12px] leading-snug text-text-tertiary">Empty allows any method. Type <code>none</code> to deny every request.</p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-paths" className="text-[13px] text-text-primary">Allowed paths</Label>
        <Textarea id="ag-paths" rows={2} value={pathsText} disabled={pathsLocked} spellCheck={false} placeholder="/v1/charges" className="font-mono text-[13.5px]" onChange={(e) => set({ paths: e.target.value })} />
        <p className="text-[12px] leading-snug text-text-tertiary">One per line, matched by whole segments. Empty allows any path. Type <code>none</code> to deny every request.</p>
        {ENCODED.test(pathsText) && <p role="status" className="text-[12px] leading-snug text-amber-700 dark:text-amber-500">The gateway always refuses encoded slashes, backslashes and dots (%2f, %5c, %2e) in a path, so requests using them never get through.</p>}
      </div>
      {pathsLocked && <LockLine />}
    </div>
  );
}
