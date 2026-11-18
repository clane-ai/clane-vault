import { useRef, useState } from "react";
import { X } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { defaultSecretRef, envKeys, templateOf, validateAgentPolicy, type AgentInject, type AgentPolicy, type RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { LockLine } from "../admin/PlanLock";

const DEFAULT_SECRET = "__default__";
const ENCODED = /%(2f|5c|2e)/i;
const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);
/** Hosts as typed or pasted: split on spaces, commas and new lines. */
const hostsIn = (s: string) => s.split(/[\s,]+/).filter(Boolean);
const KINDS: { kind: AgentInject["kind"]; label: string }[] = [{ kind: "bearer", label: "Bearer" }, { kind: "basic", label: "Basic" }, { kind: "header", label: "Header" }, { kind: "query", label: "Query" }];
const MASK = "••••••••";
const label = "text-[13px] text-text-primary";
const hint = "text-[12px] leading-snug text-text-tertiary";

/** The message to show under the section, or null when the policy is fine. Unicode hosts are refused, not converted: the gateway only matches punycode. */
// eslint-disable-next-line react-refresh/only-export-components
export function agentPolicyError(p: AgentPolicy | undefined, body: Pick<RecordBody, "type" | "fields" | "data">): string | null {
  if (!p) return null;
  if (p.hosts.some((h) => /[^\p{ASCII}]/u.test(h))) return "Agent policy: write international host names in punycode (xn--…). The gateway only matches that form.";
  try { validateAgentPolicy(p, body); return null; } catch (e) { return (e as Error).message.replace(/^agent policy:/, "Agent policy:"); }
}
/** One host on its own, through the same check: a chip the policy would be refused for is marked. */
const badHost = (h: string) => !!agentPolicyError({ v: 1, hosts: [h], inject: { kind: "bearer" } }, { type: "apiKey" });

/** Agent use applies to a record that has a policy or something to send: a default secret, a secret custom field, or an env file's keys. */
// eslint-disable-next-line react-refresh/only-export-components
export function agentUseApplies(b: Pick<RecordBody, "type" | "fields" | "data" | "agentPolicy">): boolean {
  return !!b.agentPolicy || defaultSecretRef(b.type) !== null || !!b.fields?.some((f) => f.kind === "secret") || (b.type === "envFile" && envKeys(b.data?.content ?? "").length > 0);
}

/**
 * The HTTP request an agent's call carries under this policy, line by line, the secret masked. One line when the policy
 * refuses every call (methods or paths set to none).
 */
// eslint-disable-next-line react-refresh/only-export-components
export function requestPreview(p: { hosts: string[]; inject: AgentInject; methods?: string[]; paths?: string[] }): string[] {
  if (p.methods?.length === 0 || p.paths?.length === 0) return ["No request is sent: the allowed methods or paths are set to none."];
  const i = p.inject;
  const path = p.paths?.[0] ?? "/";
  const target = i.kind === "query" ? `${path}${path.includes("?") ? "&" : "?"}${i.name || "api_key"}=${MASK}` : path;
  return [`${p.methods?.[0] ?? "GET"} ${target} HTTP/1.1`, `Host: ${p.hosts[0] ?? "api.example.com"}`,
    ...(i.kind === "bearer" ? [`Authorization: Bearer ${MASK}`] : i.kind === "basic" ? [`Authorization: Basic base64(username:${MASK})`]
      : i.kind === "header" ? [`${i.name || "X-Api-Key"}: ${i.prefix ?? ""}${MASK}`] : [])];
}

interface S { hosts: string[]; /** Typed, not yet a chip: it counts as a host all the same. */ draft: string; kind: AgentInject["kind"]; name: string; prefix: string; secret: string; methods: string; paths: string }
// An empty list means deny all, so it shows as "none"; an omitted one is blank (any).
const listText = (a?: string[]) => (a === undefined ? "" : a.length ? a.join("\n") : "none");
const injectOf = (s: S): AgentInject => s.kind === "header" ? { kind: "header", name: s.name.trim(), ...(s.prefix ? { prefix: s.prefix } : {}) }
  : s.kind === "query" ? { kind: "query", name: s.name.trim() } : { kind: s.kind };

function build(s: S, base: AgentPolicy | undefined, locked: boolean): AgentPolicy | undefined {
  const hosts = [...s.hosts, ...hostsIn(s.draft).filter((h) => !s.hosts.includes(h))];
  if (!hosts.length) return undefined;
  // Keeps what the form doesn't show (approval, and methods/paths while locked).
  const p: AgentPolicy = { ...base, v: 1, hosts, inject: injectOf(s) };
  if (s.secret === DEFAULT_SECRET) delete p.secret; else p.secret = s.secret;
  if (!locked) {
    const m = s.methods.split(/[,\s]+/).filter(Boolean).map((x) => x.toUpperCase());
    const ph = lines(s.paths);
    delete p.methods; delete p.paths;
    if (m.length) p.methods = (m.length === 1 && m[0] === "NONE" ? [] : m) as AgentPolicy["methods"];
    if (ph.length) p.paths = ph.length === 1 && ph[0]!.toLowerCase() === "none" ? [] : ph;
  }
  return p;
}

/**
 * The Agent use policy form (the Agent use sheet): hosts as chips, how the secret is sent with a preview of the request,
 * which field it is, and the Business limits. `onChange` gets the policy as it stands, or undefined with no host.
 */
export function AgentPolicyEditor({ body, value, onChange, pathsLocked = false }: {
  /** The record as it stands: its type, secret custom fields and (an env file) its keys decide what can be injected. */
  body: Pick<RecordBody, "type" | "fields" | "data">; value: AgentPolicy | undefined; onChange: (p: AgentPolicy | undefined) => void;
  /** Methods and paths are a Business feature: shown, not editable. */ pathsLocked?: boolean;
}) {
  // The policy as stored: what the form does not show survives clearing and refilling the hosts.
  const [stored] = useState(value);
  const [s, setS] = useState<S>(() => ({
    hosts: value?.hosts ?? [], draft: "", kind: value?.inject.kind ?? "bearer",
    name: value && "name" in value.inject ? value.inject.name : "", prefix: value?.inject.kind === "header" ? value.inject.prefix ?? "" : "",
    secret: value?.secret ?? DEFAULT_SECRET, methods: listText(value?.methods).replace(/\n/g, ", "), paths: listText(value?.paths),
  }));
  const hostInput = useRef<HTMLInputElement>(null);
  const set = (patch: Partial<S>) => { const n = { ...s, ...patch }; setS(n); onChange(build(n, stored, pathsLocked)); };
  /** Turns what is typed (or `text`: typed plus a paste) into chips. */
  const addHosts = (text = s.draft) => set({ hosts: [...s.hosts, ...hostsIn(text).filter((h, i, a) => !s.hosts.includes(h) && a.indexOf(h) === i)], draft: "" });
  // An env file injects one entry and nothing else: no Contents, no default (spec §10.5).
  const env = body.type === "envFile";
  const secrets = env ? envKeys(body.data?.content ?? "").map((k) => ({ ref: `env:${k}`, label: k })) : [
    ...templateOf(body.type).filter((f) => !f.core || f.key === "password").map((f) => ({ ref: f.core ? f.key : `data.${f.key}`, label: f.label })),
    ...(body.fields ?? []).filter((f) => f.kind === "secret").map((f) => ({ ref: `field:${f.id}`, label: f.label || "Custom field" })),
  ];
  const known = s.secret === DEFAULT_SECRET || secrets.some((x) => x.ref === s.secret);
  const methodsText = pathsLocked ? listText(value?.methods).replace(/\n/g, ", ") : s.methods;
  const pathsText = pathsLocked ? listText(value?.paths) : s.paths;
  const preview = requestPreview(build(s, stored, pathsLocked) ?? { hosts: [], inject: injectOf(s) });
  const secretName = secrets.find((x) => x.ref === (s.secret === DEFAULT_SECRET ? defaultSecretRef(body.type) : s.secret))?.label;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-hosts" className={label}>Allowed hosts</Label>
        <div className="flex items-start gap-2">
          {/* The box is the field: a click anywhere in it lands in the input. */}
          <div className="flex min-h-10 min-w-0 flex-1 cursor-text flex-wrap items-center gap-1.5 rounded-[10px] border border-input bg-card px-2 py-[5px] transition-[border-color,box-shadow] duration-150 hover:border-border-strong focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/20 dark:bg-input/30"
            onClick={(e) => { if (e.target === e.currentTarget) hostInput.current?.focus(); }}>
            {s.hosts.length > 0 && (
              <ul aria-label="Hosts added" className="contents">
                {s.hosts.map((h) => {
                  const bad = badHost(h);
                  return (
                    <li key={h} data-invalid={bad || undefined} className={cn("inline-flex h-7 max-w-full items-center gap-0.5 rounded-[7px] border py-0 pr-0.5 pl-2 font-mono text-[12.5px]",
                      bad ? "border-[var(--red-tint-border)] bg-red-tint text-red-500" : "border-border-default bg-well text-text-primary")}>
                      <span className="truncate">{h}</span>
                      <button type="button" aria-label={`Remove ${h}`} className="grid size-6 shrink-0 place-items-center rounded-[5px] text-text-tertiary outline-none hover:text-text-primary focus-visible:ring-2 focus-visible:ring-ring/40"
                        onClick={() => { set({ hosts: s.hosts.filter((x) => x !== h) }); hostInput.current?.focus(); }}><X className="size-3" /></button>
                    </li>
                  );
                })}
              </ul>
            )}
            <input id="ag-hosts" ref={hostInput} value={s.draft} spellCheck={false} autoComplete="off" autoCapitalize="none" placeholder={s.hosts.length ? "Add another" : "api.stripe.com"}
              aria-describedby="ag-hosts-hint" className="h-7 min-w-[120px] flex-1 bg-transparent px-1 font-mono text-[13.5px] text-text-primary outline-none placeholder:text-text-tertiary"
              onChange={(e) => (/[\s,]$/.test(e.target.value) ? addHosts(e.target.value) : set({ draft: e.target.value }))}
              onBlur={() => { if (s.draft.trim()) addHosts(); }}
              onPaste={(e) => { const t = e.clipboardData.getData("text"); if (/[\s,]/.test(t.trim())) { e.preventDefault(); addHosts(s.draft + t); } }}
              onKeyDown={(e) => {
                // Enter adds the host; with nothing typed it is the form's Enter (Save).
                if (e.key === "Enter" && s.draft.trim()) { e.preventDefault(); addHosts(); }
                if (e.key === "Backspace" && !s.draft && s.hosts.length) set({ hosts: s.hosts.slice(0, -1) });
              }} />
          </div>
          <Button type="button" variant="outline" className="h-10" aria-label="Add host" disabled={!s.draft.trim()} onClick={() => { addHosts(); hostInput.current?.focus(); }}>Add</Button>
        </div>
        <p id="ag-hosts-hint" className={hint}>Agents send this credential only to these hosts. They never see it. <code>*.example.com</code> matches subdomains only, never <code>example.com</code> itself or an IP address.</p>
      </div>

      <div className="flex flex-col gap-1.5">
        <span id="ag-kind" className={cn(label, "font-medium")}>Send it as</span>
        <RadioGroup.Root aria-labelledby="ag-kind" value={s.kind} onValueChange={(k) => set({ kind: k as S["kind"] })}
          className="grid h-10 grid-cols-4 gap-1 rounded-[10px] border border-border-default bg-well p-[3px]">
          {KINDS.map((k) => (
            <RadioGroup.Item key={k.kind} value={k.kind} className={cn("rounded-[7px] px-2 text-[13px] font-medium text-text-secondary transition-[color,background-color,box-shadow] duration-150 outline-none select-none",
              "hover:text-text-primary focus-visible:ring-3 focus-visible:ring-ring/25",
              "data-[state=checked]:bg-card data-[state=checked]:text-text-primary data-[state=checked]:shadow-[var(--shadow-card)] data-[state=checked]:ring-1 data-[state=checked]:ring-border-default")}>{k.label}</RadioGroup.Item>
          ))}
        </RadioGroup.Root>
        {s.kind === "query" && <p className="text-[12px] leading-snug text-amber-700 dark:text-amber-500">Weaker: URLs end up in logs.</p>}
      </div>
      {(s.kind === "header" || s.kind === "query") && (
        <div className="flex gap-2">
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <Label htmlFor="ag-name" className={label}>{s.kind === "header" ? "Header name" : "Parameter name"}</Label>
            <Input id="ag-name" value={s.name} spellCheck={false} placeholder={s.kind === "header" ? "X-Api-Key" : "api_key"} className="font-mono text-[13.5px]" onChange={(e) => set({ name: e.target.value })} />
          </div>
          {s.kind === "header" && (
            <div className="flex w-[130px] flex-col gap-1.5">
              <Label htmlFor="ag-prefix" className={label}>Header prefix</Label>
              <Input id="ag-prefix" value={s.prefix} spellCheck={false} placeholder="Token " className="font-mono text-[13.5px]" onChange={(e) => set({ prefix: e.target.value })} />
            </div>
          )}
        </div>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-secret" className={label}>Secret</Label>
        <Select value={env && s.secret === DEFAULT_SECRET ? "" : s.secret} onValueChange={(v) => set({ secret: v })}>
          <SelectTrigger id="ag-secret" className="w-full"><SelectValue placeholder="Choose an entry" /></SelectTrigger>
          <SelectContent>
            {!env && <SelectItem value={DEFAULT_SECRET}>Default for this record type</SelectItem>}
            {secrets.map((x) => <SelectItem key={x.ref} value={x.ref}>{x.label}</SelectItem>)}
            {!known && <SelectItem value={s.secret}>{s.secret} (not on this record)</SelectItem>}
          </SelectContent>
        </Select>
      </div>

      {/* Always dark, in both themes: it is the wire, not the app. */}
      <figure className="flex flex-col gap-1.5">
        <figcaption className={cn(label, "font-medium")}>What the service receives</figcaption>
        <pre aria-label="Request preview" className="overflow-x-auto rounded-[10px] border border-[var(--border-dark-2)] bg-navy-900 px-3.5 py-3 font-mono text-[12.5px] leading-[1.7] text-[var(--text-dark-tertiary)]">
          {preview.map((l, i) => {
            const at = l.indexOf(MASK);
            return (
              <span key={i} className={cn("block", at >= 0 && "text-[var(--text-on-dark)]")}>
                {at < 0 ? l : <>{l.slice(0, at)}<span className="text-[var(--green-code)]">{MASK}</span>{l.slice(at + MASK.length)}</>}
              </span>
            );
          })}
        </pre>
        <p className={hint}>The gateway puts {secretName ? <>the {secretName.toLowerCase()}</> : "the secret"} in place of the dots as the call leaves. The agent and the AI model get the reply, never the value.</p>
      </figure>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-methods" className={label}>Allowed methods</Label>
        <Input id="ag-methods" value={methodsText} disabled={pathsLocked} spellCheck={false} placeholder="GET, POST" onChange={(e) => set({ methods: e.target.value })} />
        <p className={hint}>Empty allows any method. Type <code>none</code> to deny every request.</p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="ag-paths" className={label}>Allowed paths</Label>
        <Textarea id="ag-paths" rows={2} value={pathsText} disabled={pathsLocked} spellCheck={false} placeholder="/v1/charges" className="font-mono text-[13.5px]" onChange={(e) => set({ paths: e.target.value })} />
        <p className={hint}>One per line, matched by whole segments. Empty allows any path. Type <code>none</code> to deny every request.</p>
        {ENCODED.test(pathsText) && <p role="status" className="text-[12px] leading-snug text-amber-700 dark:text-amber-500">The gateway always refuses encoded slashes, backslashes and dots (%2f, %5c, %2e) in a path, so requests using them never get through.</p>}
      </div>
      {pathsLocked && <LockLine />}
    </div>
  );
}
