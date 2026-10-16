import { useEffect, useMemo, useState } from "react";
import { flushSync } from "react-dom";
import { Link, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, CheckCircle2, ChevronDown, ChevronRight, Download, EyeOff, FileText, HelpCircle, KeyRound, LogIn, MailCheck, MinusCircle, Paperclip, Printer, ShieldCheck, Stethoscope, UsersRound, XCircle, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/SectionLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { useSpacePaths } from "@/lib/space";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { RiskReport } from "./RiskReport";
import "./risk-print.css";
import { csvTile, download, isTile, memberHas, pct, REMEDIATION, scoreTone, SEVERITY_LABEL, trendLabel, type Alert, type AlertPeople, type Benchmark, type RiskMember, type RiskMembers, type RiskOverview, type Tile } from "./model";
import { formatBytes } from "@/features/attachments/format";
import { StorageMembers } from "../StoragePages";
import { planMessage } from "../plan";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.08em] text-text-secondary uppercase";
const num = "font-mono tabular-nums";

/**
 * Admin → Risk dashboard (docs/risk-dashboard.md): a 0–100 score, utilisation tiles with per-member drill-downs, security
 * benchmarks with the exact settings page to fix each, high-priority alerts (last 30 days against the 30 before) and
 * the members' password health counts. "Download report" prints a plain version (Save as PDF in the print dialog).
 */
export default function RiskPage() {
  const oapi = useOrgApi();
  const scope = useScope();
  const { org } = useSession();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin-risk", scope], queryFn: () => oapi.get<RiskOverview>("/admin/risk") });
  const [params, setParams] = useSearchParams();
  const view = params.get("view");
  const tile: Tile | null = isTile(view) ? view : null;
  const openTile = (t: Tile | null) => setParams((p) => { const n = new URLSearchParams(p); if (t) n.set("view", t); else n.delete("view"); return n; }, { replace: true });

  // Printing (the button, or Ctrl+P on this page) renders the plain report; the print stylesheet shows only it.
  const [printing, setPrinting] = useState(false);
  useEffect(() => {
    const before = () => flushSync(() => setPrinting(true));
    const after = () => setPrinting(false);
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => { window.removeEventListener("beforeprint", before); window.removeEventListener("afterprint", after); };
  }, []);

  const ignore = useMutation({
    mutationFn: ({ key, on }: { key: string; on: boolean }) => (on ? oapi.post<RiskOverview>(`/admin/risk/benchmarks/${key}/ignore`) : oapi.del(`/admin/risk/benchmarks/${key}/ignore`).then(() => null)),
    onSuccess: (data, v) => {
      if (data) qc.setQueryData(["admin-risk", scope], data); else void qc.invalidateQueries({ queryKey: ["admin-risk", scope] });
      toast.success(v.on ? "Benchmark ignored" : "Benchmark restored");
    },
    onError: () => toast.error("Couldn't change the benchmark. Try again."),
  });

  const d = q.data;
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Risk dashboard">
      <PageHeader title="Risk dashboard">
        <Button type="button" variant="outline" size="sm" disabled={!d} onClick={() => { flushSync(() => setPrinting(true)); window.print(); }}><Printer className="size-3.5" /><span className="max-[760px]:sr-only">Download report</span></Button>
      </PageHeader>
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[1000px] flex-col gap-8">
          {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error || !d ? <p role="alert" className="text-[14px] text-red-500">Couldn't load the risk dashboard.</p> : (<>
            <ScoreCard d={d} />
            <Utilisation d={d} tile={tile} onTile={openTile} />
            {tile && (tile === "storage" ? <StorageMembers onClose={() => openTile(null)} /> : <Drilldown tile={tile} d={d} onClose={() => openTile(null)} />)}
            <Benchmarks d={d} busy={ignore.isPending} onIgnore={(key, on) => ignore.mutate({ key, on })} />
            <Alerts d={d} />
            <HealthSummary d={d} />
          </>)}
        </div>
      </div>
      {printing && d && <RiskReport d={d} orgName={org?.name ?? ""} />}
    </section>
  );
}

function ScoreCard({ d }: { d: RiskOverview }) {
  const s = d.score;
  const ignored = d.benchmarks.filter((b) => b.status === "ignored").length;
  return (
    <section aria-label="Risk score" className={cn(card, "flex flex-col gap-4 p-5")}>
      <div className="flex flex-wrap items-center gap-5">
        <div className="flex items-center gap-4">
          <span className="grid size-12 place-items-center rounded-[12px] bg-well text-text-secondary"><ShieldCheck className="size-5" /></span>
          <div><p className="font-mono text-[11px] tracking-[.08em] text-text-secondary uppercase">Security score</p>
            <p className={cn("font-display text-[34px] leading-none font-semibold tabular-nums", scoreTone(s.value))} data-testid="risk-score">{s.value}<span className="text-[15px] text-text-secondary"> / 100</span></p></div>
        </div>
        <div className="min-w-[220px] flex-1">
          <div className="h-2 overflow-hidden rounded-full bg-well" aria-hidden="true"><div className={cn("h-full rounded-full", s.value >= 80 ? "bg-green-600" : s.value >= 50 ? "bg-orange-500" : "bg-red-500")} style={{ width: `${s.value}%` }} /></div>
          <p className="mt-2 text-[13px] text-text-secondary">
            Benchmarks {s.benchmarks}/100{s.health !== null ? <> · password health {s.health}/100</> : " · no password health reports yet"}
            {ignored ? ` · ${ignored} ignored benchmark${ignored === 1 ? "" : "s"} not counted` : ""}
          </p>
        </div>
      </div>
      <details className="group text-[13px] text-text-secondary">
        <summary className="cursor-pointer font-medium text-blue-ink select-none">How is this computed?</summary>
        <div className="mt-2 flex flex-col gap-1.5 leading-relaxed">
          <p>Benchmarks: each passing benchmark earns its weight (high 3, medium 2, low 1); the score is the share earned of what could be: {s.counted.earned} of {s.counted.possible} points = {s.benchmarks}. Ignored benchmarks, ones that don't apply and ones you can't see don't count.</p>
          <p>Password health: the average score of the members' latest reports{s.health !== null ? ` (${s.health})` : " (none yet)"}.</p>
          <p>Score = {s.health !== null ? `${Math.round(s.weights.benchmarks * 100)}% benchmarks + ${Math.round(s.weights.health * 100)}% password health` : "the benchmark score (until members report password health)"}. Computed from settings and counts only; nobody's passwords or items are read.</p>
        </div>
      </details>
    </section>
  );
}

const TILE_META: Record<Tile, { label: string; icon: LucideIcon; with: string; without: string }> = {
  records: { label: "Members with records", icon: FileText, with: "With records", without: "Without records" },
  active: { label: "Signed in within 30 days", icon: LogIn, with: "Signed in", without: "Not signed in" },
  invites: { label: "Invitations accepted", icon: MailCheck, with: "", without: "" },
  two_factor: { label: "Two-step sign-in", icon: KeyRound, with: "IdP MFA session", without: "Authenticator code" },
  recovery_kit: { label: "Recovery kit saved", icon: UsersRound, with: "Saved a kit", without: "No kit" },
  health: { label: "Password health reported", icon: Stethoscope, with: "Reported in 30 days", without: "Not reported" },
  storage: { label: "File storage", icon: Paperclip, with: "", without: "" },
};

function Utilisation({ d, tile, onTile }: { d: RiskOverview; tile: Tile | null; onTile: (t: Tile | null) => void }) {
  const u = d.utilisation;
  const invTotal = u.invitations.accepted + u.invitations.pending;
  const tiles: { id: Tile; value: string; of: string; percent: number; note: string }[] = [
    { id: "records", value: `${u.withRecords}`, of: `of ${u.members}`, percent: pct(u.withRecords, u.members), note: "Can open at least one of the organisation's records" },
    { id: "active", value: `${u.active30d}`, of: `of ${u.members}`, percent: pct(u.active30d, u.members), note: "Used the app in the last 30 days" },
    { id: "invites", value: `${u.invitations.accepted}`, of: `of ${invTotal}`, percent: pct(u.invitations.accepted, invTotal), note: `${u.invitations.pending} pending` },
    { id: "two_factor", value: "100%", of: "required", percent: 100, note: `Required for everyone · ${u.twoFactor.idpMfaSessions} signed in with IdP MFA` },
    { id: "recovery_kit", value: `${u.recoveryKit}`, of: `of ${u.members}`, percent: pct(u.recoveryKit, u.members), note: "Can recover without an admin" },
    { id: "health", value: `${u.healthReported30d}`, of: `of ${u.members}`, percent: pct(u.healthReported30d, u.members), note: "Reported in the last 30 days" },
    ...(u.storage?.enabled ? [{ id: "storage" as const, value: formatBytes(u.storage.used), of: `of ${formatBytes(u.storage.quota)}`, percent: pct(u.storage.used, u.storage.quota),
      note: `${u.storage.files} ${u.storage.files === 1 ? "file" : "files"}${u.storage.used > u.storage.alertRatio * u.storage.quota ? " · over 90 %: uploads stop when full" : ""}` }] : []),
  ];
  return (
    <section aria-label="Utilisation" className="flex flex-col gap-3">
      <div><h2 className={h2}>Utilisation</h2><p className="text-[13px] text-text-secondary">{u.members} active member{u.members === 1 ? "" : "s"}. Open a tile for the members behind it.</p></div>
      <div className="grid grid-cols-3 gap-3 max-[900px]:grid-cols-2 max-[520px]:grid-cols-1">
        {tiles.map((t) => {
          const m = TILE_META[t.id];
          const on = tile === t.id;
          return (
            <button key={t.id} type="button" aria-pressed={on} aria-label={`${m.label}: ${t.value} ${t.of}`} onClick={() => onTile(on ? null : t.id)}
              className={cn(card, "flex flex-col gap-2 p-4 text-left hover:border-border-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40", on && "border-blue-500 bg-blue-tint")}>
              <span className="flex items-center gap-2 text-[13px] font-medium text-text-primary"><m.icon className="size-4 text-text-secondary" />{m.label}</span>
              <span className="flex items-baseline gap-1.5"><span className={cn("font-display text-[26px] leading-none font-semibold", num)}>{t.value}</span><span className="text-[13px] text-text-secondary">{t.of}</span>
                {t.id !== "two_factor" && <span className={cn("ml-auto text-[12px] text-text-secondary", num)}>{t.percent}%</span>}</span>
              <span className="h-1.5 overflow-hidden rounded-full bg-well" aria-hidden="true"><span className={cn("block h-full rounded-full", t.id === "storage" && t.percent > 90 ? "bg-red-500" : "bg-blue-500")} style={{ width: `${t.percent}%` }} /></span>
              <span className="text-[12.5px] text-text-secondary">{t.note}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function Drilldown({ tile, d, onClose }: { tile: Tile; d: RiskOverview; onClose: () => void }) {
  const oapi = useOrgApi();
  const scope = useScope();
  const qc = useQueryClient();
  const paths = useSpacePaths();
  const q = useQuery({ queryKey: ["admin-risk-members", scope], queryFn: () => oapi.get<RiskMembers>("/admin/risk/members") });
  const [has, setHas] = useState<"all" | "yes" | "no">("all");
  const [search, setSearch] = useState("");
  const [exporting, setExporting] = useState(false);
  useEffect(() => { setHas("all"); }, [tile]);
  const meta = TILE_META[tile];
  const s = search.trim().toLowerCase();
  const rows = useMemo(() => (q.data?.members ?? []).filter((m) => (has === "all" || memberHas(tile, m) === (has === "yes")) && (!s || m.name.toLowerCase().includes(s) || m.email.toLowerCase().includes(s))), [q.data, has, s, tile]);
  const invites = (q.data?.invites ?? []).filter((i) => !s || i.email.toLowerCase().includes(s));

  const resend = useMutation({
    mutationFn: () => oapi.post<{ resent: number; skipped: number }>("/admin/invites/resend-all", {}),
    onSuccess: (r) => {
      toast.success(r.resent ? `Sent ${r.resent} invitation${r.resent === 1 ? "" : "s"} again${r.skipped ? ` (${r.skipped} skipped: sent recently, over the daily limit or no seat left)` : ""}` : "Nothing sent: the invitations were sent recently or the daily limit is reached");
      void qc.invalidateQueries({ queryKey: ["admin-risk-members", scope] }); void qc.invalidateQueries({ queryKey: ["admin-risk", scope] });
    },
    onError: (e) => toast.error(planMessage(e) ?? (e instanceof ApiError && e.code === "email_required" ? "Set up email first: invitations can only be resent by email." : e instanceof ApiError && e.status === 429 ? "Too many requests. Try again in a minute." : "Couldn't resend the invitations.")),
  });

  async function exportCsv() {
    setExporting(true);
    try {
      const qs = new URLSearchParams({ tile: csvTile(tile), ...(has !== "all" && tile !== "invites" ? { has } : {}) });
      download(await oapi.text(`/admin/risk/members.csv?${qs}`), `${tile === "invites" ? "pending-invitations" : `members-${tile}`}-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch { toast.error("Couldn't export. Try again."); }
    finally { setExporting(false); }
  }

  const seg = (v: "all" | "yes" | "no", label: string) => (
    <button key={v} type="button" aria-pressed={has === v} onClick={() => setHas(v)}
      className={cn("rounded-[9px] border px-3 py-1.5 text-[13px]", has === v ? "border-blue-500 bg-blue-tint text-text-primary" : "border-border-default bg-card text-text-secondary hover:text-text-primary")}>{label}</button>
  );
  return (
    <section aria-label={`${meta.label}: members`} className={cn(card, "flex flex-col gap-3 p-4")}>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className={cn(h2, "mr-auto")}>{meta.label}</h2>
        {tile === "invites" && <Button type="button" size="sm" disabled={resend.isPending || !d.utilisation.invitations.pending} onClick={() => resend.mutate()}>{resend.isPending ? "Sending…" : "Resend all pending invites"}</Button>}
        <Button type="button" variant="outline" size="sm" disabled={exporting} onClick={() => void exportCsv()}><Download className="size-3.5" />{exporting ? "Exporting…" : "Export CSV"}</Button>
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>Close</Button>
      </div>
      {tile === "two_factor" && <p className="text-[13px] text-text-secondary">Every account sets up an authenticator before it can sign in, so two-step sign-in is on for all {d.utilisation.members} members. Members whose organisation trusts its identity provider's MFA may skip the code after single sign-on; those with such a session now are marked.</p>}
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter members">
        {tile !== "invites" && [seg("all", "All"), seg("yes", meta.with), seg("no", meta.without)]}
        <Input aria-label="Search people" placeholder="Search name or email" className="ml-auto w-[220px] max-[520px]:ml-0 max-[520px]:w-full" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load the members.</p> : tile === "invites" ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Pending invitation</th><th className={th}>Role</th><th className={th}>Invited</th><th className={th}>Expires</th></tr></thead>
            <tbody>
              {invites.length === 0 && <tr><td colSpan={4} className="px-3 py-6 text-center text-text-secondary">No pending invitations.</td></tr>}
              {invites.map((i) => (
                <tr key={i.email} className="border-b border-border-default last:border-b-0">
                  <td className="px-3 py-2 text-text-primary">{i.email}</td><td className="px-3 py-2 capitalize text-text-secondary">{i.role}</td>
                  <td className="px-3 py-2 text-text-secondary">{new Date(i.createdAt).toLocaleDateString()}</td><td className="px-3 py-2 text-text-secondary">{new Date(i.expiresAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-[12.5px] text-text-secondary">{d.utilisation.invitations.accepted} accepted. Resending gives each invitation a new link and a fresh 7 days (the old link stops working); it counts toward the daily invitation limit.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Member</th><th className={th}>Role</th><th className={th}>Records</th><th className={th}>Last active</th><th className={th}>Recovery kit</th><th className={th}>Health</th></tr></thead>
            <tbody>
              {rows.length === 0 && <tr><td colSpan={6} className="px-3 py-6 text-center text-text-secondary">No members match.</td></tr>}
              {rows.map((m) => <MemberRow key={m.id} m={m} tile={tile} to={paths.admin("people", m.id)} />)}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function MemberRow({ m, tile, to }: { m: RiskMember; tile: Tile; to: string }) {
  const yes = memberHas(tile, m);
  return (
    <tr className="border-b border-border-default last:border-b-0" aria-label={m.name}>
      <td className="px-3 py-2"><Link to={to} className="block font-medium text-text-primary underline-offset-2 hover:underline">{m.name}</Link><span className="block text-[12px] text-text-secondary">{m.email}</span></td>
      <td className="px-3 py-2 capitalize text-text-secondary">{m.role}</td>
      <td className={cn("px-3 py-2", num)} title={`Owns ${m.records.owned}, can open ${m.records.canOpen}`}>{m.records.canOpen}<span className="text-text-secondary"> ({m.records.owned} own)</span></td>
      <td className="px-3 py-2 text-text-secondary">{m.lastSeen ? relativeTime(m.lastSeen) : "Never"}{tile === "two_factor" && yes && <span className="ml-1.5 rounded-[6px] bg-well px-1.5 py-px text-[11px]">IdP MFA</span>}</td>
      <td className="px-3 py-2 text-text-secondary">{m.recoveryKit ? "Saved" : "None"}</td>
      <td className="px-3 py-2">{m.health ? <><span className={cn(num, scoreTone(m.health.score))}>{m.health.score}</span><span className="ml-1.5 text-[12px] text-text-secondary">{relativeTime(m.health.reportedAt)}</span></> : <span className="text-text-secondary">No report</span>}</td>
    </tr>
  );
}

const STATUS_ICON: Record<Benchmark["status"], { icon: LucideIcon; cls: string; label: string }> = {
  critical: { icon: XCircle, cls: "text-red-500", label: "Needs action" },
  completed: { icon: CheckCircle2, cls: "text-green-600", label: "Completed" },
  ignored: { icon: EyeOff, cls: "text-text-secondary", label: "Ignored" },
  not_applicable: { icon: MinusCircle, cls: "text-text-secondary", label: "Doesn't apply" },
  unknown: { icon: HelpCircle, cls: "text-text-secondary", label: "Not visible to you" },
};

function Benchmarks({ d, busy, onIgnore }: { d: RiskOverview; busy: boolean; onIgnore: (key: string, on: boolean) => void }) {
  const groups: { id: string; title: string; items: Benchmark[] }[] = [
    { id: "critical", title: "Critical", items: d.benchmarks.filter((b) => b.status === "critical" || b.status === "unknown") },
    { id: "completed", title: "Completed", items: d.benchmarks.filter((b) => b.status === "completed" || b.status === "not_applicable") },
    { id: "ignored", title: "Ignored", items: d.benchmarks.filter((b) => b.status === "ignored") },
  ];
  return (
    <section aria-label="Security benchmarks" className="flex flex-col gap-3">
      <div><h2 className={h2}>Security benchmarks</h2><p className="text-[13px] text-text-secondary">Checked against this organisation's settings. Fix opens the exact settings page; ignore a benchmark that doesn't fit how you work (it stops counting, and you can restore it).</p></div>
      {groups.map((g) => (
        <div key={g.id} role="group" aria-label={`${g.title} (${g.items.length})`} className={cn(card, "overflow-hidden")}>
          <p className="flex items-center gap-2 border-b border-border-default px-4 py-2 font-mono text-[11px] tracking-[.08em] text-text-secondary uppercase">{g.title}<span className={num}>{g.items.length}</span></p>
          {g.items.length === 0 && <p className="px-4 py-3 text-[13px] text-text-secondary">{g.id === "critical" ? "Nothing needs action." : g.id === "ignored" ? "No ignored benchmarks." : "None yet."}</p>}
          <ul>{g.items.map((b) => <BenchmarkRow key={b.key} b={b} instanceAdmin={d.instanceAdmin} busy={busy} onIgnore={onIgnore} />)}</ul>
        </div>
      ))}
    </section>
  );
}

function BenchmarkRow({ b, instanceAdmin, busy, onIgnore }: { b: Benchmark; instanceAdmin: boolean; busy: boolean; onIgnore: (key: string, on: boolean) => void }) {
  const paths = useSpacePaths();
  const st = STATUS_ICON[b.status];
  const fix = REMEDIATION[b.key];
  const canFix = fix && (b.key !== "backups" || instanceAdmin);
  return (
    <li className="flex flex-wrap items-center gap-3 border-b border-border-default px-4 py-3 last:border-b-0" aria-label={b.title}>
      <st.icon className={cn("size-[18px] shrink-0", st.cls)} aria-label={st.label} role="img" />
      <div className="min-w-[200px] flex-1">
        <p className="flex flex-wrap items-center gap-2 text-[13.5px] font-medium text-text-primary">{b.title}
          <span className="rounded-[6px] bg-well px-1.5 py-px font-mono text-[10.5px] font-normal text-text-secondary">{SEVERITY_LABEL[b.severity]}</span>
          {b.status === "ignored" && b.passing !== null && <span className="text-[12px] font-normal text-text-secondary">({b.passing ? "would pass" : "would need action"})</span>}</p>
        <p className="text-[12.5px] text-text-secondary">{b.detail}</p>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {canFix && b.status !== "not_applicable" && (
          <Button asChild size="sm" variant={b.status === "critical" ? "default" : "outline"}>
            <Link to={paths.admin(fix.section)} aria-label={`${b.status === "critical" ? "Fix" : "Review"}: ${b.title}`}>{b.status === "critical" ? "Fix" : "Review"}<ChevronRight className="size-3.5" /></Link>
          </Button>
        )}
        {b.status === "ignored"
          ? <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => onIgnore(b.key, false)} aria-label={`Restore benchmark: ${b.title}`}>Restore</Button>
          : b.status !== "not_applicable" && b.status !== "unknown" && <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => onIgnore(b.key, true)} aria-label={`Ignore benchmark: ${b.title}`}>Ignore</Button>}
      </div>
    </li>
  );
}

type SortKey = "label" | "current" | "previous" | "trend";
function Alerts({ d }: { d: RiskOverview }) {
  const oapi = useOrgApi();
  const paths = useSpacePaths();
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "current", dir: -1 });
  const [open, setOpen] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [all, setAll] = useState(false);
  const quiet = d.alerts.filter((a) => a.current === 0 && a.previous === 0).length;
  const trendVal = (a: Alert) => (a.trend === null ? Number.POSITIVE_INFINITY : a.trend);
  const rows = [...d.alerts].filter((a) => all || a.current > 0 || a.previous > 0).sort((a, b) => {
    const v = sort.key === "label" ? a.label.localeCompare(b.label) : sort.key === "trend" ? trendVal(a) - trendVal(b) || 0 : a[sort.key] - b[sort.key];
    return (v || a.label.localeCompare(b.label) * -sort.dir) * sort.dir;
  });
  const by = (key: SortKey) => setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === "label" ? 1 : -1 }));
  const head = (key: SortKey, label: string, right = false) => (
    <th className={cn(th, right && "text-right")} aria-sort={sort.key === key ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => by(key)} className={cn("inline-flex items-center gap-1 uppercase hover:text-text-primary", right && "flex-row-reverse")}>{label}
        {sort.key === key && (sort.dir === 1 ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />)}</button>
    </th>
  );
  async function exportCsv() {
    setExporting(true);
    try { download(await oapi.text("/admin/risk/alerts.csv"), `security-alerts-${new Date().toISOString().slice(0, 10)}.csv`); }
    catch { toast.error("Couldn't export. Try again."); }
    finally { setExporting(false); }
  }
  const total = d.alerts.reduce((a, x) => a + x.current, 0);
  return (
    <section aria-label="High-priority alerts" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-2">
        <div className="mr-auto"><h2 className={h2}>High-priority alerts</h2><p className="text-[13px] text-text-secondary">{total} risky event{total === 1 ? "" : "s"} in the last {d.windowDays} days, against the {d.windowDays} days before.</p></div>
        <Button type="button" variant="outline" size="sm" disabled={exporting} onClick={() => void exportCsv()}><Download className="size-3.5" />{exporting ? "Exporting…" : "Export CSV"}</Button>
      </div>
      <div className={cn(card, "overflow-x-auto")}>
        <table className="w-full min-w-[640px] text-[13px]">
          <thead><tr className="border-b border-border-default">{head("label", "Alert")}{head("current", `Last ${d.windowDays} days`, true)}{head("previous", "Previous", true)}{head("trend", "Trend", true)}<th className={th}><span className="sr-only">Details</span></th></tr></thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={5} className="px-3 py-6 text-center text-text-secondary">No risky events in the last {2 * d.windowDays} days.</td></tr>}
            {rows.map((a) => (<AlertRows key={a.action} a={a} open={open === a.action} onToggle={() => setOpen(open === a.action ? null : a.action)} eventsTo={`${paths.admin("events")}?action=${encodeURIComponent(a.action === "attachment.download_wide" ? "attachment.download" : a.action)}`} />))}
          </tbody>
        </table>
      </div>
      {quiet > 0 && <Button type="button" variant="ghost" size="sm" className="self-start" aria-pressed={all} onClick={() => setAll(!all)}>{all ? "Hide alerts with no events" : `Show all ${d.alerts.length} alerts (${quiet} with no events)`}</Button>}
      <p className="text-[12.5px] text-text-secondary">Sign-in alerts (failed sign-ins, token reuse, failed step-ups) are account events of your current members since they joined; they don't appear in the organisation's event log, so open their details here.</p>
    </section>
  );
}

function AlertRows({ a, open, onToggle, eventsTo }: { a: Alert; open: boolean; onToggle: () => void; eventsTo: string }) {
  const up = a.trend === null ? a.current > 0 : a.trend > 0;
  return (<>
    <tr className={cn("border-b border-border-default last:border-b-0", a.current === 0 && a.previous === 0 && "text-text-secondary")} aria-label={a.label}>
      <td className="px-3 py-2">
        {a.scope === "org" ? <Link to={eventsTo} className="font-medium text-text-primary underline-offset-2 hover:underline">{a.label}</Link> : <span className="font-medium text-text-primary">{a.label}</span>}
        <span className="block font-mono text-[11px] text-text-secondary">{a.action}</span>
      </td>
      <td className={cn("px-3 py-2 text-right", num, a.current > 0 && "font-semibold text-text-primary")}>{a.current}</td>
      <td className={cn("px-3 py-2 text-right text-text-secondary", num)}>{a.previous}</td>
      <td className={cn("px-3 py-2 text-right", num, a.current || a.previous ? (up ? "text-red-500" : "text-green-600") : "text-text-secondary")}>{trendLabel(a)}</td>
      <td className="px-2 py-2 text-right">
        <Button type="button" size="sm" variant="ghost" aria-expanded={open} disabled={a.current === 0} onClick={onToggle} aria-label={`People: ${a.label}`}>{open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}People</Button>
      </td>
    </tr>
    {open && <tr className="border-b border-border-default bg-app"><td colSpan={5} className="px-3 py-2"><AlertPeopleList action={a.action} /></td></tr>}
  </>);
}

function AlertPeopleList({ action }: { action: string }) {
  const oapi = useOrgApi();
  const scope = useScope();
  const paths = useSpacePaths();
  const q = useQuery({ queryKey: ["admin-risk-alert", scope, action], queryFn: () => oapi.get<AlertPeople>(`/admin/risk/alerts/${encodeURIComponent(action)}/members`) });
  if (q.isLoading) return <p className="text-[13px] text-text-secondary">Loading…</p>;
  if (q.error || !q.data) return <p role="alert" className="text-[13px] text-red-500">Couldn't load the details.</p>;
  return (
    <ul className="flex flex-col gap-1" aria-label={`People: ${q.data.label}`}>
      {q.data.people.map((p, i) => (
        <li key={p.user?.id ?? `none-${i}`} className="flex flex-wrap items-baseline gap-x-3 text-[13px]">
          {p.user ? <Link to={paths.admin("people", p.user.id)} className="font-medium text-text-primary underline-offset-2 hover:underline">{p.user.name ?? p.user.email ?? "Former member"}</Link> : <span className="text-text-secondary">No person (e.g. an unknown sign-in)</span>}
          <span className={cn("text-text-secondary", num)}>{[p.asActor ? `${p.asActor}× by them` : "", p.asTarget ? `${p.asTarget}× to them` : ""].filter(Boolean).join(" · ")}</span>
          <span className="text-[12px] text-text-secondary">last {relativeTime(p.lastAt)}</span>
        </li>
      ))}
    </ul>
  );
}

function HealthSummary({ d }: { d: RiskOverview }) {
  const paths = useSpacePaths();
  const h = d.health;
  const stat = (label: string, value: number | string | null) => (
    <div className="flex flex-col gap-0.5"><span className="font-mono text-[10.5px] tracking-[.08em] text-text-secondary uppercase">{label}</span><span className={cn("text-[20px] font-semibold text-text-primary", num)}>{value ?? "—"}</span></div>
  );
  return (
    <section aria-label="Password health summary" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-2">
        <div className="mr-auto"><h2 className={h2}>Password health</h2><p className="text-[13px] text-text-secondary">From the members' own reports: counts only, checked on their devices. {h.reported} of {h.members} reported ({h.reported30d} in the last 30 days).</p></div>
        <Button asChild variant="outline" size="sm"><Link to={paths.admin("health")}>Per member<ChevronRight className="size-3.5" /></Link></Button>
      </div>
      <div className={cn(card, "grid grid-cols-4 gap-4 p-4 max-[640px]:grid-cols-2")}>
        {stat("Average score", h.averageScore)}{stat("Members at risk", h.atRisk)}{stat("Passwords", h.passwords)}{stat("Weak", h.weak)}
        {stat("Reused", h.reused)}{stat("Old", h.old)}{stat("Breached", h.breached)}{stat("Breach check on", `${h.breachCheckMembers}`)}
      </div>
      <p className="text-[12.5px] text-text-secondary">At risk: a breached password, or a score under {h.atRiskBelow}. Breached counts only cover members who turned on the breach check.</p>
    </section>
  );
}
