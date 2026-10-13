import { useMemo, useState } from "react";
import { useSpacePaths } from "@/lib/space";
import { PageHeader } from "@/components/SectionLayout";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { HeartPulse, ShieldCheck } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import type { VaultFolder, VaultRecord } from "@/features/vault/types";
import { ISSUE_LABEL, type HealthIssue } from "./health";
import { useHealthReport } from "./useHealthReport";
import { usePasswordScores } from "@/features/vault/usePasswordScores";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
type Filter = "all" | HealthIssue;
const TONE: Record<HealthIssue, "orange" | "red" | "neutral"> = { weak: "orange", reused: "orange", old: "neutral", breached: "red" };

interface MemberHealth { id: string; name: string; email: string; role: string; status: string;
  report: { score: number; total: number; weak: number; reused: number; old: number; breached: number | null; reportedAt: string } | null }

/** Admin → Password health: each member's last reported counts and score (never their passwords); a row opens the member. */
export function TeamHealth() {
  // Admin pages of the active org (lib/paths): /o/:org/admin/...
  const adminBase = useSpacePaths().admin();
  const oapi = useOrgApi();
  const q = useQuery({ queryKey: ["admin-health", useScope()], queryFn: () => oapi.get<{ members: MemberHealth[] }>("/admin/health").then((r) => r.members) });
  const rows = q.data ?? [];
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.08em] text-text-tertiary uppercase";
  return (
    <section className="flex flex-col gap-3" aria-label="Team password health">
      <div><h2 className={h2}>Team</h2><p className="text-[13px] text-text-secondary">Counts each member's app reports from their own vault. Nobody's passwords leave their device.</p></div>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load the team report.</p> : (
        <div className={cn(card, "overflow-x-auto")}>
          <table className="w-full min-w-[620px] text-[13px]">
            <thead><tr className="border-b border-border-default"><th className={th}>Member</th><th className={th}>Score</th><th className={th}>Weak</th><th className={th}>Reused</th><th className={th}>Old</th><th className={th}>Breached</th><th className={th}>Reported</th></tr></thead>
            <tbody>
              {rows.map((m) => (
                <tr key={m.id} className="border-b border-border-default last:border-b-0" aria-label={m.name}>
                  <td className="px-3 py-2"><Link to={`${adminBase}/people/${m.id}`} className="block font-medium text-text-primary underline-offset-2 hover:underline">{m.name}</Link><span className="block text-[12px] text-text-secondary">{m.email}</span></td>
                  {m.report ? (<>
                    <td className="px-3 py-2 font-mono tabular-nums"><span className={cn(m.report.score >= 80 ? "text-green-600" : m.report.score >= 50 ? "text-orange-ink" : "text-red-500")}>{m.report.score}</span></td>
                    <td className="px-3 py-2 font-mono tabular-nums">{m.report.weak}</td><td className="px-3 py-2 font-mono tabular-nums">{m.report.reused}</td>
                    <td className="px-3 py-2 font-mono tabular-nums">{m.report.old}</td><td className="px-3 py-2 font-mono tabular-nums">{m.report.breached ?? "—"}</td>
                    <td className="px-3 py-2 text-text-secondary">{relativeTime(m.report.reportedAt) || new Date(m.report.reportedAt).toLocaleDateString()}</td>
                  </>) : <td colSpan={6} className="px-3 py-2 text-text-tertiary">No report yet</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Password health (docs/password-health.md) with its own report hook (the vault passes its shared one to HealthView). */
export default function HealthPage({ records, folders, loading = false, onOpen }: { records: VaultRecord[]; folders?: VaultFolder[]; loading?: boolean; onOpen: (id: string) => void }) {
  const scores = usePasswordScores(records);
  return <HealthView health={useHealthReport(records, loading, folders ?? [], scores)} records={records} loading={loading} onOpen={onOpen} />;
}

/** Password health: a score, issue counts and filterable lists that open the record. */
export function HealthView({ health, records, loading, onOpen }: { health: ReturnType<typeof useHealthReport>; records: VaultRecord[]; loading?: boolean; onOpen: (id: string) => void }) {
  const { user, org } = useSession();
  const { report, allowed, optIn, setOptIn, checking } = health;
  const [filter, setFilter] = useState<Filter>("all");
  const live = useMemo(() => records.filter((r) => !r.deleted && r.body?.password), [records]);

  const shown = live.filter((r) => (filter === "all" ? report.issues.has(r.id) : report.issues.get(r.id)?.includes(filter)));
  const issues: HealthIssue[] = ["weak", "reused", "old", ...(report.breached !== null ? ["breached" as const] : [])];
  const tone = report.score >= 80 ? "text-green-600" : report.score >= 50 ? "text-orange-ink" : "text-red-500";

  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Password health">
      {/* The records of the space in use (Personal, or the organisation). */}
      <PageHeader title="Password health" sub={org ? org.name : "Personal"} />
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[860px] flex-col gap-6">
          <div className={cn(card, "flex flex-wrap items-center gap-5 p-5")}>
            <div className="flex items-center gap-4">
              <span className="grid size-12 place-items-center rounded-[12px] bg-well text-text-tertiary"><HeartPulse className="size-5" /></span>
              <div><p className="font-mono text-[11px] tracking-[.08em] text-text-tertiary uppercase">Score</p>
                <p className={cn("font-display text-[34px] leading-none font-semibold tabular-nums", tone)} data-testid="health-score">{loading || health.scoring ? "…" : report.score}</p></div>
            </div>
            <div className="min-w-[200px] flex-1">
              <div className="h-2 overflow-hidden rounded-full bg-well" aria-hidden="true"><div className={cn("h-full rounded-full", report.score >= 80 ? "bg-green-500" : report.score >= 50 ? "bg-orange-500" : "bg-red-500")} style={{ width: `${report.score}%` }} /></div>
              <p className="mt-2 text-[13px] text-text-secondary">{report.total} {report.total === 1 ? "password" : "passwords"} checked, {report.issues.size} with issues. Checked on this device only.</p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2" role="group" aria-label="Filter">
            {(["all", ...issues] as Filter[]).map((f) => {
              const n = f === "all" ? report.issues.size : (report[f] ?? 0);
              return (
                <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}
                  className={cn("rounded-[9px] border px-3 py-1.5 text-[13px] transition-colors", filter === f ? "border-blue-500 bg-blue-tint text-text-primary" : "border-border-default bg-card text-text-secondary hover:text-text-primary")}>
                  {f === "all" ? "All issues" : ISSUE_LABEL[f]} <span className="ml-1 font-mono tabular-nums">{n}</span>
                </button>
              );
            })}
          </div>

          {loading ? <p className="text-[14px] text-text-secondary">Decrypting your vault…</p> : shown.length === 0 ? (
            <div className={cn(card, "flex items-center gap-3 p-4")}><ShieldCheck className="size-5 text-green-600" /><p className="text-[14px] text-text-primary">{filter === "all" ? "No issues found. Nice work." : `No ${ISSUE_LABEL[filter].toLowerCase()} passwords.`}</p></div>
          ) : (
            <ul className={cn(card, "px-4")} aria-label="Records with issues">
              {shown.map((r) => (
                <li key={r.id} className="border-b border-border-default last:border-b-0">
                  <button type="button" onClick={() => onOpen(r.id)} className="flex w-full items-center gap-3 py-2.5 text-left hover:opacity-80">
                    <span className="min-w-0 flex-1"><span className="block truncate text-[14px] font-medium text-text-primary">{r.body?.title}</span>
                      {r.body?.username && <span className="block truncate text-[12.5px] text-text-secondary">{r.body.username}</span>}</span>
                    <span className="flex shrink-0 flex-wrap justify-end gap-1">{report.issues.get(r.id)!.map((i) => <Chip key={i} tone={TONE[i]}>{ISSUE_LABEL[i]}</Chip>)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className={cn(card, "flex items-start gap-3 p-4")}>
            <div className="min-w-0 flex-1">
              <label htmlFor="hibp" className="text-[14px] font-medium text-text-primary">Check against known breaches</label>
              <p className="text-[12.5px] leading-relaxed text-text-secondary">
                {allowed ? "Uses Have I Been Pwned: only the first 5 characters of each password's SHA-1 hash are sent, never the password." : "Your organisation turned the breach check off."}
                {checking === "busy" && " Checking…"}{checking === "failed" && " The check couldn't reach the service; try again later."}
              </p>
            </div>
            <Switch id="hibp" aria-label="Check against known breaches" disabled={!allowed || !user} checked={optIn} onCheckedChange={setOptIn} />
          </div>

        </div>
      </div>
    </section>
  );
}
