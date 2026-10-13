import { useEffect, useMemo, useRef, useState } from "react";
import { PageHeader } from "@/components/SectionLayout";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, Check, CheckCircle2, Copy, Download, FileUp, Folder, FolderSync, Inbox, LoaderCircle, TriangleAlert, UserCheck, Users, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { copySecret } from "@/lib/clipboard";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { cn } from "@/lib/utils";
import { ImportFormatError } from "@/features/import/parsers";
import { Chip } from "@/features/vault/people";
import { PERMISSION_LABEL, type VaultFolder, type VaultRecord } from "@/features/vault/types";
import { parseKeeperExport, SOURCE_LABEL, type KeeperExport } from "./keeper";
import { buildPlan, defaultSelection, joins, planTypeCounts, recordsToWrite, totals, type DirectoryUser, type MemberStatus, type Plan, type PlanFolder, type Selection } from "./plan";
import { reportCsv, reportJson, reportTotals, type MigrationReport } from "./report";
import { clearMigrationLogs, fingerprint, logFor, useCompletePending, useMigration, usePendingMembers, type Progress } from "./useMigration";

const card = "rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const eyebrow = "font-mono text-[10.5px] tracking-[.1em] text-text-tertiary uppercase";

type Step =
  | { kind: "choose" }
  | { kind: "plan"; file: string; fp: string; ex: KeeperExport; plan: Plan }
  | { kind: "running"; progress: Progress }
  | { kind: "done"; file: string; fp: string; ex: KeeperExport; plan: Plan; report: MigrationReport };

const STATUS: Record<MemberStatus, { label: string; tone: "green" | "blue" | "orange" | "red" | "neutral" }> = {
  add: { label: "Added now", tone: "green" }, invite: { label: "Will be invited", tone: "blue" }, invited: { label: "Already invited", tone: "blue" },
  "awaiting-setup": { label: "Finishing sign-up", tone: "orange" }, disabled: { label: "Disabled, not added", tone: "red" }, self: { label: "You (owner)", tone: "neutral" },
  team: { label: "Not mapped (Keeper team)", tone: "orange" },
};
const n = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const KIND: Record<PlanFolder["kind"], string> = { team: "Team folder", private: "Private folder", none: "No folder" };

function Tile({ icon: Icon, label, value, sub }: { icon: LucideIcon; label: string; value: number; sub?: string }) {
  return (
    <div className={cn(card, "flex min-w-0 gap-3 p-3.5")} role="group" aria-label={label}>
      <span className="grid size-8 shrink-0 place-items-center rounded-[9px] bg-well text-text-tertiary"><Icon className="size-4" /></span>
      <div className="min-w-0">
        <p className={eyebrow}>{label}</p>
        <p className="font-display text-[20px] leading-tight font-semibold text-text-primary tabular-nums">{value}</p>
        {sub && <p className="truncate text-[12px] text-text-secondary">{sub}</p>}
      </div>
    </div>
  );
}

function CopyLink({ url, email }: { url: string; email: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button type="button" variant="outline" size="sm" aria-label={`Copy invite link for ${email}`}
      onClick={async () => { await copySecret(url, 120_000); setDone(true); toast.success("Invite link copied"); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}Copy link
    </Button>
  );
}

/** A download link for text made in the browser (a blob: URL; CSP-safe, nothing is uploaded). */
function DownloadLink({ text, type, name, children }: { text: string; type: string; name: string; children: React.ReactNode }) {
  const url = useMemo(() => URL.createObjectURL(new Blob([text], { type })), [text, type]);
  useEffect(() => () => URL.revokeObjectURL(url), [url]);
  return (
    <a href={url} download={name} className="inline-flex h-8 items-center gap-1.5 rounded-[8px] border border-border-default bg-card px-3 text-[13px] font-medium text-text-primary shadow-[var(--shadow-card)] transition-colors hover:bg-well">
      <Download className="size-3.5" />{children}
    </a>
  );
}

export function ExportGuide({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const code = "block rounded-[8px] border border-border-default bg-well px-3 py-2 font-mono text-[12px] whitespace-pre-wrap text-text-primary";
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="w-full sm:max-w-[520px]">
        <SheetHeader><SheetTitle className="font-display text-[18px] font-semibold tracking-[-0.02em]">Export from Keeper</SheetTitle><SheetCloseButton /></SheetHeader>
        <SheetBody className="text-[13.5px] text-text-primary">
          <p>Use <strong>Keeper Commander</strong> for a full migration: its export includes shared folders and who they're shared with. The web vault's export has records and folders only, so you add people by hand.</p>
          <ol className="flex list-decimal flex-col gap-2.5 pl-5">
            <li>Install Commander and sign in as a Keeper admin who can see every shared folder to move:<code className={cn(code, "mt-1.5")}>pip install keepercommander{"\n"}keeper shell</code></li>
            <li>Export to JSON (shared folders and their permissions included):<code className={cn(code, "mt-1.5")}>export --format json keeper-export.json</code></li>
            <li>Choose the file here. It's read and encrypted in this browser; it's never uploaded.</li>
            <li>When the migration is done, <strong>delete the export file</strong> and empty the trash. It holds every password in plain text.</li>
          </ol>
          <p className="text-text-secondary">Web vault instead: Settings → Export → JSON. Attachments aren't migrated; the report lists them so you can move them by hand.</p>
          <p className="text-text-secondary">The full guide is <span className="font-mono text-[12.5px]">docs/migrate-from-keeper.md</span>.</p>
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}

/** Pending folder members (people added to folders before they had an account), with "Complete pending members". */
function PendingCard({ folders }: { folders: VaultFolder[] }) {
  const p = usePendingMembers(true);
  const complete = useCompletePending();
  const [busy, setBusy] = useState(false);
  if (p.pending.length === 0) return null;
  const name = (id: string) => folders.find((f) => f.id === id)?.name ?? "Team folder";
  async function run() {
    setBusy(true);
    try {
      const r = await complete(p.ready, folders);
      if (r.added.length) toast.success(`Added ${r.added.length} ${r.added.length === 1 ? "person" : "people"} to their folders`);
      if (r.failed.length) toast.error(`${r.failed.length} couldn't be added. Try again.`);
    } catch { toast.error("The vault locked. Unlock and try again."); }
    finally { setBusy(false); }
  }
  return (
    <section className={cn(card, "flex flex-col gap-3 p-4")} aria-label="Pending members">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <h2 className={h2}>People waiting to join folders</h2>
          <p className="text-[13px] text-text-secondary">{p.pending.length} waiting · <strong className="text-text-primary">{p.ready.length} ready</strong>. People are added once they've registered and set up 2FA.</p>
        </div>
        <Button type="button" onClick={() => void run()} disabled={busy || p.ready.length === 0} aria-busy={busy}>
          {busy ? <LoaderCircle className="size-4 animate-spin" /> : <UserCheck className="size-4" />}Complete pending members
        </Button>
      </div>
      <ul className="flex flex-col divide-y divide-border-default rounded-[10px] border border-border-default">
        {p.pending.map((x) => (
          <li key={x.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]" aria-label={`${x.email} → ${name(x.folderId)}`}>
            <span className="min-w-0 flex-1 truncate text-text-primary">{x.email} <span className="text-text-tertiary">→</span> {name(x.folderId)}</span>
            <span className="text-text-secondary">{PERMISSION_LABEL[x.permission]}</span>
            {x.user ? <Chip tone="green">Ready</Chip> : <Chip>Not registered yet</Chip>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function FolderPlanRow({ f, sel, setSel }: { f: PlanFolder; sel: Selection; setSel: (s: Selection) => void }) {
  const included = !sel.excluded.has(f.key);
  const writing = recordsToWrite(f, sel).length;
  const toggle = () => { const ex = new Set(sel.excluded); if (included) ex.add(f.key); else ex.delete(f.key); setSel({ ...sel, excluded: ex }); };
  const members = f.members.filter((m) => m.status !== "self");
  return (
    <li className={cn("flex flex-col gap-2 border-b border-border-default px-4 py-3 last:border-b-0", !included && "opacity-60")} aria-label={f.name}>
      <div className="flex flex-wrap items-center gap-2.5">
        <input type="checkbox" className="size-4 accent-blue-500" checked={included} onChange={toggle} aria-label={`Include ${f.name}`} />
        {f.kind === "team" ? <Users className="size-4 text-blue-500" /> : f.kind === "private" ? <Folder className="size-4 text-blue-500" /> : <Inbox className="size-4 text-text-tertiary" />}
        <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{f.name}</span>
        <Chip tone={f.kind === "team" ? "blue" : "neutral"}>{KIND[f.kind]}</Chip>
        {f.kind !== "none" && <Chip tone={f.existingId ? "neutral" : "green"}>{f.existingId ? "Existing" : "New"}</Chip>}
        <span className="font-mono text-[12px] text-text-secondary tabular-nums">{writing} {writing === 1 ? "record" : "records"}</span>
        {f.duplicates > 0 && <Chip tone="orange">{f.duplicates} duplicate{f.duplicates === 1 ? "" : "s"}</Chip>}
      </div>
      {f.kind === "team" && members.length > 0 && (
        <ul className="ml-[26px] flex flex-col gap-1" aria-label={`People in ${f.name}`}>
          {members.map((m) => (
            <li key={m.label} className="flex flex-wrap items-center gap-2 text-[13px]">
              <span className="min-w-0 truncate text-text-primary">{m.name ? `${m.name} · ${m.email}` : m.label}</span>
              <Chip tone={m.status === "invite" && !joins(m, sel) ? "neutral" : STATUS[m.status].tone}>{m.status === "invite" && !joins(m, sel) ? "Not invited" : STATUS[m.status].label}</Chip>
              {m.status !== "team" && m.status !== "disabled" && <span className="text-text-secondary">{PERMISSION_LABEL[m.permission]}</span>}
              {m.manager && m.status !== "team" && <span className="text-[12px] text-text-tertiary">Keeper folder manager</span>}
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function PlanView({ plan, sel, setSel }: { plan: Plan; sel: Selection; setSel: (s: Selection) => void }) {
  const t = totals(plan, sel);
  const invitees = plan.people.filter((p) => p.status === "invite");
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-4 gap-3 max-[900px]:grid-cols-2">
        <Tile icon={FolderSync} label="Folders" value={t.folders} sub={`${t.newFolders} new`} />
        <Tile icon={FileUp} label="Records" value={t.records} sub={plan.skipped.length ? `${plan.skipped.length} unreadable` : "to encrypt and upload"} />
        <Tile icon={Users} label="People" value={t.people} sub={`${t.addNow} now · ${t.later} after sign-up`} />
        <Tile icon={TriangleAlert} label="Duplicates" value={t.duplicates} sub={t.duplicates ? (sel.duplicates === "skip" ? "will be skipped" : "imported anyway") : "none found"} />
      </div>
      <TypeLine types={planTypeCounts(plan)} />

      {t.duplicates > 0 && (
        <fieldset className={cn(card, "flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3")}>
          <legend className="sr-only">Duplicates</legend>
          <span className="text-[13.5px] text-text-primary">Records with the same title, username and URL already in the folder:</span>
          {(["skip", "import"] as const).map((v) => (
            <label key={v} className="flex items-center gap-2 text-[13.5px] text-text-primary">
              <input type="radio" name="dupes" className="accent-blue-500" checked={sel.duplicates === v} onChange={() => setSel({ ...sel, duplicates: v })} />{v === "skip" ? "Skip them" : "Import anyway"}
            </label>
          ))}
        </fieldset>
      )}

      <section className="flex flex-col gap-2" aria-label="Folders to create">
        <h2 className={h2}>Folders</h2>
        <p className="text-[13px] text-text-secondary">Keeper shared folders become team folders that you own; personal folders become your private folders. Nested paths are flattened. Untick a folder to leave it out.</p>
        <ul className={card}>{plan.folders.map((f) => <FolderPlanRow key={f.key} f={f} sel={sel} setSel={setSel} />)}</ul>
      </section>

      {invitees.length > 0 && (
        <section className="flex flex-col gap-2" aria-label="People to invite">
          <h2 className={h2}>People to invite</h2>
          <p className="text-[13px] text-text-secondary">They don't have an account yet. Each gets an invite link; once they've registered, use "Complete pending members" to add them to their folders.</p>
          <ul className={card}>
            {invitees.map((p) => (
              <li key={p.email} className="flex items-center gap-2.5 border-b border-border-default px-4 py-2.5 last:border-b-0">
                <input type="checkbox" className="size-4 accent-blue-500" aria-label={`Invite ${p.email}`} checked={!sel.noInvite.has(p.email)}
                  onChange={(e) => { const n = new Set(sel.noInvite); if (e.target.checked) n.delete(p.email); else n.add(p.email); setSel({ ...sel, noInvite: n }); }} />
                <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{p.email}</span>
                <span className="truncate text-[12.5px] text-text-secondary">{p.folders.join(", ")}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {(plan.teams.length > 0 || plan.attachments.length > 0 || plan.skipped.length > 0 || plan.multiFolder > 0) && (
        <section className="flex flex-col gap-2 text-[13px] text-text-secondary" aria-label="Not migrated">
          <h2 className={h2}>Good to know</h2>
          {plan.teams.length > 0 && <p><strong className="text-text-primary">Keeper teams aren't mapped:</strong> {plan.teams.map((x) => `${x.name} (${x.folders.join(", ")})`).join("; ")}. Add their people to those folders by hand.</p>}
          {plan.attachments.length > 0 && <p><strong className="text-text-primary">{n(plan.attachments.reduce((x, a) => x + a.files.length, 0), "attachment")}</strong> on {n(plan.attachments.length, "record")} aren't migrated; they're listed in the report.</p>}
          {plan.multiFolder > 0 && <p><strong className="text-text-primary">{n(plan.multiFolder, "record")}</strong> {plan.multiFolder === 1 ? "is" : "are"} in more than one Keeper folder; a copy goes into each.</p>}
          {plan.skipped.length > 0 && <p><strong className="text-text-primary">{n(plan.skipped.length, "record")} can't be read</strong>: {plan.skipped.slice(0, 5).map((s) => `${s.title ?? `record ${s.row}`} (${s.reason})`).join(", ")}{plan.skipped.length > 5 ? "…" : ""}</p>}
        </section>
      )}
    </div>
  );
}

/** "Login 12 · Payment card 3 · Server credentials 2": what kinds of record the migration brings over. */
function TypeLine({ types }: { types: { type: string; label: string; count: number }[] }) {
  if (!types.length) return null;
  return (
    <p className="text-[13px] text-text-secondary" aria-label="Record types">
      {types.map((x, i) => <span key={x.type}>{i > 0 && " · "}{x.label} <span className="font-mono text-text-primary tabular-nums">{x.count}</span></span>)}
    </p>
  );
}

export function ReportView({ report, fileName }: { report: MigrationReport; fileName: string }) {
  const t = reportTotals(report);
  const base = fileName.replace(/\.[^.]+$/, "") || "keeper";
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.1em] text-text-tertiary uppercase";
  const td = "px-3 py-2 text-[13px] text-text-primary";
  const ok = t.failed === 0 && report.failures.length === 0;
  return (
    <div className="flex flex-col gap-5" aria-label="Migration report" role="region">
      <div className="flex flex-wrap items-center gap-3">
        {ok ? <CheckCircle2 className="size-7 text-green-600" /> : <TriangleAlert className="size-7 text-orange-500" />}
        <div className="min-w-0 flex-1">
          <h2 className="font-display text-[18px] font-semibold text-text-primary">{ok ? "Migration finished" : "Migration finished with problems"}</h2>
          <p className="text-[13.5px] text-text-secondary">{n(t.created, "record")} created · {t.skipped} skipped · {t.failed} failed. Delete the export file from your computer now.</p>
        </div>
        <DownloadLink text={reportCsv(report)} type="text/csv" name={`${base}-migration-report.csv`}>CSV</DownloadLink>
        <DownloadLink text={reportJson(report)} type="application/json" name={`${base}-migration-report.json`}>JSON</DownloadLink>
      </div>
      {report.types && <TypeLine types={report.types} />}
      <table className={cn(card, "w-full table-fixed overflow-hidden")} aria-label="Folders">
        <thead className="bg-app"><tr><th className={cn(th, "w-[38%]")}>Folder</th><th className={th}>Type</th><th className={th}>Created</th><th className={th}>Skipped</th><th className={th}>Failed</th></tr></thead>
        <tbody>
          {report.folders.map((f) => (
            <tr key={`${f.kind}:${f.name}`} className="border-t border-border-default">
              <td className={cn(td, "truncate")}>{f.name}{f.status === "failed" && <span className="block text-[12px] text-red-500">{f.error}</span>}</td>
              <td className={cn(td, "text-text-secondary")}>{KIND[f.kind]}{f.status === "existing" && f.kind !== "none" ? " (existing)" : ""}</td>
              <td className={cn(td, "font-mono tabular-nums")}>{f.created}</td><td className={cn(td, "font-mono tabular-nums")}>{f.skipped}</td>
              <td className={cn(td, "font-mono tabular-nums", f.failed > 0 && "text-red-500")}>{f.failed}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {report.invites.length > 0 && (
        <section className="flex flex-col gap-2" aria-label="Invite links">
          <h3 className={h2}>Invite links to send</h3>
          <p className="text-[13px] text-text-secondary">Each link works once, for 7 days, and is shown only now (it's also in the downloaded report: keep that file safe).</p>
          <ul className={card}>
            {report.invites.map((i) => (
              <li key={i.email} className="flex items-center gap-3 border-b border-border-default px-4 py-2.5 last:border-b-0" aria-label={i.email}>
                <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{i.email}</span>
                {i.url ? <CopyLink url={i.url} email={i.email} /> : <span className="text-[12.5px] text-text-secondary">{i.note}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {report.pending.length > 0 && (
        <section className="flex flex-col gap-2" aria-label="Add after they register">
          <h3 className={h2}>Add after they register</h3>
          <p className="text-[13px] text-text-secondary">Folders can only be shared with active accounts. When these people have registered, press "Complete pending members" at the top of this page.</p>
          <ul className="flex flex-col gap-1 text-[13px] text-text-primary">
            {report.pending.map((p) => <li key={`${p.folder}|${p.email}`}>{p.email} → {p.folder} ({PERMISSION_LABEL[p.permission]}) <span className="text-text-tertiary">· {p.reason}</span></li>)}
          </ul>
        </section>
      )}
      {(report.managers.length > 0 || report.notAdded.length > 0 || report.teams.length > 0 || report.attachments.length > 0) && (
        <section className="flex flex-col gap-1.5 text-[13px] text-text-secondary" aria-label="Notes">
          <h3 className={h2}>Notes</h3>
          {report.managers.length > 0 && <p>Keeper folder managers (in Clane only the owner manages people): {report.managers.map((m) => `${m.email} (${m.folder})`).join(", ")}.</p>}
          {report.notAdded.length > 0 && <p>Not added: {report.notAdded.map((n) => `${n.email} → ${n.folder} (${n.reason})`).join(", ")}.</p>}
          {report.teams.length > 0 && <p>Keeper teams, add their people by hand: {report.teams.map((x) => `${x.name} (${x.folders.join(", ")})`).join("; ")}.</p>}
          {report.attachments.length > 0 && (
            <details><summary className="cursor-pointer">Attachments not migrated ({report.attachments.reduce((n, a) => n + a.files.length, 0)})</summary>
              <ul className="mt-1 list-disc pl-5">{report.attachments.map((a, i) => <li key={i}>{a.title} ({a.folder}): {a.files.join(", ")}</li>)}</ul>
            </details>
          )}
        </section>
      )}
    </div>
  );
}

/** Admin → Migrate from Keeper: choose a Keeper export, review the plan, run it, get the report. */
export default function MigratePage({ folders, records, vaultLoading }: { folders: VaultFolder[]; records: VaultRecord[]; vaultLoading?: boolean }) {
  const { user, keys } = useSession();
  const oapi = useOrgApi();
  const people = useQuery({ queryKey: ["admin-people", useScope()], queryFn: () => oapi.get<{ users: DirectoryUser[]; invites: { email: string }[] }>("/admin/people") });
  const { run } = useMigration();
  const [step, setStep] = useState<Step>({ kind: "choose" });
  const [sel, setSel] = useState<Selection>(defaultSelection);
  const [error, setError] = useState<string | null>(null);
  const [guide, setGuide] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  // The in-memory log holds team folder keys and invite links: drop it (and any plan with plaintext) on lock.
  useEffect(() => { if (!keys) { clearMigrationLogs(); setStep({ kind: "choose" }); } }, [keys]);
  // The plan matches people by email: only a directory read since this page opened (never an older cached copy).
  const ready = people.isFetchedAfterMount && !people.isFetching && !vaultLoading;

  const plan = (ex: KeeperExport) => buildPlan(ex, { me: { id: user?.id ?? "", email: user?.email ?? "" }, users: people.data?.users ?? [], invitedEmails: (people.data?.invites ?? []).map((i) => i.email), folders, records });

  async function onFile(f: File | undefined) {
    if (!f) return;
    setError(null);
    if (f.size > 50 * 1024 * 1024) return setError("That file is too big (over 50 MB).");
    try {
      const text = await f.text();
      const ex = parseKeeperExport(text);
      if (ex.items.length === 0 && ex.sharedFolders.length === 0) return setError("There's nothing to migrate in that file.");
      setSel(defaultSelection());
      setStep({ kind: "plan", file: f.name, fp: await fingerprint(text), ex, plan: plan(ex) });
    } catch (e) {
      setError(e instanceof ImportFormatError ? e.message : "We couldn't read that file.");
    } finally { if (input.current) input.current.value = ""; }
  }

  async function start(s: Extract<Step, { kind: "plan" | "done" }>) {
    setError(null);
    setStep({ kind: "running", progress: { phase: "Preparing", done: 0, total: 0 } });
    try {
      const report: MigrationReport = { ...await run(s.plan, sel, logFor(s.fp), folders, (progress) => setStep({ kind: "running", progress })), types: planTypeCounts(s.plan) };
      setStep({ kind: "done", file: s.file, fp: s.fp, ex: s.ex, plan: s.plan, report });
    } catch (e) {
      setError((e as Error).message === "Vault locked" ? "The vault locked during the migration. Unlock and run it again: what's done is skipped." : "The migration stopped. Check your connection and run it again: what's done is skipped.");
      setStep({ kind: "plan", file: s.file, fp: s.fp, ex: s.ex, plan: s.plan });
    }
  }

  const t = step.kind === "plan" ? totals(step.plan, sel) : null;
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Migrate from Keeper">
      <PageHeader title="Migrate from Keeper">
        <Button type="button" variant="ghost" size="sm" onClick={() => setGuide(true)}><BookOpen className="size-4" />How to export</Button>
      </PageHeader>
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[880px] flex-col gap-5">
          <PendingCard folders={folders} />
          {step.kind === "choose" && (
            <section className="flex flex-col gap-3" aria-label="Choose export">
              <div><h2 className={h2}>Bulk migration</h2>
                <p className="text-[13px] text-text-secondary">Moves a whole Keeper vault: shared folders become team folders with their people, personal folders become your private folders. You review the plan before anything is written. The file is read and encrypted in this browser; it's never uploaded.</p></div>
              <label htmlFor="mig-file" className={cn("flex cursor-pointer flex-col items-center gap-2 rounded-[12px] border border-dashed border-border-strong bg-app px-6 py-10 text-center transition-colors duration-150 hover:bg-well", !ready && "pointer-events-none opacity-60")}>
                <FileUp className="size-6 text-blue-500" />
                <span className="text-[14px] font-medium text-text-primary">{ready ? "Choose a Keeper JSON export" : "Loading people and your vault…"}</span>
                <span className="text-[12.5px] text-text-tertiary">Keeper Commander <span className="font-mono">export --format json</span> · Keeper web vault JSON</span>
              </label>
              <input ref={input} id="mig-file" aria-label="Keeper export file" type="file" accept=".json,application/json" className="sr-only" disabled={!ready} onChange={(e) => void onFile(e.target.files?.[0])} />
              <p className="text-[12.5px] text-text-tertiary">The export holds every password in plain text. Delete it when you're done. <button type="button" className="font-medium text-text-primary underline-offset-2 hover:underline" onClick={() => setGuide(true)}>Read the guide</button></p>
            </section>
          )}
          {step.kind === "plan" && (
            <>
              <p className="text-[13.5px] text-text-primary"><strong>{step.file}</strong> · {SOURCE_LABEL[step.ex.source]}{step.ex.source === "web-vault" ? ". This export has no sharing data: team folders are created with only you in them." : ""}</p>
              <PlanView plan={step.plan} sel={sel} setSel={setSel} />
              <div className="sticky bottom-0 flex flex-wrap items-center justify-end gap-2 border-t border-border-default bg-app py-3">
                <Button type="button" variant="ghost" onClick={() => setStep({ kind: "choose" })}>Choose another file</Button>
                <Button type="button" disabled={!t || (t.records === 0 && t.folders === 0)} onClick={() => void start(step)}>Start migration ({t?.records ?? 0} records)</Button>
              </div>
            </>
          )}
          {step.kind === "running" && (
            <div className={cn(card, "flex flex-col gap-3 p-5")} role="status">
              <p className="text-[14px] text-text-primary">Migrating… {step.progress.done} of {step.progress.total} records</p>
              <div className="h-2 overflow-hidden rounded-full bg-well"><div className="h-full rounded-full bg-blue-500 transition-[width] duration-200" style={{ width: `${step.progress.total ? (step.progress.done / step.progress.total) * 100 : 0}%` }} /></div>
              <p className="text-[12.5px] text-text-tertiary">{step.progress.phase}. Keep this page open until it finishes.</p>
            </div>
          )}
          {step.kind === "done" && (
            <>
              <ReportView report={step.report} fileName={step.file} />
              <div className="flex flex-wrap justify-end gap-2 border-t border-border-default pt-3">
                {reportTotals(step.report).failed + step.report.failures.length > 0 && <Button type="button" variant="outline" onClick={() => void start(step)}>Run again (skips what's done)</Button>}
                <Button type="button" onClick={() => setStep({ kind: "choose" })}>Migrate another file</Button>
              </div>
            </>
          )}
          {error && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{error}</p>}
        </div>
      </div>
      <ExportGuide open={guide} onOpenChange={setGuide} />
    </section>
  );
}
