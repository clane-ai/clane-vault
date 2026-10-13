import { useRef, useState, type ChangeEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Check, ClipboardList, Copy, FileUp, Send } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/api";
import { copySecret } from "@/lib/clipboard";
import { useOrgApi, useScope } from "@/lib/scope";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import { MAX_INVITE_ROWS, rowsFromCsv, rowsFromPaste, type InviteRowInput } from "./inviteCsv";
import { STATUS_LABEL, type BulkResponse, type BulkRow } from "./provisioning";

type Role = "member" | "admin";
type Step = "input" | "preview" | "results";

const ERRORS: Record<string, string> = {
  email_required: "Invites are sent by email here, and email isn't set up on this server.",
  group_not_found: "One of the chosen groups no longer exists. Reopen the dialog and choose again.",
  rate_limited: "Too many requests. Wait a minute and try again.",
};
const errorText = (e: unknown) => (e instanceof ApiError ? ERRORS[e.code] : undefined) ?? "Couldn't check the list. Try again.";

function StatusChip({ r }: { r: BulkRow }) {
  const s = r.status === "invited" && r.emailed ? { label: "Emailed", tone: "green" as const } : STATUS_LABEL[r.status];
  return <span title={r.detail ? `${s.label}: ${r.detail}` : undefined}><Chip tone={s.tone}>{s.label}{r.detail ? `: ${r.detail}` : ""}</Chip></span>;
}

function RowsTable({ rows, showLinks }: { rows: BulkRow[]; showLinks?: boolean }) {
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.08em] text-text-tertiary uppercase";
  return (
    <div className="max-h-[46vh] overflow-auto rounded-[10px] border border-border-default max-sm:max-h-none">
      <table className="w-full min-w-[520px] border-collapse text-[13px]">
        <thead className="sticky top-0 bg-well"><tr><th className={th}>Email</th><th className={th}>Role</th><th className={th}>Groups</th><th className={th}>Status</th>{showLinks && <th className={th}><span className="sr-only">Link</span></th>}</tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.row} className="border-t border-border-subtle" aria-label={r.email || `Row ${r.row}`}>
              <td className="max-w-[220px] px-3 py-2"><span className="block truncate font-mono text-[12.5px] text-text-primary" title={r.email}>{r.email || "—"}</span>{r.name && <span className="block truncate text-[12px] text-text-secondary">{r.name}</span>}</td>
              <td className="px-3 py-2 text-text-secondary">{r.role === "admin" ? "Admin" : r.role === "member" ? "Member" : r.role}</td>
              <td className="max-w-[160px] px-3 py-2"><span className="block truncate text-text-secondary" title={r.groups.join(", ")}>{r.groups.join(", ") || "—"}</span></td>
              <td className="px-3 py-2"><StatusChip r={r} /></td>
              {showLinks && <td className="px-2 py-1.5 text-right">{r.inviteUrl && <CopyOne url={r.inviteUrl} email={r.email} />}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CopyOne({ url, email }: { url: string; email: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button type="button" variant="ghost" size="sm" aria-label={`Copy invite link for ${email}`} onClick={async () => { await copySecret(url, 120_000); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check className="size-3.5 text-green-600" /> : <Copy className="size-3.5" />}Copy link
    </Button>
  );
}

/**
 * "Invite people" (docs/provisioning.md): pasted addresses or a CSV, a default role and groups, a preview of what the
 * server will do with each row (it checks members, open invitations, cooldowns and today's cap), then one request and
 * each row's result. Self-hosted, new invite links are shown once here to copy.
 */
export function InviteDialog({ open, onOpenChange, onSent }: { open: boolean; onOpenChange: (o: boolean) => void; onSent?: (r: BulkResponse) => void }) {
  const oapi = useOrgApi();
  const scope = useScope();
  const groupsQ = useQuery({ queryKey: ["admin-groups", scope], queryFn: () => oapi.get<{ groups: { id: string; name: string }[] }>("/admin/groups"), enabled: open });
  const groups = groupsQ.data?.groups ?? [];
  const [step, setStep] = useState<Step>("input");
  const [mode, setMode] = useState<"paste" | "csv">("paste");
  const [pasted, setPasted] = useState("");
  const [csv, setCsv] = useState<{ name: string; rows: InviteRowInput[] } | null>(null);
  const [role, setRole] = useState<Role>("member");
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<BulkResponse | null>(null);
  const [result, setResult] = useState<BulkResponse | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const rows = mode === "paste" ? rowsFromPaste(pasted) : csv?.rows ?? [];
  const body = (dryRun: boolean) => ({ rows: rows.map((r) => ({ email: r.email, ...(r.name ? { name: r.name } : {}), ...(r.role ? { role: r.role } : {}), ...(r.groups ? { groups: r.groups } : {}) })), role, groupIds, dryRun });

  function reset() {
    setStep("input"); setMode("paste"); setPasted(""); setCsv(null); setRole("member"); setGroupIds([]); setError(null); setPreview(null); setResult(null);
  }
  function close(o: boolean) { onOpenChange(o); if (!o) reset(); }

  async function readFile(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    if (f.size > 1_000_000) return setError("That file is too large (1 MB at most).");
    setError(null);
    setCsv({ name: f.name, rows: rowsFromCsv(await f.text()) });
  }

  async function check() {
    if (!rows.length) return setError(mode === "paste" ? "Paste at least one email address." : "Choose a CSV file with at least one row.");
    if (rows.length > MAX_INVITE_ROWS) return setError(`That's ${rows.length} rows: up to ${MAX_INVITE_ROWS} at a time.`);
    setBusy(true); setError(null);
    try { setPreview(await oapi.post<BulkResponse>("/admin/invites/bulk", body(true))); setStep("preview"); }
    catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  async function send() {
    setBusy(true); setError(null);
    try {
      const r = await oapi.post<BulkResponse>("/admin/invites/bulk", body(false));
      setResult(r); setStep("results"); onSent?.(r);
      const n = r.counts.invited ?? 0;
      toast.success(n === 1 ? "1 invitation sent" : `${n} invitations sent`);
    } catch (e) { setError(e instanceof ApiError && ERRORS[e.code] ? ERRORS[e.code]! : "Couldn't send the invitations. Try again."); }
    finally { setBusy(false); }
  }

  const ready = preview?.results.filter((r) => r.status === "valid").length ?? 0;
  const links = result?.results.filter((r) => r.inviteUrl) ?? [];
  const toggleGroup = (id: string) => setGroupIds((g) => (g.includes(id) ? g.filter((x) => x !== id) : [...g, id]));

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-[720px]">
        <DialogHeader>
          <DialogTitle>{step === "results" ? "Invitations sent" : "Invite people"}</DialogTitle>
          <DialogDescription>
            {step === "input" ? "Paste email addresses or upload a CSV. Everyone gets a link to create their account (or an invitation in the app if they already have one). Links work for 7 days."
              : step === "preview" ? "Check the list before anything is sent. Only rows marked Ready are invited."
              : "Each row's result. Groups apply when they join; folder access still needs a folder owner's approval."}
          </DialogDescription>
        </DialogHeader>

        {step === "input" && (
          <div className="flex min-w-0 flex-col gap-4">
            <Tabs value={mode} onValueChange={(v) => { setMode(v as "paste" | "csv"); setError(null); }}>
              <TabsList>
                <TabsTrigger value="paste"><ClipboardList />Paste addresses</TabsTrigger>
                <TabsTrigger value="csv"><FileUp />Upload CSV</TabsTrigger>
              </TabsList>
              <TabsContent value="paste" className="mt-3 flex flex-col gap-1.5">
                <Label htmlFor="bulk-emails">Email addresses</Label>
                <Textarea id="bulk-emails" rows={6} spellCheck={false} className="font-mono text-[13px]" placeholder={"ann@company.com, bob@company.com\ncara@company.com"} value={pasted} onChange={(e) => setPasted(e.target.value)} />
                <p className="text-[12.5px] text-text-secondary">Separate with commas or new lines. Up to {MAX_INVITE_ROWS} at a time.{rows.length ? ` ${rows.length} ${rows.length === 1 ? "address" : "addresses"}.` : ""}</p>
              </TabsContent>
              <TabsContent value="csv" className="mt-3 flex flex-col gap-2">
                <input ref={fileRef} type="file" accept=".csv,text/csv" className="sr-only" aria-label="CSV file" onChange={(e) => void readFile(e)} />
                <div className="flex flex-wrap items-center gap-3 rounded-[10px] border border-dashed border-border-strong bg-well px-4 py-4">
                  <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}><FileUp className="size-3.5" />Choose CSV file</Button>
                  <span className="min-w-0 text-[13px] text-text-secondary">{csv ? <><span className="font-medium text-text-primary">{csv.name}</span>: {csv.rows.length} {csv.rows.length === 1 ? "row" : "rows"}</> : "No file chosen"}</span>
                </div>
                <p className="text-[12.5px] text-text-secondary">Columns: <span className="font-mono">email</span>, <span className="font-mono">name</span>, <span className="font-mono">role</span> (member or admin), <span className="font-mono">groups</span> (separate several with ;). A header row is optional; without one the columns are read in that order.</p>
              </TabsContent>
            </Tabs>

            <div className="flex flex-wrap gap-4">
              <div className="flex flex-col gap-1.5"><Label htmlFor="bulk-role">Role</Label>
                <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                  <SelectTrigger id="bulk-role" className="w-[150px]"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="member">Member</SelectItem><SelectItem value="admin">Admin</SelectItem></SelectContent>
                </Select>
                <span className="text-[12px] text-text-tertiary">For rows without their own role.</span>
              </div>
              <fieldset className="flex min-w-0 flex-1 flex-col gap-1.5">
                <legend className="mb-1.5 text-[13px] font-medium text-text-primary">Add to groups</legend>
                {groups.length === 0 ? <p className="text-[12.5px] text-text-secondary">{groupsQ.isLoading ? "Loading groups…" : "No groups yet. Create them under Groups."}</p> : (
                  <div className="flex flex-wrap gap-1.5">
                    {groups.map((g) => {
                      const on = groupIds.includes(g.id);
                      return (
                        <button key={g.id} type="button" role="checkbox" aria-checked={on} onClick={() => toggleGroup(g.id)}
                          className={cn("inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-[12.5px] font-medium", on ? "border-[var(--blue-tint-border)] bg-blue-tint text-blue-ink" : "border-border-default bg-card text-text-secondary hover:bg-well")}>
                          {on && <Check className="size-3" />}{g.name}
                        </button>
                      );
                    })}
                  </div>
                )}
              </fieldset>
            </div>
            <p className="rounded-[10px] border border-border-default bg-well px-3 py-2 text-[12.5px] text-text-secondary">Groups apply when each person joins. Folders shared with a group still wait for a folder owner or editor to approve them.</p>
          </div>
        )}

        {step === "preview" && preview && (
          <div className="flex min-w-0 flex-col gap-3">
            <p className="text-[13.5px] text-text-primary" role="status">
              <span className="font-medium">{ready} will be invited</span>
              {preview.results.length - ready > 0 && <span className="text-text-secondary"> · {preview.results.length - ready} skipped</span>}
              <span className="text-text-secondary"> · {preview.cap.remaining} of {preview.cap.perDay} invitations left today</span>
            </p>
            <RowsTable rows={preview.results} />
          </div>
        )}

        {step === "results" && result && (
          <div className="flex min-w-0 flex-col gap-3">
            <p className="text-[13.5px] text-text-primary" role="status">
              <span className="font-medium">{result.counts.invited ?? 0} invited</span>
              {result.results.length - (result.counts.invited ?? 0) > 0 && <span className="text-text-secondary"> · {result.results.length - (result.counts.invited ?? 0)} skipped</span>}
            </p>
            {links.length > 0 && <p className="text-[12.5px] text-text-secondary">Invite links are shown once. Copy each one and send it to that person, or copy them all.</p>}
            <RowsTable rows={result.results} showLinks={links.length > 0} />
          </div>
        )}

        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}

        <div className="flex flex-wrap justify-end gap-2">
          {step === "input" && (<>
            <Button type="button" variant="ghost" onClick={() => close(false)}>Cancel</Button>
            <Button type="button" onClick={() => void check()} disabled={busy || !rows.length}>{busy ? "Checking…" : "Preview"}</Button>
          </>)}
          {step === "preview" && (<>
            <Button type="button" variant="ghost" onClick={() => { setStep("input"); setError(null); }}><ArrowLeft className="size-4" />Back</Button>
            <Button type="button" onClick={() => void send()} disabled={busy || ready === 0}><Send className="size-4" />{busy ? "Sending…" : ready === 1 ? "Send 1 invitation" : `Send ${ready} invitations`}</Button>
          </>)}
          {step === "results" && (<>
            {links.length > 1 && <Button type="button" variant="outline" onClick={async () => { await copySecret(links.map((r) => `${r.email},${r.inviteUrl}`).join("\n"), 120_000); toast.success(`${links.length} invite links copied`); }}><Copy className="size-4" />Copy all links</Button>}
            <Button type="button" onClick={() => close(false)}>Done</Button>
          </>)}
        </div>
      </DialogContent>
    </Dialog>
  );
}
