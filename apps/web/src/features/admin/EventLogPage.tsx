import { useState } from "react";
import { PageHeader } from "@/components/SectionLayout";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { Download } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useOrgApi, useScope } from "@/lib/scope";
import { cn } from "@/lib/utils";

interface Who { id: string; name: string | null; email: string | null }
export interface LogEvent { id: string; at: string; action: string; actor: Who | null; target: Who | null; recordId: string | null; folderId: string | null; ip: string | null; meta: unknown }
const ALL = "__all";

/** Filters → query string ("from"/"to" are whole days in the viewer's time zone). */
export function eventQuery(f: { actor: string; action: string; from: string; to: string }): string {
  const p = new URLSearchParams();
  if (f.actor) p.set("actor", f.actor);
  if (f.action) p.set("action", f.action);
  if (f.from) p.set("from", new Date(`${f.from}T00:00:00`).toISOString());
  if (f.to) p.set("to", new Date(`${f.to}T23:59:59.999`).toISOString());
  return p.toString();
}

/** Admin → Event log: the active org's events with filters, newest first, and a CSV export (docs/policies.md). */
export default function EventLogPage() {
  const oapi = useOrgApi();
  const scope = useScope();
  // The filters live in the query string (?actor=&action=&from=&to=): a filtered view can be bookmarked and shared.
  const [params, setParams] = useSearchParams();
  const f = { actor: params.get("actor") ?? "", action: params.get("action") ?? "", from: params.get("from") ?? "", to: params.get("to") ?? "" };
  const setF = (n: typeof f) => setParams(Object.fromEntries(Object.entries(n).filter(([, v]) => v)), { replace: true });
  const qs = eventQuery(f);
  const people = useQuery({ queryKey: ["admin-people", scope], queryFn: () => oapi.get<{ users: { id: string; name: string; email: string }[] }>("/admin/people") });
  const actions = useQuery({ queryKey: ["admin-event-actions", scope], queryFn: () => oapi.get<{ actions: string[] }>("/admin/events/actions").then((r) => r.actions) });
  const q = useInfiniteQuery({
    queryKey: ["admin-events", scope, qs], initialPageParam: null as string | null,
    queryFn: ({ pageParam }) => oapi.get<{ events: LogEvent[]; nextBefore: string | null }>(`/admin/events?${qs}${pageParam ? `${qs ? "&" : ""}before=${pageParam}` : ""}`),
    getNextPageParam: (last) => last.nextBefore,
  });
  const events = q.data?.pages.flatMap((p) => p.events) ?? [];
  const families = [...new Set((actions.data ?? []).map((a) => `${a.split(".")[0]}.`))];
  const [exporting, setExporting] = useState(false);

  async function exportCsv() {
    setExporting(true);
    try {
      const csv = await oapi.text(`/admin/events/export.csv${qs ? `?${qs}` : ""}`);
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = `events-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { toast.error("Couldn't export. Try again."); }
    finally { setExporting(false); }
  }

  const who = (w: Who | null) => (w ? w.name ?? w.email ?? "Former member" : "—");
  const th = "px-3 py-2 text-left font-mono text-[10.5px] font-normal tracking-[.08em] text-text-tertiary uppercase";
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Event log">
      <PageHeader title="Event log">
        <Button type="button" variant="outline" size="sm" onClick={() => void exportCsv()} disabled={exporting}><Download className="size-3.5" />{exporting ? "Exporting…" : "Export CSV"}</Button>
      </PageHeader>
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className="mx-auto flex max-w-[1000px] flex-col gap-4">
          <div className="flex flex-wrap items-end gap-3" role="group" aria-label="Filters">
            <div className="flex flex-col gap-1.5"><Label htmlFor="ev-actor">Who</Label>
              <Select value={f.actor || ALL} onValueChange={(v) => setF({ ...f, actor: v === ALL ? "" : v })}>
                <SelectTrigger id="ev-actor" className="w-[200px]"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value={ALL}>Anyone</SelectItem>{(people.data?.users ?? []).map((u) => <SelectItem key={u.id} value={u.id}>{u.name}</SelectItem>)}</SelectContent>
              </Select></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="ev-action">Action</Label>
              <Select value={f.action || ALL} onValueChange={(v) => setF({ ...f, action: v === ALL ? "" : v })}>
                <SelectTrigger id="ev-action" className="w-[220px]"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value={ALL}>Any action</SelectItem>
                  {families.map((x) => <SelectItem key={x} value={x}>{`${x}*`}</SelectItem>)}
                  {(actions.data ?? []).map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
              </Select></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="ev-from">From</Label><Input id="ev-from" type="date" className="w-[160px]" value={f.from} onChange={(e) => setF({ ...f, from: e.target.value })} /></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="ev-to">To</Label><Input id="ev-to" type="date" className="w-[160px]" value={f.to} onChange={(e) => setF({ ...f, to: e.target.value })} /></div>
            {(f.actor || f.action || f.from || f.to) && <Button type="button" variant="ghost" size="sm" onClick={() => setF({ actor: "", action: "", from: "", to: "" })}>Clear</Button>}
          </div>
          {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load the event log.</p> : (
            <div className="overflow-x-auto rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]">
              <table className="w-full min-w-[700px] text-[13px]">
                <thead><tr className="border-b border-border-default"><th className={th}>When</th><th className={th}>Who</th><th className={th}>Action</th><th className={th}>Target</th><th className={th}>IP</th></tr></thead>
                <tbody>
                  {events.length === 0 && <tr><td colSpan={5} className="px-3 py-6 text-center text-text-secondary">No events match.</td></tr>}
                  {events.map((e) => (
                    <tr key={e.id} className="border-b border-border-default last:border-b-0">
                      <td className="px-3 py-2 whitespace-nowrap text-text-secondary" title={e.at}>{new Date(e.at).toLocaleString()}</td>
                      <td className="px-3 py-2 text-text-primary">{who(e.actor)}</td>
                      <td className="px-3 py-2 font-mono text-[12px] text-text-primary">{e.action}</td>
                      <td className="px-3 py-2 text-text-secondary">{e.target ? who(e.target) : e.folderId ? "Team folder" : e.recordId ? "Record" : ""}</td>
                      <td className={cn("px-3 py-2 font-mono text-[12px] text-text-tertiary")}>{e.ip ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {q.hasNextPage && <Button type="button" variant="outline" className="self-center" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>{q.isFetchingNextPage ? "Loading…" : "Load more"}</Button>}
        </div>
      </div>
    </section>
  );
}
