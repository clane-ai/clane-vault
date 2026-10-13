import { useState } from "react";
import { useSpacePaths } from "@/lib/space";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { Folder, Hourglass, UserPlus, UsersRound, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SectionPage } from "@/components/SectionLayout";
import { ApiError } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";
import { Chip, PersonAvatar } from "@/features/vault/people";
import { usePeople } from "@/features/vault/useVault";
import { PERMISSION_LABEL, type Grant, type VaultFolder } from "@/features/vault/types";

/** GET /admin/groups/:id. Folder names are encrypted: shown when the admin can open the folder. */
export interface GroupDetail {
  group: { id: string; name: string; createdAt: string };
  members: { id: string; name: string; email: string; addedAt: string }[];
  folders: { id: string; permission: Grant; sharedAt: string }[];
  pending: { folderId: string; userId: string; name: string; email: string; declined: boolean }[];
}

const card = "rounded-[14px] border border-border-default bg-card px-4 shadow-[var(--shadow-card)]";
const h2 = "flex items-center gap-2 font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

/** Admin → Groups → one group: its members (add, remove), the team folders shared with it and who still waits for a key. */
export default function GroupPage({ groupId, folders }: { groupId: string; folders: VaultFolder[] }) {
  // Admin pages of the active org (lib/paths): /o/:org/admin/...
  const adminBase = useSpacePaths().admin();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const people = usePeople();
  const KEY = ["admin-group", useScope(), groupId];
  const q = useQuery({ queryKey: KEY, queryFn: () => oapi.get<GroupDetail>(`/admin/groups/${groupId}`), retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 1 });
  const [adding, setAdding] = useState("");
  const d = q.data;
  const notFound = q.error instanceof ApiError && q.error.status === 404;
  const folderName = (id: string) => folders.find((f) => f.id === id && !f.deleted)?.name ?? null;
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: KEY }), qc.invalidateQueries({ queryKey: ["admin-groups"] }), qc.invalidateQueries({ queryKey: ["groups"] }), qc.invalidateQueries({ queryKey: ["vault"] })]);
  async function run(fn: () => Promise<unknown>, done: string) {
    try { await fn(); await refresh(); toast.success(done); return true; }
    catch (e) { toast.error(e instanceof ApiError && e.code === "user_not_member" ? "Only people in this organisation can join its groups." : "Couldn't save that. Try again."); return false; }
  }
  const candidates = (people.data ?? []).filter((p) => !d?.members.some((m) => m.id === p.id));

  return (
    <SectionPage title={d?.group.name ?? (notFound ? "Not found" : "Group")} label="Group" keepHeadings>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p>
        : notFound ? <p className="text-[14px] text-text-secondary">This group doesn't exist (any more). <Link to={`${adminBase}/groups`} className="font-medium text-[var(--link)]">Back to Groups</Link></p>
        : !d ? <p role="alert" className="text-[14px] text-red-500">Couldn't load this group.</p> : (<>
          <section className="flex flex-col gap-3" aria-label="Members">
            <h2 className={h2}><UsersRound className="size-4 text-text-tertiary" />Members <span className="font-mono text-[12px] font-normal text-text-tertiary">{d.members.length}</span></h2>
            {d.members.length > 0 && (
              <ul className={card}>
                {d.members.map((m) => (
                  <li key={m.id} className="flex items-center gap-3 border-b border-border-default py-2.5 last:border-b-0" aria-label={m.name}>
                    <PersonAvatar id={m.id} name={m.name} />
                    <span className="min-w-0 flex-1">
                      <Link to={`${adminBase}/people/${m.id}`} className="block truncate text-[14px] font-medium text-text-primary underline-offset-2 hover:underline">{m.name}</Link>
                      <span className="block truncate text-[12.5px] text-text-secondary">{m.email} · added {relativeTime(m.addedAt) || new Date(m.addedAt).toLocaleDateString()}</span>
                    </span>
                    <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${m.name} from ${d.group.name}`} className="hover:bg-red-tint hover:text-red-500"
                      onClick={() => void run(() => oapi.del(`/admin/groups/${groupId}/members/${m.id}`), `${m.name} removed from ${d.group.name}`)}><X className="size-4" /></Button>
                  </li>
                ))}
              </ul>
            )}
            {candidates.length > 0 && (
              <div className="flex items-center gap-2">
                <Select value={adding} onValueChange={setAdding}>
                  <SelectTrigger aria-label={`Add someone to ${d.group.name}`} className="h-9 max-w-[340px] flex-1 text-[13px]"><SelectValue placeholder="Add someone…" /></SelectTrigger>
                  <SelectContent>{candidates.map((p) => <SelectItem key={p.id} value={p.id}>{p.name} ({p.email})</SelectItem>)}</SelectContent>
                </Select>
                <Button type="button" variant="outline" disabled={!adding} onClick={async () => { if (await run(() => oapi.post(`/admin/groups/${groupId}/members`, { userIds: [adding] }), "Added to the group")) setAdding(""); }}>
                  <UserPlus className="size-4" />Add</Button>
              </div>
            )}
          </section>

          <section className="flex flex-col gap-3" aria-label="Folders shared with this group">
            <div><h2 className={h2}><Folder className="size-4 text-text-tertiary" />Team folders <span className="font-mono text-[12px] font-normal text-text-tertiary">{d.folders.length}</span></h2>
              <p className="text-[13px] text-text-secondary">A folder's owner shares it with the group from the folder's people sheet.</p></div>
            {d.folders.length > 0 && (
              <ul className={card}>
                {d.folders.map((f) => (
                  <li key={f.id} className="flex items-center gap-2 border-b border-border-default py-2.5 last:border-b-0">
                    <span className="min-w-0 flex-1 truncate text-[14px] text-text-primary">{folderName(f.id) ?? <span className="text-text-tertiary italic">A folder you aren't in</span>}</span>
                    <Chip>{PERMISSION_LABEL[f.permission]}</Chip>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="flex flex-col gap-3" aria-label="Waiting for access">
            <div><h2 className={h2}><Hourglass className="size-4 text-text-tertiary" />Waiting for access <span className="font-mono text-[12px] font-normal text-text-tertiary">{d.pending.length}</span></h2>
              <p className="text-[13px] text-text-secondary">Members who don't have a folder's key yet. Its owner or an editor gives it to them when they're next online.</p></div>
            {d.pending.length > 0 && (
              <ul className={card}>
                {d.pending.map((p) => (
                  <li key={`${p.folderId}:${p.userId}`} className={cn("flex flex-wrap items-center gap-2 border-b border-border-default py-2.5 last:border-b-0")}>
                    <Link to={`${adminBase}/people/${p.userId}`} className="min-w-0 truncate text-[14px] font-medium text-text-primary underline-offset-2 hover:underline">{p.name}</Link>
                    <span className="min-w-0 flex-1 truncate text-[13px] text-text-secondary">→ {folderName(p.folderId) ?? "a folder you aren't in"}</span>
                    {p.declined ? <Chip tone="red">Declined</Chip> : <Chip tone="orange">Waiting</Chip>}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>)}
    </SectionPage>
  );
}
