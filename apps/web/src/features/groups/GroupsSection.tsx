import { useState, type FormEvent } from "react";
import { useSpacePaths } from "@/lib/space";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { Pencil, Trash2, UserPlus, UsersRound, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import { useOrgApi } from "@/lib/scope";
import { Chip, PersonAvatar } from "@/features/vault/people";
import { usePeople } from "@/features/vault/useVault";
import { useAdminGroups, type AdminGroup } from "./groups";

const card = "rounded-[14px] border border-border-default bg-card px-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";
const errorText = (e: unknown) => {
  const c = e instanceof ApiError ? e.code : "";
  return c === "exists" ? "A group with that name already exists." : c === "invalid_request" ? "Use a plain name (up to 60 characters, no links or email addresses)."
    : c === "user_not_member" ? "Only people in this organisation can join its groups." : "Couldn't save that. Try again.";
};

/**
 * Admin → Groups (docs/groups.md): create, rename and delete groups and choose their members. Folder owners
 * share team folders with groups; removing someone here ends the folder access they had only through the group.
 */
export function GroupsSection() {
  // Admin pages of the active org (lib/paths): /o/:org/admin/...
  const adminBase = useSpacePaths().admin();
  const q = useAdminGroups();
  const people = usePeople();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState<AdminGroup | null>(null);
  const [adding, setAdding] = useState<Record<string, string>>({});
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ["admin-groups"] }), qc.invalidateQueries({ queryKey: ["groups"] }), qc.invalidateQueries({ queryKey: ["vault"] })]);
  async function run(fn: () => Promise<unknown>, done: string) {
    try { await fn(); await refresh(); toast.success(done); return true; } catch (e) { toast.error(errorText(e)); return false; }
  }
  async function create(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setError(null);
    try { await oapi.post("/admin/groups", { name: name.trim() }); setName(""); await refresh(); toast.success("Group created"); }
    catch (err) { setError(errorText(err)); }
  }
  const groups = q.data ?? [];
  return (
    <section className="flex flex-col gap-3" aria-label="Groups">
      <div><h2 className={h2}>Groups <span className="font-mono text-[12px] font-normal text-text-tertiary">{groups.length}</span></h2>
        <p className="text-[13px] text-text-secondary">Share a team folder with a group once instead of person by person. Someone you add here gets the folder when its owner or an editor is next online.</p></div>
      <form onSubmit={create} className={`${card} flex flex-wrap items-end gap-3 py-4`} noValidate>
        <div className="flex min-w-[220px] flex-1 flex-col gap-1.5"><Label htmlFor="group-name">New group</Label>
          <Input id="group-name" maxLength={60} autoComplete="off" placeholder="e.g. Engineering" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <Button type="submit" disabled={!name.trim()}><UsersRound className="size-4" />Create group</Button>
        {error && <p role="alert" className="w-full text-[13px] text-red-500">{error}</p>}
      </form>
      {q.isLoading ? <p className="text-[14px] text-text-secondary">Loading…</p> : q.error ? <p role="alert" className="text-[14px] text-red-500">Couldn't load groups.</p> : groups.length > 0 && (
        <ul className="flex flex-col gap-3">
          {groups.map((g) => {
            const candidates = (people.data ?? []).filter((p) => !g.members.some((m) => m.id === p.id));
            return (
              <li key={g.id} className={`${card} py-3`} aria-label={`Group ${g.name}`}>
                <div className="flex flex-wrap items-center gap-2">
                  {renaming?.id === g.id ? (
                    <form className="flex flex-1 items-center gap-2" onSubmit={async (e) => { e.preventDefault(); if (await run(() => oapi.patch(`/admin/groups/${g.id}`, { name: renaming.name.trim() }), "Group renamed")) setRenaming(null); }}>
                      <Input aria-label="Group name" autoFocus maxLength={60} value={renaming.name} onChange={(e) => setRenaming({ id: g.id, name: e.target.value })} className="h-8 max-w-[260px]" />
                      <Button type="button" variant="ghost" size="sm" onClick={() => setRenaming(null)}>Cancel</Button>
                      <Button type="submit" size="sm" disabled={!renaming.name.trim()}>Save</Button>
                    </form>
                  ) : (<>
                    <p className="flex min-w-0 flex-1 items-center gap-2 text-[14px] font-medium text-text-primary"><Link to={`${adminBase}/groups/${g.id}`} className="truncate underline-offset-2 hover:underline">{g.name}</Link>
                      <Chip>{g.members.length} {g.members.length === 1 ? "member" : "members"}</Chip>{g.folderCount > 0 && <Chip tone="blue">{g.folderCount} {g.folderCount === 1 ? "folder" : "folders"}</Chip>}</p>
                    <Button type="button" variant="ghost" size="icon" aria-label={`Rename ${g.name}`} onClick={() => setRenaming({ id: g.id, name: g.name })}><Pencil className="size-4" /></Button>
                    <Button type="button" variant="ghost" size="icon" aria-label={`Delete ${g.name}`} className="hover:bg-red-tint hover:text-red-500" onClick={() => setDeleting(g)}><Trash2 className="size-4" /></Button>
                  </>)}
                </div>
                {g.members.length > 0 && (
                  <ul className="mt-2 flex flex-wrap gap-1.5" aria-label={`Members of ${g.name}`}>
                    {g.members.map((m) => (
                      <li key={m.id} className="flex items-center gap-1.5 rounded-full border border-border-default bg-app py-0.5 pr-1 pl-0.5 text-[12.5px] text-text-primary">
                        <PersonAvatar id={m.id} name={m.name} size={24} />{m.name}
                        <button type="button" aria-label={`Remove ${m.name} from ${g.name}`} className="grid size-5 place-items-center rounded-full text-text-tertiary hover:bg-red-tint hover:text-red-500"
                          onClick={() => void run(() => oapi.del(`/admin/groups/${g.id}/members/${m.id}`), `${m.name} removed from ${g.name}`)}><X className="size-3" /></button>
                      </li>
                    ))}
                  </ul>
                )}
                {candidates.length > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <Select value={adding[g.id] ?? ""} onValueChange={(v) => setAdding((a) => ({ ...a, [g.id]: v }))}>
                      <SelectTrigger aria-label={`Add someone to ${g.name}`} className="h-8 max-w-[300px] flex-1 text-[13px]"><SelectValue placeholder="Add someone…" /></SelectTrigger>
                      <SelectContent>{candidates.map((p) => <SelectItem key={p.id} value={p.id}>{p.name} ({p.email})</SelectItem>)}</SelectContent>
                    </Select>
                    <Button type="button" variant="outline" size="sm" disabled={!adding[g.id]} onClick={async () => {
                      const id = adding[g.id]!;
                      if (await run(() => oapi.post(`/admin/groups/${g.id}/members`, { userIds: [id] }), "Added to the group")) setAdding((a) => ({ ...a, [g.id]: "" }));
                    }}><UserPlus className="size-3.5" />Add</Button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <Dialog open={!!deleting} onOpenChange={(o) => !o && setDeleting(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete the group {deleting?.name}?</DialogTitle>
            <DialogDescription>People lose the team folders they could open only through this group. Access given to them directly or through other groups stays.</DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setDeleting(null)}>Cancel</Button>
            <Button type="button" variant="destructive" onClick={() => { const g = deleting!; setDeleting(null); void run(() => oapi.del(`/admin/groups/${g.id}`), "Group deleted"); }}>Delete</Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
