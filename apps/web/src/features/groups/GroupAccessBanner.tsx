import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Users } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useSession } from "@/lib/session";
import { AgentAttestationError, fingerprintOf, isAgent, pinStatus } from "@/lib/orgKeys";
import { AgentWarning } from "@/features/vault/AgentWarning";
import { AgentChip } from "@/features/vault/people";
import { PERMISSION_LABEL, type VaultFolder } from "@/features/vault/types";
import { useGroupAccess, type GroupPending } from "./groups";

/**
 * "N people are waiting for access" (docs/groups.md): group members who should reach a team folder I own or edit.
 * Nothing is sealed until I approve, per folder, seeing each person's name and email, the group that gives them
 * access, who added them to it, and the fingerprint of the key I'd seal to (with a warning if it changed since I
 * last sealed to them on this device).
 */
export function GroupAccessBanner({ folders }: { folders: VaultFolder[] }) {
  const { pending, approve, decline } = useGroupAccess(folders);
  const waiting = pending.filter((p) => !p.declined);
  const [open, setOpen] = useState(false);
  if (!waiting.length) return null;
  const folderCount = new Set(waiting.map((p) => p.folderId)).size;
  return (
    <>
      <div role="status" aria-label="Group access requests" className="flex shrink-0 items-center gap-2.5 border-b border-border bg-card px-6 py-2 text-[13px] text-text-primary max-[760px]:px-3">
        <Users className="size-4 shrink-0 text-text-secondary" />
        <p className="min-w-0 flex-1">{waiting.length === 1 ? "1 person is" : `${waiting.length} people are`} waiting for access to {folderCount === 1 ? "a team folder" : `${folderCount} team folders`} through a group.
          {" "}<button type="button" onClick={() => setOpen(true)} className="font-medium text-orange-ink underline-offset-2 hover:underline">Review</button></p>
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Access through groups</DialogTitle>
            <DialogDescription>These people were added to a group that a folder you hold the key of is shared with. They get the folder only if you approve.</DialogDescription>
          </DialogHeader>
          <div className="flex max-h-[60vh] flex-col gap-4 overflow-y-auto">
            {[...new Set(waiting.map((p) => p.folderId))].map((fid) => (
              <FolderRequests key={fid} folder={folders.find((f) => f.id === fid)} people={waiting.filter((p) => p.folderId === fid)}
                onApprove={async (people) => {
                  try { const r = await approve(fid, people); toast.success(r.skipped ? `Access given to ${r.added.length}; ${r.skipped} changed meanwhile, review again.` : `Access given to ${r.added.length}`); }
                  catch (e) { if (e instanceof AgentAttestationError) return e.message; toast.error("Couldn't give access. Try again."); }
                }}
                onDecline={async (ids) => { try { await decline(fid, ids); toast.success("Declined"); } catch { toast.error("Couldn't decline. Try again."); } }} />
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** `onApprove` resolves to a message when sealing was refused (an agent's key not attested by the pinned gateway). */
function FolderRequests({ folder, people, onApprove, onDecline }: { folder?: VaultFolder; people: GroupPending[]; onApprove: (p: GroupPending[]) => Promise<string | void>; onDecline: (ids: string[]) => Promise<void> }) {
  const groups = [...new Set(people.flatMap((p) => p.via.map((v) => v.groupName)))];
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<string | null>(null);
  const run = (f: () => Promise<void>) => { setBusy(true); void f().finally(() => setBusy(false)); };
  return (
    <section aria-label={`Requests for ${folder?.name ?? "a folder"}`} className="rounded-[10px] border border-border p-3">
      <h3 className="text-[13px] font-semibold">{people.length} {people.length === 1 ? "person" : "people"} waiting for access to {folder?.name ?? "a team folder"} via {groups.join(", ")}</h3>
      <ul className="mt-2 flex flex-col gap-2">
        {people.map((p) => <PersonRow key={p.userId} p={p} />)}
      </ul>
      {refused && <p role="alert" className="mt-2 text-[12.5px] text-red-500">{refused}</p>}
      {people.some(isAgent) && <div className="mt-3"><AgentWarning /></div>}
      <div className="mt-3 flex justify-end gap-2">
        <Button type="button" variant="ghost" disabled={busy} onClick={() => run(() => onDecline(people.map((p) => p.userId)))}>Decline</Button>
        <Button type="button" disabled={busy} onClick={() => run(async () => setRefused((await onApprove(people)) || null))}>Approve</Button>
      </div>
    </section>
  );
}

function PersonRow({ p }: { p: GroupPending }) {
  const { user, org } = useSession();
  const [fp, setFp] = useState<string | null>(null);
  const pin = useMemo(() => (user && org ? pinStatus(user.id, org.id, p.userId, p.membershipKey, p.publicKey) : { status: "new" as const }), [user, org, p.userId, p.membershipKey, p.publicKey]);
  useEffect(() => { if (p.membershipKey) void fingerprintOf(p.membershipKey).then(setFp); }, [p.membershipKey]);
  return (
    <li className="text-[13px]">
      <div><span className="font-medium">{p.name}</span>{isAgent(p) && <> <AgentChip /></>} <span className="text-text-secondary">{p.email}</span> · {PERMISSION_LABEL[p.permission]}</div>
      <div className="text-[12px] text-text-tertiary">
        {p.via.map((v) => `${v.groupName}${v.addedBy ? ` (added by ${v.addedBy.name})` : ""}`).join("; ")}
        {fp && <> · key <span className="font-mono">{fp}</span></>}
        {!p.membershipKey && " · no organisation key yet (sealed to their account key)"}
      </div>
      {pin.status === "changed" && (
        <p className="mt-1 flex items-center gap-1 text-[12px] text-orange-ink"><AlertTriangle className="size-3.5" />Their key changed since you last gave them access on this device (expected after an account reset). Check with them if unsure.</p>
      )}
    </li>
  );
}
