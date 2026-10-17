import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Building2, LogOut, Trash2, UserRoundCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api";
import { useOrgApi } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";
import { Chip } from "@/features/vault/people";
import { usePeople } from "@/features/vault/useVault";
import { ROLE_LABEL, useOrgDetails, useReloadOrgs } from "./orgs";
import { LogoField } from "@/features/settings/LogoField";
import { OrgAvatar, useOrgLogoUrl } from "./OrgLogo";
import { useLocked } from "@/features/admin/plan";
import { LockLine } from "@/features/admin/PlanLock";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const h2 = "font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary";

type Dialogs = "transfer" | "delete" | "leave" | null;

/**
 * Organisation settings: name and logo (owners and admins change them), members, and the owner's transfer/delete or a
 * member's leave.
 */
export function OrgDetailsSection() {
  const { org, user } = useSession();
  const oapi = useOrgApi();
  const d = useOrgDetails();
  const qc = useQueryClient();
  const reload = useReloadOrgs();
  const people = usePeople();
  const [name, setName] = useState<string | null>(null);
  const [open, setOpen] = useState<Dialogs>(null);
  const [target, setTarget] = useState("");
  const [confirmName, setConfirmName] = useState("");
  const [trash, setTrash] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const logoUrl = useOrgLogoUrl(org?.id, org?.logoVersion);
  const logoLocked = useLocked("orgLogo", org?.role === "owner" || org?.role === "admin");
  if (!org) return null;
  const isOwner = org.role === "owner";
  const canEdit = org.role === "owner" || org.role === "admin";
  const afterLogo = async () => { await reload(); await qc.invalidateQueries({ queryKey: ["org"] }); };
  const details = d.data;
  const close = () => { setOpen(null); setError(null); setConfirmName(""); setTrash(false); setTarget(""); };

  async function run(fn: () => Promise<unknown>, done: string) {
    setBusy(true); setError(null);
    try { await fn(); toast.success(done); close(); }
    catch (e) {
      const c = e instanceof ApiError ? e.code : "";
      setError(c === "confirm_name" ? "Type the organisation's name exactly." : c === "org_has_team_folders" ? "It still has team folders. Tick the box to delete them."
        : c === "invalid_request" ? "Use a plain name (up to 60 characters, no links or email addresses)." : c === "org_limit" ? "They already own as many organisations as allowed."
        : c === "default_org" ? "This server's main organisation can't be deleted." : c === "owner_must_transfer" ? "Transfer ownership first." : "Couldn't do that. Try again.");
    } finally { setBusy(false); }
  }
  async function rename(e: FormEvent) {
    e.preventDefault();
    if (!name?.trim()) return;
    await run(async () => { await oapi.patch("/org", { name: name.trim() }); setName(null); await reload(); await qc.invalidateQueries({ queryKey: ["org"] }); }, "Organisation renamed");
  }
  const candidates = (people.data ?? []).filter((p) => p.id !== user?.id);

  return (
    <section className="flex flex-col gap-3" aria-label="Organisation details">
      <h2 className={h2}>Organisation</h2>
      <div className={cn(card, "flex flex-col gap-3")}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Building2 className="size-4" /></span>
          <div className="min-w-0 flex-1">
            {name !== null ? (
              <form onSubmit={rename} className="flex flex-wrap items-end gap-2">
                <div className="flex min-w-[200px] flex-1 flex-col gap-1.5"><Label htmlFor="org-rename">Name</Label>
                  <Input id="org-rename" autoFocus maxLength={60} value={name} onChange={(e) => setName(e.target.value)} /></div>
                <Button type="button" variant="ghost" onClick={() => setName(null)}>Cancel</Button>
                <Button type="submit" disabled={busy || !name.trim()}>Save</Button>
              </form>
            ) : (
              <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-text-primary">{org.name}<Chip tone="blue">{ROLE_LABEL[org.role]}</Chip>{details?.isDefault && <Chip>Main organisation</Chip>}</p>
            )}
            {details && (
              <p className="mt-0.5 text-[13px] text-text-secondary">
                {details.memberCount} {details.memberCount === 1 ? "member" : "members"} · {details.teamFolderCount} team {details.teamFolderCount === 1 ? "folder" : "folders"}{details.owner ? ` · owner ${details.owner.name}` : ""}
              </p>
            )}
            <p className="mt-1 text-[12.5px] text-text-tertiary">Team folders, shares and people belong to this organisation. Your private records stay yours and show in every organisation.</p>
          </div>
          {canEdit && name === null && <Button type="button" variant="outline" size="sm" onClick={() => setName(org.name)}>Rename</Button>}
        </div>
        {canEdit && (
          <div className="border-t border-border-default pt-3">
            {logoLocked ? <LockLine /> : <LogoField id="org-logo" label="Organisation logo" url={logoUrl} fallback={<OrgAvatar org={{ id: org.id, name: org.name }} size={36} tone="light" />}
              onUpload={async (f) => { await oapi.upload("/org/logo", f); await afterLogo(); }}
              onRemove={async () => { await oapi.del("/org/logo"); await afterLogo(); }} />}
            {!logoLocked && <p className="mt-2 text-[12.5px] text-text-tertiary">Shown to this organisation's members in the sidebar and the organisation menu.</p>}
          </div>
        )}
        <div className="flex flex-wrap gap-2 border-t border-border-default pt-3">
          {isOwner ? (<>
            <Button type="button" variant="outline" size="sm" onClick={() => setOpen("transfer")}><UserRoundCheck className="size-3.5" />Transfer ownership</Button>
            {!details?.isDefault && <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setOpen("delete")}><Trash2 className="size-3.5" />Delete organisation</Button>}
          </>) : (
            <Button type="button" variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setOpen("leave")}><LogOut className="size-3.5" />Leave organisation</Button>
          )}
        </div>
      </div>

      <Dialog open={open !== null} onOpenChange={(o) => !o && close()}>
        <DialogContent>
          {open === "transfer" && (<>
            <DialogHeader>
              <DialogTitle>Transfer ownership of {org.name}?</DialogTitle>
              <DialogDescription>The new owner can rename, delete and transfer the organisation. You stay an admin.</DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-1.5"><Label htmlFor="transfer-to">New owner</Label>
              <Select value={target} onValueChange={setTarget}>
                <SelectTrigger id="transfer-to"><SelectValue placeholder="Choose a member" /></SelectTrigger>
                <SelectContent>{candidates.map((p) => <SelectItem key={p.id} value={p.id}>{p.name} ({p.email})</SelectItem>)}</SelectContent>
              </Select></div>
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
              <Button type="button" disabled={busy || !target} onClick={() => void run(async () => { await oapi.post("/org/transfer", { userId: target }); await reload(); await qc.invalidateQueries({ queryKey: ["org"] }); }, "Ownership transferred")}>Transfer</Button>
            </div>
          </>)}
          {open === "delete" && (<>
            <DialogHeader>
              <DialogTitle>Delete {org.name}?</DialogTitle>
              <DialogDescription>Everyone loses access to its team folders, shares and links. People keep their accounts and private records. This can't be undone.</DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-1.5"><Label htmlFor="delete-confirm">Type <span className="font-mono">{org.name}</span> to confirm</Label>
              <Input id="delete-confirm" autoComplete="off" value={confirmName} onChange={(e) => setConfirmName(e.target.value)} /></div>
            {(details?.teamFolderCount ?? 0) > 0 && (
              <label className="flex items-start gap-2 text-[13px] text-text-primary">
                <input type="checkbox" className="mt-0.5" checked={trash} onChange={(e) => setTrash(e.target.checked)} />
                Delete its {details!.teamFolderCount} team {details!.teamFolderCount === 1 ? "folder" : "folders"} and every record in them for good
              </label>
            )}
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
              <Button type="button" variant="destructive" disabled={busy || confirmName.trim() !== org.name || ((details?.teamFolderCount ?? 0) > 0 && !trash)}
                onClick={() => void run(async () => { await oapi.delReq("/org", { confirmName: confirmName.trim(), trashTeamFolders: trash }); await reload(null); }, "Organisation deleted")}>Delete</Button>
            </div>
          </>)}
          {open === "leave" && (<>
            <DialogHeader>
              <DialogTitle>Leave {org.name}?</DialogTitle>
              <DialogDescription>You lose access to its team folders and to records shared with you there; records you created in its team folders stay with the organisation. Your account and private records stay yours.</DialogDescription>
            </DialogHeader>
            {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
              <Button type="button" variant="destructive" disabled={busy} onClick={() => void run(async () => { await oapi.post("/org/leave"); await reload(null); }, `You left ${org.name}`)}>Leave</Button>
            </div>
          </>)}
        </DialogContent>
      </Dialog>
    </section>
  );
}
