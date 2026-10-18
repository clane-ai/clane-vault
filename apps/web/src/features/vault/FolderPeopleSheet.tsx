import { useState } from "react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useFolderGroups, useOrgGroups } from "@/features/groups/groups";
import { LogOut, Users, UsersRound, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useSession } from "@/lib/session";
import { isAgent } from "@/lib/orgKeys";
import { AgentWarning } from "./AgentWarning";
import { PeoplePicker } from "./PeoplePicker";
import { Chip, Fingerprint, PermissionSelect, PersonRow } from "./people";
import { PERMISSION_LABEL, type FolderMember, type Grant, type Person, type VaultFolder } from "./types";

export function FolderPeopleSheet({ folder, onClose, onAdd, onUpdate, onRemove, onGiveAccess }: {
  folder: VaultFolder | null; onClose: () => void;
  /** A member lost their key (account reset): a key holder seals the folder key to their new key, explicitly. */
  onGiveAccess?: (f: VaultFolder, m: FolderMember) => Promise<unknown>;
  onAdd: (f: VaultFolder, p: Person, permission: Grant) => Promise<unknown>;
  onUpdate: (folderId: string, userId: string, permission: Grant) => Promise<unknown>;
  onRemove: (folderId: string, userId: string) => Promise<unknown>;
}) {
  const { user } = useSession();
  const [confirmLeave, setConfirmLeave] = useState(false);
  const members = folder?.members ?? [];
  // Adding needs the folder key (sealed to the new member), so only a member who owns the folder can add; admins can also change or remove.
  const canAdd = folder?.myPermission === "owner" && !!folder.folderKey;
  const canManage = folder?.myPermission === "owner" || user?.role === "admin";
  const amOwner = folder?.myPermission === "owner";
  // Owners and editors hold the key: they can give it again to someone who lost theirs.
  const holdsKey = (folder?.myPermission === "owner" || folder?.myPermission === "edit") && !!folder?.folderKey;
  const owner = members.find((m) => m.permission === "owner");
  const grants = folder?.groups ?? [];
  // Access only through a group can't be left here: an admin removes them from the group.
  const myViaGroup = members.find((m) => m.userId === user?.id)?.directPermission === null;
  const groupsOf = (userId: string) => grants.filter((g) => g.memberIds.includes(userId)).map((g) => g.name);
  const orgGroups = useOrgGroups(!!folder && canAdd);
  const fg = useFolderGroups();
  const [pick, setPick] = useState("");
  const [pickPerm, setPickPerm] = useState<Grant>("view");
  const addable = (orgGroups.data ?? []).filter((g) => !grants.some((x) => x.id === g.id));

  const run = async (done: string, fn: () => Promise<unknown>) => {
    try { await fn(); toast.success(done); } catch { toast.error("Couldn't save that change. Try again."); }
  };

  return (
    <Sheet open={!!folder} onOpenChange={(o) => { if (!o) { setConfirmLeave(false); onClose(); } }}>
      <SheetContent side="right" showCloseButton={false} className="w-full sm:max-w-[480px]">
        <SheetHeader>
          <div className="min-w-0">
            <SheetTitle className="truncate">People in {folder?.name}</SheetTitle>
            <SheetDescription className="text-[13px] text-text-secondary">{members.length} {members.length === 1 ? "person" : "people"} can open this team folder.</SheetDescription>
          </div>
          <SheetCloseButton />
        </SheetHeader>
        <SheetBody>
          {owner && (
            <p className="rounded-[10px] border border-border-default bg-app px-3 py-2.5 text-[13px] text-text-secondary" aria-label="Folder owner">
              Owned by <span className="font-medium text-text-primary">{owner.userId === user?.id ? "you" : owner.name}</span>. Key fingerprint{" "}
              <Fingerprint publicKey={owner.membershipKey ?? owner.publicKey} className="text-text-primary" />. Compare it with them before trusting this folder.
            </p>
          )}
          {folder && canAdd && <PeoplePicker exclude={members.map((m) => m.userId)} onAdd={(p, perm) => onAdd(folder, p, perm).then(() => toast.success(`${p.name} added`))} />}
          {/* "Give access again" to an agent reseals to it: the warning stands above that button too (as ShareSheet). */}
          {holdsKey && onGiveAccess && members.some((m) => m.needsAccess && !!m.membershipKey && isAgent(m) && m.userId !== user?.id) && <AgentWarning />}
          <ul className="rounded-[12px] border border-border-default px-3" aria-label="Members">
            {members.map((m) => {
              const isFolderOwner = m.permission === "owner";
              // Access only through groups: managed on the group, not here.
              const viaGroup = !isFolderOwner && m.directPermission === null;
              const gs = groupsOf(m.userId);
              return (
                <PersonRow key={m.userId} id={m.userId} name={m.name} email={m.email} publicKey={m.membershipKey ?? m.publicKey} agent={isAgent(m)}
                  badge={<>{isFolderOwner && <Chip tone="blue">Owner</Chip>}{m.userId === user?.id && <Chip>You</Chip>}{!isFolderOwner && gs.length > 0 && <Chip>{viaGroup ? "via " : "+ "}{gs.join(", ")}</Chip>}{m.needsAccess && <Chip tone="orange">Needs access again</Chip>}</>}>
                  {m.needsAccess && holdsKey && onGiveAccess && folder && m.userId !== user?.id && (
                    <Button type="button" variant="outline" size="sm" title={m.membershipKey ? "Their new key's fingerprint is shown under their name: compare it with them" : "They haven't opened their vault since the reset"}
                      disabled={!m.membershipKey}
                      onClick={() => void run(`${m.name} has access again`, () => onGiveAccess(folder, m))}>Give access again</Button>
                  )}
                  {isFolderOwner || !canManage || viaGroup ? (
                    !isFolderOwner && <span className="text-[13px] text-text-secondary">{PERMISSION_LABEL[m.permission]}</span>
                  ) : (
                    <>
                      <PermissionSelect value={(m.directPermission ?? m.permission) as Grant} disabled={isAgent(m)} label={`Permission for ${m.name}`} onChange={(p) => folder && void run("Permission changed", () => onUpdate(folder.id, m.userId, p))} />
                      <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${m.name}`} className="hover:bg-red-tint hover:text-red-500"
                        onClick={() => folder && void run(`${m.name} removed`, () => onRemove(folder.id, m.userId))}><X className="size-4" /></Button>
                    </>
                  )}
                </PersonRow>
              );
            })}
          </ul>
          {(grants.length > 0 || canAdd) && (
            <section aria-label="Groups" className="flex flex-col gap-2">
              <h3 className="flex items-center gap-1.5 text-[13px] font-medium text-text-primary"><UsersRound className="size-3.5 text-text-tertiary" />Groups</h3>
              {grants.length > 0 && (
                <ul className="rounded-[12px] border border-border-default px-3" aria-label="Groups with access">
                  {grants.map((g) => (
                    <li key={g.id} className="flex items-center gap-3 border-b border-border-default py-2.5 last:border-b-0" aria-label={g.name}>
                      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-well text-text-tertiary"><UsersRound className="size-4" /></span>
                      <span className="min-w-0 flex-1"><span className="block truncate text-[14px] font-medium text-text-primary">{g.name}</span>
                        <span className="block text-[12.5px] text-text-secondary">{g.memberIds.length} {g.memberIds.length === 1 ? "member" : "members"}</span></span>
                      {canManage ? (<>
                        <PermissionSelect value={g.permission} label={`Permission for group ${g.name}`} onChange={(p) => folder && void run("Permission changed", () => fg.update(folder.id, g.id, p))} />
                        <Button type="button" variant="ghost" size="icon" aria-label={`Stop sharing with ${g.name}`} className="hover:bg-red-tint hover:text-red-500"
                          onClick={() => folder && void run(`${g.name} removed`, () => fg.remove(folder.id, g.id))}><X className="size-4" /></Button>
                      </>) : <span className="text-[13px] text-text-secondary">{PERMISSION_LABEL[g.permission]}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {folder && canAdd && addable.length > 0 && <>
                {/* Sharing with a group that has agents shares with those agents (capped to Use only by the server). */}
                {addable.find((g) => g.id === pick)?.members.some(isAgent) && <AgentWarning />}
                <div className="flex items-center gap-2">
                  <Select value={pick} onValueChange={setPick}>
                    <SelectTrigger aria-label="Group to share with" className="h-8 flex-1 text-[13px]"><SelectValue placeholder="Share with a group…" /></SelectTrigger>
                    <SelectContent>{addable.map((g) => <SelectItem key={g.id} value={g.id}>{g.name} ({g.members.length})</SelectItem>)}</SelectContent>
                  </Select>
                  <PermissionSelect value={pickPerm} label="Permission for the group" onChange={setPickPerm} />
                  <Button type="button" variant="outline" size="sm" disabled={!pick} onClick={() => {
                    const g = addable.find((x) => x.id === pick);
                    if (g) void run(`Shared with ${g.name}`, () => fg.add(folder, g, pickPerm)).then(() => setPick(""));
                  }}>Share</Button>
                </div>
              </>}
              {canAdd && grants.length > 0 && <p className="text-[12px] leading-snug text-text-tertiary">People who join a group later wait until you or an editor approve them (you'll see who, through which group, and who added them).</p>}
            </section>
          )}
          <p className="flex gap-2 text-[12.5px] leading-snug text-text-tertiary"><Users className="mt-0.5 size-3.5 shrink-0" />Removing someone stops their access right away. Anything they already copied stays with them, so change important passwords afterwards.</p>
        </SheetBody>
        <SheetFooter>
          {folder && !amOwner && !myViaGroup && (confirmLeave ? (
            <>
              <span className="mr-auto text-[13px] text-text-primary">Leave {folder.name}?</span>
              <Button type="button" variant="ghost" onClick={() => setConfirmLeave(false)}>Cancel</Button>
              <Button type="button" variant="destructive" onClick={() => user && void run("You left the folder", () => onRemove(folder.id, user.id)).then(onClose)}>Leave</Button>
            </>
          ) : <Button type="button" variant="ghost" className="mr-auto" onClick={() => setConfirmLeave(true)}><LogOut className="size-4" />Leave folder</Button>)}
          <Button type="button" onClick={onClose}>Done</Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
