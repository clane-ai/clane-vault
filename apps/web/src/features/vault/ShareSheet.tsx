import { useState } from "react";
import { Link } from "react-router";
import { Info, Link2, UserMinus, Users } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { OneTimeLinkForm } from "@/features/links/OneTimeLinkSheet";
import { useSession, type Org } from "@/lib/session";
import { InOrg } from "@/lib/scope";
import { recordPath, spacePrefix } from "@/lib/paths";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PeoplePicker } from "./PeoplePicker";
import { RecordAvatar } from "./RecordAvatar";
import { Chip, Fingerprint, PermissionSelect, PersonAvatar } from "./people";
import { PERMISSION_LABEL, type Grant, type Person, type Permission, type VaultFolder, type VaultRecord } from "./types";
import { usePeople } from "./useVault";

const eyebrow = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** One row in "People with access": avatar · name, email, how they got access · trailing control. */
function AccessRow({ id, name, email, publicKey, via, badge, children }: {
  id: string; name: string; email?: string; publicKey?: string; via: string; badge?: React.ReactNode; children?: React.ReactNode;
}) {
  return (
    <li aria-label={name} className="flex items-center gap-3 border-b border-border-default px-4 py-3 transition-colors duration-150 last:border-b-0 hover:bg-app/60">
      <PersonAvatar id={id} name={name} />
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 items-center gap-1.5"><span className="truncate text-[14px] font-medium text-text-primary">{name}</span>{badge}</span>
        {email && <span className="block truncate text-[12.5px] text-text-secondary">{email}</span>}
        <span className="flex min-w-0 items-center gap-1.5 text-[11.5px] text-text-tertiary">
          <span className="shrink-0">{via}</span>
          {publicKey && <><span aria-hidden="true">·</span><Fingerprint publicKey={publicKey} className="truncate text-[11px]" /></>}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-1">{children}</span>
    </li>
  );
}

const PermissionChip = ({ permission }: { permission: Permission }) =>
  <span className="inline-flex h-8 w-[104px] items-center sm:w-[118px] rounded-[9px] border border-border-default bg-app px-3 text-[13px] text-text-secondary">{PERMISSION_LABEL[permission]}</span>;

/**
 * The Personal space's People tab: direct shares belong to an organisation (its members, policies and event log), so a
 * private record is shared inside one the user picks, and its shares are managed in that organisation's space.
 */
function PersonalSharing({ record, onShareIn }: { record: VaultRecord; onShareIn?: (inOrg: Org, p: Person, permission: Grant) => Promise<unknown> }) {
  const { orgs } = useSession();
  const [orgId, setOrgId] = useState(orgs[0]?.id ?? "");
  const target = orgs.find((o) => o.id === orgId) ?? null;
  const sharedIn = (record.sharedIn ?? []).map((id) => orgs.find((o) => o.id === id)).filter((o): o is Org => !!o);
  if (orgs.length === 0) return (
    <p className="rounded-[12px] border border-dashed border-border-mid px-4 py-3.5 text-[13px] text-text-secondary">
      Sharing with people happens inside an organisation. Join or create one to share this record, or send a one-time link.
    </p>
  );
  return (
    <>
      <section aria-label="Add people" className="flex flex-col gap-2.5">
        <h3 className="text-[13px] font-medium text-text-primary">Add people</h3>
        <div className="flex flex-col gap-1.5">
          <span aria-hidden="true" className="text-[12.5px] text-text-secondary">Share inside</span>
          <Select value={orgId} onValueChange={setOrgId}>
            <SelectTrigger aria-label="Share inside" className="h-10 w-full"><SelectValue /></SelectTrigger>
            <SelectContent>{orgs.map((o) => <SelectItem key={o.id} value={o.id}>{o.name}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        {target && onShareIn && (
          <InOrg key={target.id} org={target}>
            <PeoplePicker addLabel="Share" exclude={record.ownerId ? [record.ownerId] : []}
              onAdd={(p, perm) => onShareIn(target, p, perm).then(() => toast.success(`Shared with ${p.name} in ${target.name}`))} />
          </InOrg>
        )}
        <p className="text-[12px] leading-snug text-text-tertiary">The share belongs to that organisation: the record then also shows in its space, where you manage who has it.</p>
      </section>
      {sharedIn.length > 0 && (
        <section aria-label="Shared in" className="flex flex-col gap-2.5">
          <h3 className={eyebrow}>Shared in</h3>
          <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
            {sharedIn.map((o) => (
              <li key={o.id} aria-label={o.name} className="flex items-center gap-3 border-b border-border-default px-4 py-3 last:border-b-0">
                <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-text-primary">{o.name}</span>
                <Link to={recordPath(spacePrefix(o), "vault", record.id)} className="text-[13px] font-medium text-[var(--link)] hover:underline">Manage in {o.name}</Link>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

export function ShareSheet({ record, teamFolder, open, onClose, onShare, onShareIn, onUpdate, onRemove }: {
  record: VaultRecord; teamFolder: VaultFolder | null; open: boolean; onClose: () => void;
  onShare: (p: Person, permission: Grant) => Promise<unknown>;
  /** Personal space: share inside one of my organisations. */ onShareIn?: (inOrg: Org, p: Person, permission: Grant) => Promise<unknown>;
  onUpdate: (userId: string, permission: Grant) => Promise<unknown>;
  onRemove: (userId: string) => Promise<unknown>;
}) {
  const { user, org } = useSession();
  const people = usePeople();
  const [tab, setTab] = useState("people");
  const shares = record.sharedWith ?? [];
  const title = record.body?.title ?? "record";
  const run = async (done: string, fn: () => Promise<unknown>) => {
    try { await fn(); toast.success(done); } catch { toast.error("Couldn't save that change. Try again."); }
  };
  const personOf = (userId: string) => people.data?.find((p) => p.id === userId);

  const ownerId = record.ownerId;
  const ownerName = ownerId === user?.id ? (user?.name ?? record.ownerName ?? "You") : record.ownerName;
  const direct = new Set(shares.map((s) => s.userId));
  const viaFolder = (teamFolder?.members ?? []).filter((m) => m.userId !== ownerId && !direct.has(m.userId));
  const total = (ownerId && ownerName ? 1 : 0) + shares.length + viaFolder.length;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" showCloseButton={false} className="data-[side=right]:w-full data-[side=right]:sm:max-w-[480px]">
        <TooltipProvider delayDuration={300}>
          <SheetHeader className="items-start gap-3 py-5">
            <div className="flex min-w-0 items-center gap-3">
              <RecordAvatar title={record.body?.title} size={36} />
              <div className="min-w-0">
                <SheetTitle className="truncate text-[17px] leading-tight">Share {title}</SheetTitle>
                <SheetDescription className="mt-0.5 text-[12.5px] leading-snug text-text-secondary">End-to-end encrypted. The server never sees the password.</SheetDescription>
              </div>
            </div>
            <SheetCloseButton className="-mt-1" />
          </SheetHeader>
          <Tabs value={tab} onValueChange={setTab} className="min-h-0 flex-1 gap-0">
            <div className="shrink-0 px-6 pt-4">
              <TabsList className="w-full">
                <TabsTrigger value="people"><Users />People</TabsTrigger>
                <TabsTrigger value="link"><Link2 />One-time link</TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="people" className="flex min-h-0 flex-col data-[state=inactive]:hidden">
              <SheetBody className="gap-6 pt-5">
                {!org ? <PersonalSharing record={record} onShareIn={onShareIn} /> : <>
                <section aria-label="Add people" className="flex flex-col gap-2.5">
                  <h3 className="text-[13px] font-medium text-text-primary">Add people</h3>
                  <PeoplePicker addLabel="Share" exclude={[...shares.map((s) => s.userId), ...(ownerId ? [ownerId] : [])]}
                    onAdd={(p, perm) => onShare(p, perm).then(() => toast.success(`Shared with ${p.name}`))} />
                  <p className="text-[12px] leading-snug text-text-tertiary">They open it with their own key. "Use only" hides the password in the app but still lets them copy it: a convenience, not a lock.</p>
                </section>

                <section aria-label="People with access" className="flex flex-col gap-2.5">
                  <div className="flex items-baseline justify-between">
                    <h3 className={eyebrow}>People with access</h3>
                    {total > 0 && <span className="font-mono text-[11px] text-text-tertiary">{total}</span>}
                  </div>
                  {total > 0 && <ul aria-label="Shared with" className="overflow-hidden rounded-[12px] border border-border-default bg-card">
                    {ownerId && ownerName && (
                      <AccessRow id={ownerId} name={ownerName} email={personOf(ownerId)?.email} publicKey={personOf(ownerId)?.membershipKey ?? personOf(ownerId)?.publicKey} via="Owner"
                        badge={ownerId === user?.id ? <Chip>You</Chip> : undefined}>
                        <PermissionChip permission="owner" />
                        <span className="size-8" aria-hidden="true" />
                      </AccessRow>
                    )}
                    {shares.map((s) => {
                      const p = personOf(s.userId);
                      return (
                        <AccessRow key={s.userId} id={s.userId} name={s.name} email={p?.email} publicKey={p?.membershipKey ?? p?.publicKey} via="Direct"
                          badge={s.needsAccess ? <Chip tone="orange">Needs access again</Chip> : undefined}>
                          {s.needsAccess && p?.membershipKey && (
                            <Button type="button" variant="outline" size="sm" onClick={() => void run(`Shared with ${s.name} again`, () => onShare(p, s.permission as Grant))}>Share again</Button>
                          )}
                          <PermissionSelect className="w-[104px] sm:w-[118px]" value={s.permission as Grant} label={`Permission for ${s.name}`} onChange={(perm) => void run("Permission changed", () => onUpdate(s.userId, perm))} />
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button type="button" variant="ghost" size="icon" aria-label={`Stop sharing with ${s.name}`} className="hover:bg-red-tint hover:text-red-500"
                                onClick={() => void run(`Stopped sharing with ${s.name}`, () => onRemove(s.userId))}><UserMinus className="size-4" /></Button>
                            </TooltipTrigger>
                            <TooltipContent side="left" sideOffset={6}>Stop sharing</TooltipContent>
                          </Tooltip>
                        </AccessRow>
                      );
                    })}
                    {viaFolder.map((m) => (
                      <AccessRow key={m.userId} id={m.userId} name={m.name} email={m.email} publicKey={m.membershipKey ?? m.publicKey} via={`via ${teamFolder!.name}`}
                        badge={m.userId === user?.id ? <Chip>You</Chip> : undefined}>
                        <PermissionChip permission={m.permission} />
                        <span className="size-8" aria-hidden="true" />
                      </AccessRow>
                    ))}
                  </ul>}
                  {shares.length === 0 && (
                    <div className="flex items-center gap-3 rounded-[12px] border border-dashed border-border-mid px-4 py-3.5">
                      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-well text-text-tertiary"><Users className="size-4" /></span>
                      <span className="min-w-0">
                        <span className="block text-[13.5px] font-medium text-text-primary">Not shared with anyone directly yet.</span>
                        <span className="block text-[12.5px] text-text-secondary">Pick a person above to give them access.</span>
                      </span>
                    </div>
                  )}
                  {teamFolder && (
                    <p className="flex items-start gap-2 text-[12.5px] leading-snug text-text-secondary">
                      <Info className="mt-px size-3.5 shrink-0 text-text-tertiary" />
                      <span>Everyone in {teamFolder.name} can also open it. Manage them from the folder's people.</span>
                    </p>
                  )}
                </section>
                </>}
              </SheetBody>
              <SheetFooter><Button type="button" className="min-w-24" onClick={onClose}>Done</Button></SheetFooter>
            </TabsContent>

            <TabsContent value="link" className="flex min-h-0 flex-col data-[state=inactive]:hidden">
              <OneTimeLinkForm record={record} inline onClose={onClose} />
            </TabsContent>
          </Tabs>
        </TooltipProvider>
      </SheetContent>
    </Sheet>
  );
}
