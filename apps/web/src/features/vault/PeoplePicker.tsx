import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Mail, Search, ShieldCheck, UserPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { KeyChangedError, pinKey, pinStatus } from "@/lib/orgKeys";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope, useScopeOrg } from "@/lib/scope";
import { Fingerprint, PermissionSelect, PersonAvatar } from "./people";
import type { Grant, Person } from "./types";
import { usePeople } from "./useVault";

/** Pending invites, visible to admins only: shown as "Invited" and not pickable until they register (ruling R1). */
function useInvited() {
  const org = useScopeOrg();
  const scope = useScope();
  const oapi = useOrgApi();
  return useQuery({
    queryKey: ["admin-people", scope], enabled: !!org && org.role !== "member", staleTime: 30_000,
    queryFn: () => oapi.get<{ invites: { id: string; email: string }[] }>("/admin/people"),
  });
}

/** Pick an active person and a permission, then add them. */
export function PeoplePicker({ exclude, onAdd, addLabel = "Add" }: { exclude: string[]; onAdd: (p: Person, permission: Grant) => Promise<unknown>; addLabel?: string }) {
  const { user } = useSession();
  const org = useScopeOrg();
  const people = usePeople();
  const invited = useInvited();
  const [personId, setPersonId] = useState("");
  const [permission, setPermission] = useState<Grant>("view");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [, setAccepted] = useState(0);
  const options = (people.data ?? []).filter((p) => p.id !== user?.id && !exclude.includes(p.id));
  const pending = (invited.data?.invites ?? []).filter((i) => !(people.data ?? []).some((p) => p.email === i.email));

  async function add() {
    const p = options.find((x) => x.id === personId);
    if (!p) return setError("Pick a person first.");
    setBusy(true); setError(null);
    try { await onAdd(p, permission); setPersonId(""); }
    catch (e) { setError(e instanceof KeyChangedError ? `${p.name}'s key changed. Check the new fingerprint with them first.` : `Couldn't add ${p.name}. Try again.`); }
    finally { setBusy(false); }
  }

  const selected = options.find((x) => x.id === personId);
  // The key sealing will use (membership key, else account key) and how it compares with this device's pin.
  const sealKey = selected && (selected.membershipKey ?? selected.publicKey);
  const pin = selected && user && org ? pinStatus(user.id, org.id, selected.id, selected.membershipKey, selected.publicKey) : null;
  const previous = pin?.previous?.replace(/^acct:/, "");
  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={personId} onValueChange={(v) => { setPersonId(v); setError(null); }}>
          <SelectTrigger aria-label="Person" className="h-10 min-w-0 flex-[1_1_160px] pl-2.5">
            <SelectValue placeholder={<span className="flex items-center gap-2 pl-0.5"><Search className="size-4 text-text-tertiary" />{people.isLoading ? "Loading people…" : options.length ? "Choose a person" : "No one else to add"}</span>}>
              {selected && <span className="flex min-w-0 items-center gap-2"><PersonAvatar id={selected.id} name={selected.name} size={24} /><span className="truncate">{selected.name}</span></span>}
            </SelectValue>
          </SelectTrigger>
          <SelectContent align="start" className="max-w-[min(420px,calc(100vw-32px))]">
            {options.map((p) => (
              <SelectItem key={p.id} value={p.id} textValue={p.name} className="py-1.5">
                <PersonAvatar id={p.id} name={p.name} />
                <span className="flex min-w-0 flex-col leading-tight"><span className="truncate text-text-primary">{p.name}</span><span className="truncate text-[12px] font-normal text-text-tertiary">{p.email}</span></span>
              </SelectItem>
            ))}
            {pending.map((i) => (
              <SelectItem key={i.id} value={`invite:${i.id}`} disabled textValue={i.email} className="py-1.5">
                <span className="grid size-8 shrink-0 place-items-center rounded-full border border-dashed border-border-strong text-text-tertiary"><Mail className="size-3.5" /></span>
                <span className="flex min-w-0 flex-col leading-tight"><span className="truncate">{i.email}</span><span className="text-[11px] text-text-tertiary">Invited, not signed up yet</span></span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="flex flex-[1_0_auto] items-center gap-2 sm:flex-none">
          <PermissionSelect value={permission} onChange={setPermission} label="Permission for new person" className="h-10 flex-1 sm:w-[124px] sm:flex-none" />
          <Button type="button" className="h-10 min-w-[84px]" disabled={busy || !personId || pin?.status === "changed"} onClick={() => void add()}><UserPlus className="size-4" />{addLabel}</Button>
        </div>
      </div>
      {selected && pin?.status === "changed" ? (
        <div role="alert" className="flex flex-col gap-2 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2 text-[12.5px] leading-snug text-text-secondary" aria-label="Selected person's key">
          <p className="flex items-start gap-2">
            <AlertTriangle className="mt-px size-3.5 shrink-0 text-orange-ink" />
            <span>{selected.name}'s key changed since you last shared with them on this device: was <Fingerprint publicKey={previous} className="text-text-primary" />, now <Fingerprint publicKey={sealKey} className="text-text-primary" />. That's expected after an account reset, but a compromised server could do it too. Compare the new fingerprint with them (call or in person) before you continue.</span>
          </p>
          <Button type="button" variant="outline" size="sm" className="self-end" onClick={() => { pinKey(user!.id, org!.id, selected.id, selected.membershipKey, selected.publicKey); setError(null); setAccepted((n) => n + 1); }}>I've checked it with them</Button>
        </div>
      ) : selected && (
        <p className="flex items-start gap-2 rounded-[10px] border border-border-default bg-app px-3 py-2 text-[12.5px] leading-snug text-text-secondary" aria-label="Selected person's key">
          <ShieldCheck className="mt-px size-3.5 shrink-0 text-green-600" />
          <span>{selected.name}'s key fingerprint <Fingerprint publicKey={sealKey} className="text-text-primary" />.{pin?.status === "new" ? " First share with them from this device: check it with them if you share anything sensitive." : " Same key as last time."}</span>
        </p>
      )}
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
    </div>
  );
}
