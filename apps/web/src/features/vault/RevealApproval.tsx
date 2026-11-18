import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useSession } from "@/lib/session";
import { grantErrorText } from "./RecordAgentsSection";
import { checkRequest, revealFieldLabel, useApproveReveal, useDenyReveal, usePersonalVault, useRevealRequests, type RevealCheck, type RevealRequest } from "./reveals";
import { usePinPersonalGateway } from "./useAgentInbox";
import type { VaultRecord } from "./types";

const WHY: Partial<Record<RevealCheck, string>> = {
  unsigned: "This request was not signed by your gateway.",
  unknown_item: "This asks for an item or fields you did not allow.",
  fields: "This asks for an item or fields you did not allow.",
};
const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** A second's tick, for the countdown and to drop an expired request. */
function useClock(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  return now;
}

/**
 * An agent asks to read a value (spec §5.3): a blocking sheet for the oldest request, on every unlocked screen. The item's
 * title comes from my own vault, never from the request; without a valid gateway signature there is no Allow button.
 */
export function RevealApproval() {
  const { user } = useSession();
  const { requests, paused } = useRevealRequests();
  const now = useClock();
  const live = requests.filter((r) => Date.parse(r.expiresAt) > now);
  const r = live[0];
  const vault = usePersonalVault(!!r);
  const [notice, setNotice] = useState<string | null>(null);
  const pausedLine = paused.map((p) => `${p.agentName} was denied three times. Its requests are paused until ${time(p.until)}.`).join(" ");
  useEffect(() => { if (pausedLine) setNotice(pausedLine); }, [pausedLine]);
  if (!user) return null;
  return <>
    {r && vault.data && <RequestSheet key={r.id} r={r} me={user.id} records={vault.data.records} now={now} />}
    {!r && notice && (
      <Dialog open onOpenChange={(o) => { if (!o) setNotice(null); }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Requests paused</DialogTitle><DialogDescription>{notice}</DialogDescription></DialogHeader>
          <DialogFooter><Button onClick={() => setNotice(null)}>OK</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    )}
  </>;
}

function RequestSheet({ r, me, records, now }: { r: RevealRequest; me: string; records: VaultRecord[]; now: number }) {
  const record = records.find((x) => x.id === r.recordId);
  const [check, setCheck] = useState<RevealCheck | null>(null);
  const [pinned, setPinned] = useState(0);
  const approve = useApproveReveal(), deny = useDenyReveal(), pin = usePinPersonalGateway();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { let on = true; void checkRequest(r, me, record).then((c) => { if (on) setCheck(c); }); return () => { on = false; }; }, [r, me, record, pinned]);
  const left = Math.max(0, Math.ceil((Date.parse(r.expiresAt) - now) / 1000));
  const busy = approve.isPending || deny.isPending;
  const title = record?.body?.title;
  const run = (f: () => Promise<unknown>) => { setError(null); f().catch((e: unknown) => setError(e instanceof Error ? e.message : "Something went wrong. Try again.")); };
  return (
    <Dialog open onOpenChange={() => { /* answered with a button, or it expires */ }}>
      <DialogContent showCloseButton={false} aria-label="An agent is asking for a secret">
        <DialogHeader>
          <DialogTitle>An agent is asking for a secret</DialogTitle>
          <DialogDescription>{r.agentName}{r.app ? ` through ${r.app}` : ""} asks to read {title ? <strong>{title}</strong> : "an item"}.</DialogDescription>
        </DialogHeader>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-[13.5px]">
          <dt className="text-text-secondary">Fields</dt>
          <dd>{r.fields.map((f) => (record?.body ? revealFieldLabel(record.body, f) : f)).join(", ")}</dd>
          <dt className="text-text-secondary">Asked at</dt><dd>{time(r.createdAt)}</dd>
          <dt className="text-text-secondary">Expires in</dt><dd>{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</dd>
        </dl>
        <figure className="rounded-[10px] border border-border-default bg-card px-3 py-2">
          <figcaption className="text-[12px] text-text-secondary">Written by the agent. It may not be true.</figcaption>
          <blockquote className="mt-1 text-[13.5px] break-words whitespace-pre-wrap text-text-primary">{r.reason}</blockquote>
        </figure>
        {check === "unpinned" && (
          <div className="flex flex-col gap-1.5">
            <p className="text-[13.5px] font-medium text-text-primary">Verify your gateway on this device first</p>
            {pin.error && <p role="alert" className="text-[13px] text-red-500">{grantErrorText(pin.error)}</p>}
            <div><Button size="sm" variant="outline" disabled={pin.isPending} onClick={() => pin.mutate(undefined, { onSuccess: () => setPinned((n) => n + 1) })}>Verify gateway</Button></div>
          </div>
        )}
        {check && WHY[check] && <p role="alert" className="text-[13.5px] text-red-500">{WHY[check]}</p>}
        {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => run(() => deny.mutateAsync(r))}>Deny</Button>
          {check === "ok" && <Button disabled={busy} onClick={() => run(() => approve.mutateAsync({ r, record }))}>Allow once</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
