import { useSession } from "@/lib/session";
import { relativeTime } from "@/lib/time";
import { Chip, PersonAvatar } from "./people";
import { PERMISSION_LABEL, type VaultFolder, type VaultRecord } from "./types";
import { useRecordActivity, type ActivityEvent } from "./useVault";

const heading = "font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

function Line({ id, name, detail, chip }: { id: string; name: string; detail?: string; chip?: React.ReactNode }) {
  return (
    <li className="flex items-center gap-2.5 py-1.5">
      <PersonAvatar id={id} name={name} size={24} />
      <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{name}{detail && <span className="text-text-secondary"> · {detail}</span>}</span>
      {chip}
    </li>
  );
}

/** "Who can open this": the owner, team folder members (via the folder) and direct shares. */
export function WhoCanOpen({ record, folder }: { record: VaultRecord; folder: VaultFolder | null }) {
  const { user } = useSession();
  const me = user?.id;
  const team = folder?.kind === "team" ? folder : null;
  const ownerName = record.ownerId === me ? "You" : record.ownerName ?? record.sharedBy ?? "Owner";
  const members = (team?.members ?? []).filter((m) => m.userId !== record.ownerId);
  const direct = record.sharedWith ?? [];
  return (
    <section className="flex flex-col gap-2" aria-label="Who can open this">
      <h3 className={heading}>Who can open this</h3>
      <ul className="rounded-[12px] border border-border-default px-3 py-1.5">
        {record.ownerId && <Line id={record.ownerId} name={ownerName} chip={<Chip tone="blue">Owner</Chip>} />}
        {members.map((m) => <Line key={`f-${m.userId}`} id={m.userId} name={m.userId === me ? "You" : m.name} detail={`via ${team!.name}`} chip={<Chip>{PERMISSION_LABEL[m.permission === "owner" ? "edit" : m.permission]}</Chip>} />)}
        {direct.map((s) => <Line key={`d-${s.userId}`} id={s.userId} name={s.name} detail="shared directly" chip={<Chip>{PERMISSION_LABEL[s.permission]}</Chip>} />)}
        {record.sharedBy && me && <Line id={me} name="You" detail={`shared by ${record.sharedBy}`} chip={<Chip>{PERMISSION_LABEL[record.permission]}</Chip>} />}
      </ul>
    </section>
  );
}

const VERB: Record<string, (e: ActivityEvent) => string> = {
  "record.create": () => "created it",
  "record.update": () => "edited it",
  "record.trash": () => "moved it to the trash",
  "record.restore": () => "restored it",
  "record.move": () => "moved it to another folder",
  "record.share": (e) => `shared it with ${e.target ?? "someone"}`,
  "record.unshare": (e) => `stopped sharing with ${e.target ?? "someone"}`,
  "record.permission": (e) => `changed ${e.target ?? "someone"}'s permission`,
  "attachment.add": () => "added a file",
  "attachment.remove": () => "removed a file",
  "attachment.download": () => "downloaded a file",
  "attachment.upload_abandoned": () => "left an upload unfinished",
  "link.create": () => "created a one-time link",
  "link.revoke": () => "revoked a one-time link",
};

export function RecordActivity({ record }: { record: VaultRecord }) {
  // Files don't change the revision, but they move updatedAt: either refreshes the list.
  const q = useRecordActivity(record.id, `${record.revision}:${record.updatedAt}`);
  const events = q.data ?? [];
  return (
    <section className="flex flex-col gap-2" aria-label="Activity">
      <h3 className={heading}>Activity</h3>
      {q.isLoading ? <p className="text-[13px] text-text-tertiary">Loading…</p>
        : q.error ? <p className="text-[13px] text-text-tertiary">Couldn't load activity.</p>
        : events.length === 0 ? <p className="text-[13px] text-text-tertiary">No activity yet.</p>
        : (
          <ol className="flex flex-col gap-1.5">
            {events.slice(0, 20).map((e, i) => (
              <li key={i} className="flex items-baseline gap-2 text-[13px]">
                <span className="min-w-0 flex-1 text-text-primary"><span className="font-medium">{e.actor ?? "Someone"}</span> <span className="text-text-secondary">{(VERB[e.action] ?? (() => e.action))(e)}</span></span>
                <span className="shrink-0 font-mono text-[11px] text-text-tertiary" title={new Date(e.at).toLocaleString()}>{relativeTime(e.at)}</span>
              </li>
            ))}
          </ol>
        )}
    </section>
  );
}
