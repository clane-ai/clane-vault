import { useEffect, useRef, useState } from "react";
import { Check, ChevronRight, KeyRound, MoreHorizontal, Paperclip, Plus, UserRound, Users, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { copySecret } from "@/lib/clipboard";
import { cn } from "@/lib/utils";
import { REASON_LABEL, type AttentionReason } from "./attention";
import type { VaultView } from "./filter";
import { FolderGlyph } from "./FolderGlyph";
import { AvatarStack, Chip } from "./people";
import { ReasonChips } from "./ReasonChips";
import { RecordAvatar } from "./RecordAvatar";
import { recordSubtitle } from "./recordKinds";
import { canFileInto, glyphFor, PERMISSION_LABEL, type VaultFolder, type VaultRecord } from "./types";

// Geometry and states: docs/design/2026-10-10-vault-polish.md §2–§4, §7.
/** The 1 px line that ties a folder's records to it, hanging from the folder glyph's centre. */
const GUIDE = "before:absolute before:inset-y-0 before:left-[45px] before:w-px before:bg-border-default max-[760px]:before:left-[43px]";
const INSET = "pl-[58px] max-[760px]:pl-[54px]";

/** A hover copy button on a record row (same behaviour as CopyButton: clipboard clears, toast, check for 1.5 s). */
function RowCopy({ value, label, title, icon: Icon }: { value: string; label: string; title: string; icon: LucideIcon }) {
  const [done, setDone] = useState(false);
  const t = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(t.current), []);
  return (
    <button type="button" aria-label={label} title={title}
      onClick={async (e) => {
        e.stopPropagation();
        await copySecret(value);
        toast.success("Copied. Clipboard clears in 30 s");
        setDone(true); clearTimeout(t.current); t.current = setTimeout(() => setDone(false), 1500);
      }}
      className={cn("grid size-7 shrink-0 place-items-center rounded-[7px] transition-colors duration-150 hover:bg-well focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40",
        done ? "text-green-600" : "text-text-secondary hover:text-text-primary")}>
      {done ? <Check className="size-3.5" /> : <Icon className="size-3.5" />}
    </button>
  );
}

function Row({ r, selected, inset, onSelect, reasons, view, folder, crumb }: {
  r: VaultRecord; selected: boolean; inset?: boolean; onSelect: (id: string) => void; reasons?: AttentionReason[]; view: VaultView;
  /** The record's folder (flat lists show it as a crumb). */ folder?: VaultFolder | null; crumb?: boolean;
}) {
  const b = r.body;
  // A sensible second line per type (username, host, SSID, a card's last four digits…); never a secret.
  const sub = recordSubtitle(b);
  const trash = view === "trash" || r.deleted;
  const attention = !trash && !!reasons?.length;
  const shared = r.sharedBy ? `Shared by ${r.sharedBy}` : r.sharedWith?.length ? `Shared with ${r.sharedWith.length} ${r.sharedWith.length === 1 ? "person" : "people"}` : null;
  // Hover copy: username and password of any type that has them (logins, servers, Wi-Fi…), never in the trash.
  // "Use only" records keep the record panel's Copy, not a list shortcut.
  const copyUser = !trash && b?.username ? b.username : null;
  const copyPass = !trash && b?.password && r.permission !== "use" ? b.password : null;
  const g = crumb && folder ? glyphFor(folder) : null;
  return (
    <div data-testid="record-row" data-selected={selected || undefined}
      className={cn("group/row relative flex min-h-10 items-center border-b border-border-subtle pr-2 transition-colors duration-150 max-[760px]:min-h-11 pointer-coarse:min-h-11",
        "has-[[data-row-main]:focus-visible]:ring-2 has-[[data-row-main]:focus-visible]:ring-blue-500/40 has-[[data-row-main]:focus-visible]:ring-inset",
        inset ? cn(INSET, GUIDE) : "pl-3",
        selected ? "bg-blue-tint" : "hover:bg-app has-[[data-row-main]:focus-visible]:bg-app")}>
      {selected && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-blue-500" />}
      <button type="button" data-row-main onClick={() => onSelect(r.id)} aria-current={selected ? "true" : undefined}
        className="flex min-w-0 flex-1 items-center gap-2.5 self-stretch py-1 text-left focus-visible:outline-none">
        <RecordAvatar title={b?.title} kind={b?.type} size={22} />
        <span className="flex min-w-0 flex-1 flex-col justify-center">
          <span className="truncate text-[13.5px] leading-[17px] font-medium text-text-primary max-[760px]:text-[14px] max-[760px]:leading-[18px]">{b?.title ?? "Can't open this record"}</span>
          {sub && <span className="truncate text-[12px] leading-[15px] text-text-secondary max-[760px]:text-[12.5px] max-[760px]:leading-4">{sub}</span>}
        </span>
        <span className="flex shrink-0 items-center gap-1.5 empty:hidden">
          {view === "attention" && reasons?.length ? <ReasonChips reasons={reasons} />
            : attention && <span className="flex size-3.5 items-center justify-center" title={reasons!.map((x) => REASON_LABEL[x]).join(", ")}>
                <span aria-hidden="true" className="size-1.5 rounded-full bg-amber-500" /><span className="sr-only">Needs attention</span>
              </span>}
          {shared && <span title={shared} className="flex"><Users aria-hidden="true" className="size-3.5 text-text-secondary" /><span className="sr-only">{shared}</span></span>}
          {/* Files on the record: a count from the sync metadata (nothing to decrypt). */}
          {!!r.attachments?.length && <span title={`${r.attachments.length} ${r.attachments.length === 1 ? "file" : "files"}`} data-testid="file-count" className="flex items-center gap-0.5 font-mono text-[11px] text-text-secondary">
            <Paperclip aria-hidden="true" className="size-3.5" />{r.attachments.length}<span className="sr-only"> {r.attachments.length === 1 ? "file" : "files"}</span>
          </span>}
          {view === "shared" && <Chip>{PERMISSION_LABEL[r.permission]}</Chip>}
          {g && <span className="flex max-w-[160px] items-center gap-1 text-[12px] text-text-secondary max-[560px]:hidden">
            <FolderGlyph kind={g.kind} locked={g.locked} size={16} /><span className="truncate">{folder!.name}</span>
          </span>}
        </span>
      </button>
      {/* Both slots are always reserved (outside the Trash), so the meta of every row lines up in one column. */}
      {!trash && (
        <span className="invisible ml-1.5 flex shrink-0 items-center gap-0.5 group-focus-within/row:visible group-hover/row:visible max-[760px]:hidden pointer-coarse:hidden">
          {/* Not "Copy username"/"Copy password": the open record's panel has those, and the two must not be confused. */}
          {copyUser ? <RowCopy value={copyUser} label="Copy this record's username" title="Copy username" icon={UserRound} /> : <span aria-hidden="true" className="size-7" />}
          {copyPass ? <RowCopy value={copyPass} label="Copy this record's password" title="Copy password" icon={KeyRound} /> : <span aria-hidden="true" className="size-7" />}
        </span>
      )}
    </div>
  );
}

function ListCard({ children }: { children: React.ReactNode }) {
  // -mb-px tucks the last row's divider under the card border: no double line at the bottom.
  return (
    <div className="overflow-hidden rounded-[12px] border border-border-default bg-card shadow-[var(--shadow-card)]">
      <div className="-mb-px">{children}</div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, line, action }: { icon: LucideIcon; title: string; line: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <span className="mb-4 grid size-12 place-items-center rounded-full bg-blue-tint text-blue-500"><Icon className="size-[22px]" /></span>
      <p className="font-display text-[17px] font-semibold tracking-[-0.02em] text-text-primary">{title}</p>
      <p className="mt-1 max-w-[340px] text-[13.5px] leading-relaxed text-text-secondary">{line}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

/** Renders a folder row's Options menu around `trigger` (the row's … button); `open` is controlled so a right-click opens it too. */
export type FolderMenu = (f: VaultFolder, trigger: React.ReactNode, open: boolean, onOpenChange: (o: boolean) => void) => React.ReactNode;

export function RecordList({ groups, flat, mode, selectedId, onSelect, folderMenu, currentFolderId, onOpenFolder, onCreate, onNewRecord, empty: empty_, reasons, view = "vault", folderOf, noFolderLabel = "No folder" }: {
  groups: { folder: VaultFolder | null; records: VaultRecord[] }[]; flat: VaultRecord[]; mode: "folders" | "flat"; selectedId: string | null; onSelect: (id: string) => void;
  /** Each folder row's Options menu (none offline). */ folderMenu?: FolderMenu;
  /** The folder the Options in the list header act on: highlighted. */ currentFolderId?: string | null;
  /** A folder row was opened (its id; null for "No folder"), or the current one was closed (null). */ onOpenFolder?: (id: string | null) => void;
  /** Primary action in the empty state. */ onCreate?: () => void;
  /** "New record" in an open, empty folder (none offline). */ onNewRecord?: (folderId: string) => void;
  /** Replaces the default empty state (e.g. for the trash). */ empty?: React.ReactNode;
  /** Needs-attention reasons: a dot on each row, the reason chips in the Needs-attention list. */ reasons?: Map<string, AttentionReason[]>;
  /** The list shown: decides the permission chip (Shared with me), chips vs dot (Needs attention), no copy in the Trash. */ view?: VaultView;
  /** A record's folder, for the crumb in flat lists. */ folderOf?: (id: string | null) => VaultFolder | null;
  /** The group of records outside any folder here: "No folder" (Personal), "Shared directly" (an organisation). */ noFolderLabel?: string;
}) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [menuFor, setMenuFor] = useState<string | null>(null);
  const empty = mode === "flat" ? flat.length === 0 : groups.every((g) => g.records.length === 0) && groups.length === 0;
  if (empty) return (
    <ListCard>
      {empty_ ?? <EmptyState icon={KeyRound} title="No records yet" line="Use + New to add your first login, or import from Keeper."
        action={onCreate && <Button onClick={onCreate}><Plus className="size-4" />Add a login</Button>} />}
    </ListCard>
  );
  if (mode === "flat") return (
    <ListCard>
      {flat.map((r) => <Row key={r.id} r={r} view={view} selected={r.id === selectedId} onSelect={onSelect} reasons={reasons?.get(r.id)} crumb folder={folderOf?.(r.folderId)} />)}
    </ListCard>
  );
  return (
    <ListCard>
      {groups.map((g) => {
        const key = g.folder?.id ?? "none";
        const isOpen = open.has(key);
        const n = g.records.length;
        const current = !!g.folder && g.folder.id === currentFolderId;
        const glyph = glyphFor(g.folder);
        const members = g.folder?.kind === "team" ? g.folder.members ?? [] : [];
        return (
          <div key={key}>
            <div onContextMenu={g.folder && folderMenu ? (e) => { e.preventDefault(); setMenuFor(key); } : undefined} data-current={current || undefined} data-testid="folder-row"
              className={cn("group/folder relative flex min-h-11 items-center border-b border-border-default pr-2 transition-colors duration-150 max-[760px]:min-h-12 pointer-coarse:min-h-12",
                "[--badge-ring:var(--surface-card)] hover:bg-app hover:[--badge-ring:var(--bg-app)] has-[:focus-visible]:bg-app has-[:focus-visible]:[--badge-ring:var(--bg-app)]",
                "has-[[data-folder-main]:focus-visible]:ring-2 has-[[data-folder-main]:focus-visible]:ring-blue-500/40 has-[[data-folder-main]:focus-visible]:ring-inset",
                current && "bg-app [--badge-ring:var(--bg-app)]")}>
            {current && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-blue-500" />}
            <button type="button" data-folder-main aria-expanded={isOpen} onClick={() => {
                setOpen((s) => { const x = new Set(s); x.has(key) ? x.delete(key) : x.add(key); return x; });
                const id = g.folder?.id ?? null;
                if (!isOpen) onOpenFolder?.(id); else if (current) onOpenFolder?.(null);
              }}
              className="flex min-w-0 flex-1 items-center gap-2 self-stretch pl-3 text-left focus-visible:outline-none max-[760px]:gap-1.5">
              <ChevronRight aria-hidden="true" className={cn("size-4 shrink-0 text-text-tertiary transition-transform duration-150 group-hover/folder:text-text-secondary motion-reduce:transition-none", isOpen && "rotate-90")} />
              <span className="flex min-w-0 flex-1 items-center gap-2.5">
                <FolderGlyph kind={glyph.kind} locked={glyph.locked} open={isOpen} />
                <span className="min-w-0 truncate text-[13.5px] leading-5 font-medium text-text-primary max-[760px]:text-[14px]">
                  {g.folder?.name ?? noFolderLabel}{g.folder?.kind === "team" && <span className="sr-only">, shared folder</span>}
                </span>
              </span>
              {members.length > 0 && (
                <span className="flex shrink-0 items-center max-[760px]:hidden" title={members.map((m) => m.name).join(", ")}>
                  <AvatarStack people={members} max={3} ringClassName={current ? "ring-app" : "ring-card group-hover/folder:ring-app"} />
                  <span className="sr-only">{members.length} people</span>
                </span>
              )}
              <span aria-hidden="true" className="min-w-4 shrink-0 text-right font-mono text-[11px] text-text-secondary tabular-nums">{n}</span>
              <span className="sr-only">{n} {n === 1 ? "record" : "records"}</span>
            </button>
            {g.folder && folderMenu ? folderMenu(g.folder,
              <button type="button" aria-label={`Options for ${g.folder.name}`} title="Options" className="ml-2 grid size-7 shrink-0 place-items-center rounded-[7px] text-text-secondary opacity-0 transition-opacity duration-150 group-hover/folder:opacity-100 hover:bg-well hover:text-text-primary focus-visible:opacity-100 aria-expanded:bg-well aria-expanded:opacity-100 pointer-coarse:opacity-100 max-[760px]:opacity-100"><MoreHorizontal className="size-4" /></button>,
              menuFor === key, (o) => setMenuFor(o ? key : null))
              : <span className="ml-2 size-7 shrink-0" aria-hidden="true" />}
            </div>
            {isOpen && g.records.map((r) => <Row key={r.id} r={r} view={view} inset selected={r.id === selectedId} onSelect={onSelect} reasons={reasons?.get(r.id)} />)}
            {isOpen && n === 0 && g.folder && (
              <div className={cn("relative flex min-h-9 items-center gap-1 border-b border-border-subtle pr-2 text-[12.5px] text-text-secondary", INSET, GUIDE)}>
                No records here yet
                {onNewRecord && canFileInto(g.folder) && <>
                  <span aria-hidden="true">·</span>
                  <button type="button" onClick={() => onNewRecord(g.folder!.id)} className="rounded-[4px] font-medium text-blue-ink hover:underline">New record</button>
                </>}
              </div>
            )}
          </div>
        );
      })}
    </ListCard>
  );
}
