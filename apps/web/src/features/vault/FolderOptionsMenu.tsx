import { FileLock2, FolderInput, FolderPlus, Pencil, Trash2, Users } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { FolderGlyph } from "./FolderGlyph";
import { ItemHint, type NewKind } from "./NewMenu";
import { canFileInto, glyphFor, type VaultFolder, type VaultRecord } from "./types";

/** Whether I may delete (and rename) a folder: my private folders, and team folders I own. */
export const ownsFolder = (f: VaultFolder) => f.kind === "private" || f.myPermission === "owner";

/** Why Move To can't act on `record` (null when it can). Folders themselves can't be moved: they don't nest. */
export function moveBlocked(record: VaultRecord | null): string | null {
  if (!record) return "Select a record to move it. Folders can't be moved.";
  if (record.deleted) return "Restore the record before moving it.";
  if (record.permission !== "owner") return "Only the record's owner can move it.";
  return null;
}

const subTrigger = "gap-2.5 rounded-[9px] px-2.5 py-2 text-[13.5px] text-text-primary focus:bg-app focus:text-text-primary data-[state=open]:bg-app data-[state=open]:text-text-primary pointer-coarse:min-h-11 [&_svg]:text-text-tertiary";
const subContent = "min-w-[220px] max-w-[300px] rounded-[12px] border border-border-default p-1.5 shadow-[0_18px_40px_-16px_rgba(10,18,36,.36)] ring-0";

/**
 * Keeper's folder "Options": acts on `folder` (the open folder in the list header, or the row's own folder; null: no
 * folder open, the vault itself). Move To moves the selected record (owner only); Delete is for the folder's owner.
 */
export function FolderOptionsMenu({ folder, record, folders, team, trigger, open, onOpenChange, onNew, onMove, onDelete, onRename, onManage }: {
  folder: VaultFolder | null; record: VaultRecord | null; folders: VaultFolder[];
  /**
   * The space: true in an organisation (shared folders only; its records don't go back to "No folder"), false in
   * Personal (private folders; shared folders belong to an organisation).
   */ team: boolean;
  trigger: React.ReactNode; open?: boolean; onOpenChange?: (o: boolean) => void;
  onNew: (k: NewKind, folderId: string | null) => void; onMove: (r: VaultRecord, folderId: string | null) => void;
  onDelete: (f: VaultFolder) => void; onRename?: (f: VaultFolder) => void; onManage?: (f: VaultFolder) => void;
}) {
  const id = folder?.id ?? "vault";
  const owner = !!folder && ownsFolder(folder);
  const blocked = moveBlocked(record);
  const targets = record ? folders.filter((f) => canFileInto(f) && f.id !== record.folderId) : [];
  const deleteHint = !folder ? "Open a folder to delete it." : owner ? null : "Only the folder's owner can delete it.";
  return (
    <DropdownMenu open={open} onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={6} className="w-[248px]">
        {/* One line: what the options act on (the folder, or the vault itself). */}
        <DropdownMenuLabel className="flex items-center gap-2 px-2.5 py-1.5 text-[13px] font-medium text-text-primary">
          <FolderGlyph {...glyphFor(folder)} size={16} /><span className="min-w-0 truncate">{folder ? folder.name : "My vault"}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => onNew("record", folder?.id ?? null)}><FileLock2 />New Record</DropdownMenuItem>
        {!team && <DropdownMenuItem onSelect={() => onNew("folder", folder?.id ?? null)}><FolderPlus />New Folder</DropdownMenuItem>}
        <DropdownMenuItem disabled={!team} aria-label="New Shared Folder" aria-describedby={team ? undefined : `${id}-team-hint`} onSelect={() => onNew("team", folder?.id ?? null)}>
          <Users /><span>New Shared Folder{!team && <ItemHint id={`${id}-team-hint`}>Shared folders belong to an organisation: switch to one</ItemHint>}</span>
        </DropdownMenuItem>
        {blocked || !record ? (
          <DropdownMenuItem disabled aria-label="Move To" aria-describedby={`${id}-move-hint`}>
            <FolderInput /><span className="whitespace-normal">Move To<ItemHint id={`${id}-move-hint`}>{blocked}</ItemHint></span>
          </DropdownMenuItem>
        ) : (
          <DropdownMenuSub>
            <DropdownMenuSubTrigger className={subTrigger}><FolderInput />Move To</DropdownMenuSubTrigger>
            <DropdownMenuSubContent className={subContent} sideOffset={6}>
              <DropdownMenuLabel className="truncate px-2.5 pt-1 pb-1.5 text-[12.5px] font-normal text-text-secondary">Move “{record.body?.title ?? "record"}” to</DropdownMenuLabel>
              {!team && record.folderId !== null && <DropdownMenuItem onSelect={() => onMove(record, null)}><FolderGlyph kind="none" size={16} />No folder</DropdownMenuItem>}
              {targets.map((f) => (
                <DropdownMenuItem key={f.id} onSelect={() => onMove(record, f.id)}>
                  <FolderGlyph {...glyphFor(f)} size={16} /><span className="truncate">{f.name}</span>
                </DropdownMenuItem>
              ))}
              {(team || record.folderId === null) && targets.length === 0 && <p className="px-2.5 py-2 text-[12.5px] text-text-tertiary">No folders to move it to yet.</p>}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
        )}
        {folder && (onRename || onManage) && (owner || folder.kind === "team") && <DropdownMenuSeparator />}
        {folder?.kind === "team" && onManage && <DropdownMenuItem onSelect={() => onManage(folder)}><Users />{owner ? "Manage people" : "People"}</DropdownMenuItem>}
        {folder && owner && onRename && <DropdownMenuItem onSelect={() => onRename(folder)}><Pencil />Rename</DropdownMenuItem>}
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" disabled={!!deleteHint} aria-label="Delete" aria-describedby={deleteHint ? `${id}-delete-hint` : undefined} onSelect={() => folder && owner && onDelete(folder)}>
          <Trash2 /><span className="whitespace-normal">Delete{deleteHint && <ItemHint id={`${id}-delete-hint`}>{deleteHint}</ItemHint>}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
