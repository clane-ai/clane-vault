import { Dices, FileLock2, FileUp, FolderPlus, Plus, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

/** `record` opens the New record dialog (Login or Secure note is picked there); `team` is a shared (team) folder. */
export type NewKind = "record" | "folder" | "team" | "generate" | "import";

export const menuTitle = "px-2.5 pt-1.5 pb-1 font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase";

/** A short reason under a disabled menu item (disabled items can't show a tooltip: they take no pointer or focus). */
export function ItemHint({ id, children }: { id: string; children: React.ReactNode }) {
  return <span id={id} className="block text-[11.5px] leading-snug whitespace-normal text-text-tertiary">{children}</span>;
}

/**
 * The "+ New" menu ("Create New") for the space: in an organisation (`team`) shared folders and records in them; in
 * Personal private folders and records, and imports. `recordHint`: why Record is unavailable (an organisation with no
 * shared folder I can add to yet).
 */
export function NewMenu({ onNew, team = true, compact = false, recordHint }: { onNew: (k: NewKind) => void; team?: boolean; /** A round + (the sidebar's icon rail). */ compact?: boolean; recordHint?: string }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button className={cn("h-10 w-full rounded-[10px] bg-orange-500 font-semibold text-navy-900 shadow-[var(--shadow-card)] hover:bg-orange-500/90 aria-expanded:bg-orange-500/90 max-[760px]:size-10 max-[760px]:rounded-full max-[760px]:p-0",
          compact && "size-10 rounded-full p-0")} aria-label="New" title={compact ? "New" : undefined}>
          <Plus className="size-4" strokeWidth={2.4} /><span className={cn("max-[760px]:hidden", compact && "hidden")}>New</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side={compact ? "right" : "bottom"} sideOffset={compact ? 10 : 6} className="w-[236px] [&_[role=menuitem]]:whitespace-nowrap">
        <DropdownMenuLabel className={menuTitle}>Create New</DropdownMenuLabel>
        <DropdownMenuItem disabled={!!recordHint} aria-label="Record" aria-describedby={recordHint ? "new-record-hint" : undefined} onSelect={() => onNew("record")}>
          <FileLock2 /><span>Record{recordHint && <ItemHint id="new-record-hint">{recordHint}</ItemHint>}</span>
        </DropdownMenuItem>
        {!team && <DropdownMenuItem onSelect={() => onNew("folder")}><FolderPlus />Folder</DropdownMenuItem>}
        <DropdownMenuItem disabled={!team} aria-label="Shared Folder" aria-describedby={team ? undefined : "new-team-hint"} onSelect={() => onNew("team")}>
          <Users /><span>Shared Folder{!team && <ItemHint id="new-team-hint">Shared folders belong to an organisation: switch to one</ItemHint>}</span>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onNew("generate")}><Dices />Generate Password</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled={team} aria-label="Import" aria-describedby={team ? "new-import-hint" : undefined} onSelect={() => onNew("import")}>
          <FileUp /><span>Import{team && <ItemHint id="new-import-hint">Imports go to your Personal vault</ItemHint>}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
