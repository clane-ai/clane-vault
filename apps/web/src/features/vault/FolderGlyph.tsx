import { FolderLock, Inbox } from "lucide-react";
import { cn } from "@/lib/utils";
import type { FolderGlyphKind } from "./types";

// lucide Folder / FolderOpen paths (24-unit grid), drawn here so they can take a tint fill and the people badge.
const FOLDER = "M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z";
const FOLDER_OPEN = "m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2";

/**
 * A folder's icon (docs/design/2026-10-10-vault-polish.md §2): private (blue), shared (purple, with a people badge),
 * shared but its key isn't here yet (a lock), or "No folder" (an inbox). Decorative: the name next to it says the rest.
 * The badge's knockout ring takes `--badge-ring` from the row, so it always matches the surface underneath.
 */
export function FolderGlyph({ kind, open = false, locked = false, size = 20, className }: {
  kind: FolderGlyphKind; open?: boolean; locked?: boolean; size?: 16 | 20; className?: string;
}) {
  const box = size === 16 ? "size-4" : "size-5";
  const common = { "aria-hidden": true, "data-testid": "folder-glyph", "data-kind": kind, "data-open": open || undefined, "data-locked": locked || undefined } as const;
  if (kind === "none") {
    return <span {...common} className={cn("grid shrink-0 place-items-center text-text-secondary", box, className)}>
      <Inbox className={size === 16 ? "size-[14px]" : "size-[18px]"} strokeWidth={1.75} />
    </span>;
  }
  if (locked) return <FolderLock {...common} className={cn("shrink-0 text-text-secondary", box, className)} strokeWidth={1.75} />;
  const team = kind === "team";
  return (
    <svg {...common} viewBox="0 0 24 24" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round"
      className={cn("shrink-0", box, team ? "fill-purple-tint stroke-purple-ink" : "fill-blue-tint stroke-blue-500", className)}>
      <path d={open ? FOLDER_OPEN : FOLDER} />
      {team && (
        <g data-testid="people-badge" stroke="none">
          {/* Knockout ring in the row's colour, so the badge "cuts" the folder outline. */}
          <circle cx="18.5" cy="18.5" r="6" fill="var(--badge-ring, var(--surface-card))" />
          <circle cx="18.5" cy="18.5" r="4.75" fill="var(--purple-ink)" />
          <circle cx="18.5" cy="17.1" r="1.35" fill="#fff" />
          <path d="M15.9 21.1a2.6 2.6 0 0 1 5.2 0" fill="none" stroke="#fff" strokeWidth="1.3" strokeLinecap="round" />
        </g>
      )}
    </svg>
  );
}
