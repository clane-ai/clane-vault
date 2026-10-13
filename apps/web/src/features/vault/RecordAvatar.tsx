import type { RecordType } from "@clane-vault/crypto";
import { cn } from "@/lib/utils";
import { TYPE_ICON } from "./recordKinds";

// Six Clane accent tiles; a record always lands on the same one (hash of its title). The navy tile is lifted in the
// dark theme, where navy-700 nearly disappears into the card.
const TILES = ["bg-blue-500", "bg-orange-500", "bg-green-600", "bg-purple-ink", "bg-amber-500", "bg-navy-700 dark:bg-[#2A4A8A]"] as const;

export function tileFor(title: string): string {
  let h = 0;
  for (let i = 0; i < title.length; i++) h = (h * 31 + title.charCodeAt(i)) | 0;
  return TILES[Math.abs(h) % TILES.length];
}

const SIZE = {
  22: "size-[22px] rounded-[6px] text-[11px]",
  32: "size-8 rounded-[9px] text-[14px]",
  36: "size-9 rounded-[9px] text-[15px]",
  44: "size-11 rounded-[9px] text-[18px]",
} as const;
const NOTE_ICON = { 22: "size-3", 32: "size-4", 36: "size-4", 44: "size-5" } as const;

/**
 * A record's tile: the first letter of its title on a stable accent colour for logins; the type's glyph on the well for
 * every other type (a note, a card, a server…); "?" when it can't be opened. No favicons: the app never fetches
 * third-party images.
 */
export function RecordAvatar({ title, kind, size = 36, className }: {
  title: string | null | undefined;
  /** The record type: anything but a login shows its type glyph instead of a letter. */ kind?: RecordType;
  size?: keyof typeof SIZE; className?: string;
}) {
  const t = title?.trim() ?? "";
  const glyph = !!kind && kind !== "login" && !!t;
  const Icon = glyph ? TYPE_ICON[kind!] : null;
  return (
    <span aria-hidden="true" data-testid="record-avatar" data-kind={glyph ? kind : t ? "letter" : "unknown"}
      className={cn("grid shrink-0 place-items-center font-display font-semibold select-none", SIZE[size],
        glyph || !t ? "bg-well text-text-secondary" : cn(tileFor(t), "text-white"), className)}>
      {Icon ? <Icon className={NOTE_ICON[size]} /> : t ? t[0]!.toUpperCase() : "?"}
    </span>
  );
}
