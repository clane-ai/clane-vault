/** The strip under every page: encryption, sync time (or the offline copy's age). */
export function StatusBar({ syncedAt, offline }: { syncedAt: Date | null; offline?: boolean }) {
  // A dot span, not a "●" character: the glyph's baseline drifts between fonts.
  const dot = (tone: string) => <span aria-hidden="true" className={`mr-1.5 inline-block size-1.5 rounded-full align-[1px] ${tone}`} />;
  return (
    <div className="flex h-7 shrink-0 items-center gap-4 border-t border-border-default bg-card px-6 font-mono text-[11px] text-text-secondary max-[760px]:px-3">
      <span>{dot("bg-green-600")}End-to-end encrypted</span>
      {offline ? <span>{dot("bg-amber-500")}Offline copy{syncedAt ? ` from ${syncedAt.toLocaleString([], { dateStyle: "short", timeStyle: "short" })}` : ""}</span>
        : <span>{syncedAt ? `Synced ${syncedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Syncing…"}</span>}
    </div>
  );
}
