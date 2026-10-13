import { Link2 } from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/features/vault/RecordList";
import type { VaultRecord } from "@/features/vault/types";
import { LinkRow } from "./OneTimeLinkSheet";
import { useLinks, type ShareLink } from "./useLinks";

/** Sidebar "Share links" view: my links, active first, with Revoke. */
export function LinksView({ records }: { records: VaultRecord[] }) {
  const { links, isLoading, error, revoke } = useLinks();
  const title = (id: string) => records.find((r) => r.id === id)?.body?.title ?? "Deleted record";
  const active = links.filter((l) => l.state === "active");
  const ended = links.filter((l) => l.state !== "active").slice(0, 20);
  async function onRevoke(l: ShareLink) {
    try { await revoke(l.id); toast.success("Link revoked"); } catch { toast.error("Couldn't revoke the link. Try again."); }
  }
  if (isLoading) return <p className="py-16 text-center text-[14px] text-text-secondary">Loading links…</p>;
  if (error) return <p role="alert" className="py-16 text-center text-[14px] text-text-secondary">Couldn't load your links.</p>;
  const card = "overflow-hidden rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]";
  return (
    <div className="flex flex-col gap-5">
      {active.length === 0
        ? <div className={card}><EmptyState icon={Link2} title="No active links" line="Open a record and choose One-time link to send it to someone outside the team." /></div>
        : <ul className={card} aria-label="Active links">{active.map((l) => <LinkRow key={l.id} l={l} title={title(l.recordId)} onRevoke={onRevoke} />)}</ul>}
      {ended.length > 0 && (
        <section className="flex flex-col gap-2" aria-label="Ended links">
          <h2 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Ended</h2>
          <ul className={card}>{ended.map((l) => <LinkRow key={l.id} l={l} title={title(l.recordId)} onRevoke={onRevoke} />)}</ul>
        </section>
      )}
    </div>
  );
}
