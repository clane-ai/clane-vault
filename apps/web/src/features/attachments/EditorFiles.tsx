import { X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import type { VaultRecord } from "@/features/vault/types";
import { DropTarget } from "./AttachmentDropZone";
import { FilesSection } from "./AttachmentList";
import { fileIcon, formatBytes } from "./format";
import { precheck } from "./uploader";
import { useAttach, useAttachmentLimits } from "./useAttachments";

/** Files in the editor of an existing record: they upload at once, independent of Save. */
export function EditorFiles({ record }: { record: VaultRecord }) {
  const limits = useAttachmentLimits();
  const attach = useAttach(record);
  const canAdd = (record.permission === "owner" || record.permission === "edit") && limits.uploadsAllowed && !!record.recordKey;
  return (
    <div className="flex flex-col gap-2.5">
      <FilesSection record={record} editor />
      {canAdd && <DropTarget onFiles={attach} />}
    </div>
  );
}

/**
 * Files for a record that doesn't exist yet: kept in a queue (nothing leaves the device) and uploaded right after the
 * first successful save, when the record has its id and key. Cancelling the new record discards the queue.
 */
export function QueuedFiles({ queue, onChange }: { queue: File[]; onChange: (q: File[]) => void }) {
  const limits = useAttachmentLimits();
  if (!limits.uploadsAllowed) return null;
  const add = (files: File[]) => {
    const next = [...queue];
    for (const f of files) {
      const why = precheck(f, { maxFileMb: limits.maxFileMb, maxPerRecord: limits.maxPerRecord, maxRecordMb: limits.maxRecordMb, existingFiles: 0, existingBytes: 0, pending: next });
      if (why) { toast.error(why); continue; }
      next.push(f);
    }
    onChange(next);
  };
  return (
    <section className="flex flex-col gap-2" aria-label="Files">
      <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Files{queue.length ? ` · ${queue.length}` : ""}</h3>
      {queue.length > 0 && (
        <ul className="overflow-hidden rounded-[12px] border border-border-default bg-card">
          {queue.map((f, i) => {
            const Icon = fileIcon(f.type, f.name);
            return (
              <li key={`${f.name}-${i}`} className="flex items-center gap-3 border-b border-border-default px-4 py-2.5 last:border-b-0" data-testid="queued-file">
                <Icon className="size-4 shrink-0 text-text-secondary" />
                <span className="min-w-0 flex-1 truncate text-[13.5px] text-text-primary">{f.name}</span>
                <span className="font-mono text-[11.5px] text-text-tertiary">{formatBytes(f.size)}</span>
                <Button type="button" variant="ghost" size="icon" aria-label={`Don't attach ${f.name}`} onClick={() => onChange(queue.filter((_, j) => j !== i))}><X className="size-4" /></Button>
              </li>
            );
          })}
        </ul>
      )}
      <DropTarget onFiles={add} hint={queue.length ? "They upload as soon as you save the record." : "Drop files here or choose them. They upload after you save the record."} />
    </section>
  );
}
