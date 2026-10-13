import type { Permission } from "@prisma/client";
import type { Db } from "../access.js";

/**
 * What a client sees of a file (docs/design/2026-10-12-attachments.md §4.4): ciphertext and the facts the
 * server knows anyway. `use` holders get the metadata (names are under the record key they already hold) but not the
 * wrapped file key: they can't fetch the chunks, so they don't need it.
 */
export interface AttachmentView {
  id: string; encMeta: string; wrappedFileKey?: string; nonceBase?: string; size: number; chunkSize: number; chunkCount: number;
  createdBy: string; createdByName: string; createdAt: string;
}

type Row = { id: string; recordId: string; encMeta: string; wrappedFileKey: string; nonceBase: string; size: number; chunkSize: number; chunkCount: number; createdBy: string; createdAt: Date; readyAt: Date | null };

export function attachmentView(a: Row, names: Map<string, string>, permission: Permission): AttachmentView {
  return {
    id: a.id, encMeta: a.encMeta, ...(permission === "use" ? {} : { wrappedFileKey: a.wrappedFileKey, nonceBase: a.nonceBase }),
    size: a.size, chunkSize: a.chunkSize, chunkCount: a.chunkCount, createdBy: a.createdBy, createdByName: names.get(a.createdBy) ?? "Removed user",
    createdAt: (a.readyAt ?? a.createdAt).toISOString(),
  };
}

/** Ready files of these records, oldest first, with their creators' names; grouped by record. */
export async function readyAttachments(db: Db, recordIds: string[]): Promise<{ rows: Map<string, Row[]>; names: Map<string, string> }> {
  const rows = new Map<string, Row[]>();
  if (!recordIds.length) return { rows, names: new Map() };
  const list = await db.attachment.findMany({ where: { recordId: { in: recordIds }, state: "ready" }, orderBy: [{ readyAt: "asc" }, { id: "asc" }],
    select: { id: true, recordId: true, encMeta: true, wrappedFileKey: true, nonceBase: true, size: true, chunkSize: true, chunkCount: true, createdBy: true, createdAt: true, readyAt: true } });
  for (const a of list) rows.set(a.recordId, [...(rows.get(a.recordId) ?? []), a]);
  const ids = [...new Set(list.map((a) => a.createdBy))];
  const names = new Map((await db.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true } })).map((u) => [u.id, u.name]));
  return { rows, names };
}
