import type { RecordType } from "@clane-vault/crypto";
import { searchableText } from "./recordKinds";
import type { VaultFolder, VaultRecord } from "./types";

export type VaultView = "vault" | "shared" | "attention" | "links" | "trash";
/** Records shared with me directly by someone else (not via a team folder). */
export const isSharedWithMe = (r: VaultRecord) => !!r.sharedBy;
const title = (r: VaultRecord) => r.body?.title ?? "";

/** `type`: only records of this type (the list header's type filter). Search covers titles and non-secret fields only. */
export function filterRecords(records: VaultRecord[], o: { view: VaultView; query: string; sort: "name" | "recent"; type?: RecordType | null }): VaultRecord[] {
  const q = o.query.trim().toLowerCase();
  return records
    // Trash holds my own records only: someone else's trashed record is theirs to restore.
    .filter((r) => (o.view === "trash" ? r.deleted && r.permission === "owner" : !r.deleted && (o.view !== "shared" || isSharedWithMe(r))))
    .filter((r) => !o.type || r.body?.type === o.type)
    .filter((r) => !q || searchableText(r.body).some((v) => v.toLowerCase().includes(q)))
    .sort((a, b) => {
      if (!!a.error !== !!b.error) return a.error ? 1 : -1;
      return o.sort === "recent" ? b.updatedAt.localeCompare(a.updatedAt) : title(a).localeCompare(title(b), undefined, { sensitivity: "base" });
    });
}

export function groupByFolder(records: VaultRecord[], folders: VaultFolder[]) {
  const live = folders.filter((f) => !f.deleted).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  const groups: { folder: VaultFolder | null; records: VaultRecord[] }[] = live.map((f) => ({ folder: f, records: records.filter((r) => r.folderId === f.id) }));
  const unfiled = records.filter((r) => !r.folderId || !live.some((f) => f.id === r.folderId));
  if (unfiled.length) groups.push({ folder: null, records: unfiled });
  return groups;
}
