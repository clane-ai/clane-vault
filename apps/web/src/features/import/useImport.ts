import { useQueryClient } from "@tanstack/react-query";
import { encryptFolderName, encryptNewRecord, serverRecordType } from "@clane-vault/crypto";
import { api, ApiError , type OrgApi } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgApi } from "@/lib/scope";
import type { VaultFolder } from "@/features/vault/types";
import type { ImportItem } from "./parsers";

export const BATCH_SIZE = 25;
/** Where records go: their source folders (matched by name, created when missing) or one chosen folder (null = no folder). */
export type ImportTarget = { kind: "source" } | { kind: "single"; folderId: string | null };
export interface ImportSummary { imported: number; failed: number; foldersCreated: number }

/** Encrypts in the browser and uploads in batches of 25. Plaintext never leaves the page. */
const folderKey = (name: string) => name.trim().toLowerCase();
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Retry delay for a failed batch; exported so tests can shorten it. */
export const retry = { delayMs: 1500 };

/** Uploads one batch; on failure waits and tries once more. Ids are client-made, so a retry after a lost reply answers 409 "exists": that counts as done. */
export async function uploadWithRetry(records: unknown[], http: OrgApi = api.pinned()): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try { await http.post("/records/batch", { records }); return true; }
    catch (e) {
      if (attempt > 0) return e instanceof ApiError && e.status === 409 && e.code === "exists";
      // Client errors other than rate limiting won't get better by retrying.
      if (e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 429) return false;
      await wait(retry.delayMs);
    }
  }
  return false;
}

export function useImport() {
  const { keys, generation } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();

  async function run(items: ImportItem[], target: ImportTarget, folders: VaultFolder[], onProgress: (done: number, total: number) => void): Promise<ImportSummary> {
    if (!keys) throw new Error("Vault locked");
    const gen = generation();
    const userKey = keys.userKey.slice();
    if (userKey.every((b) => b === 0)) throw new Error("Vault locked");
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    let foldersCreated = 0, imported = 0, failed = 0;
    try {
      const folderFor = new Map<string, string>();
      if (target.kind === "source") {
        const live = folders.filter((f) => !f.deleted && f.kind === "private");
        // Folder names match case-insensitively: "Design" and "design" become one folder.
        for (const name of items.map((i) => i.folder).filter((x): x is string => !!x)) {
          const key = folderKey(name);
          if (folderFor.has(key)) continue;
          const existing = live.find((f) => folderKey(f.name) === key);
          if (existing) { folderFor.set(key, existing.id); continue; }
          const id = crypto.randomUUID();
          const encName = await encryptFolderName(id, name.trim(), userKey);
          assertOpen();
          await oapi.post("/folders", { id, encName });
          folderFor.set(key, id); foldersCreated++;
        }
      }
      const folderId = (it: ImportItem) => (target.kind === "single" ? target.folderId : it.folder ? folderFor.get(folderKey(it.folder)) ?? null : null);
      onProgress(0, items.length);
      for (let i = 0; i < items.length; i += BATCH_SIZE) {
        const batch = items.slice(i, i + BATCH_SIZE);
        const records = await Promise.all(batch.map(async (it) => {
          const id = crypto.randomUUID();
          const enc = await encryptNewRecord(id, it.body, userKey);
          enc.recordKey.fill(0);
          return { id, folderId: folderId(it), type: serverRecordType(it.body), encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
        }));
        assertOpen();
        if (await uploadWithRetry(records)) imported += batch.length; else failed += batch.length;
        onProgress(imported + failed, items.length);
      }
    } finally {
      userKey.fill(0);
      await qc.invalidateQueries({ queryKey: ["vault"] });
    }
    return { imported, failed, foldersCreated };
  }
  return { run };
}
