import type { RecordBody } from "@clane-vault/crypto";
import { ImportFormatError } from "@/features/import/parsers";
import { keeperDraft } from "@/features/import/keeperRecord";
import { buildBody } from "@/features/import/typed";

/**
 * Keeper exports for the bulk migration, parsed in the browser (plaintext never leaves the page):
 * - Keeper Commander `keeper export --format json`: { shared_folders: [...with permissions], records: [...] }
 * - the Keeper web vault's JSON export: { records: [...] } (folders on each record, no membership data).
 */
export type KeeperSource = "commander" | "web-vault";
export const SOURCE_LABEL: Record<KeeperSource, string> = { commander: "Keeper Commander (JSON)", "web-vault": "Keeper web vault (JSON)" };

export interface KeeperMember {
  /** As Keeper names it: an email for a user, anything else is a Keeper team. */ name: string;
  email: string | null; manageRecords: boolean; manageUsers: boolean; canEdit: boolean;
}
export interface KeeperSharedFolder { path: string; name: string; members: KeeperMember[]; canEdit: boolean; manageRecords: boolean }
export type KeeperLocation = { kind: "shared"; folder: string; sub: string | null } | { kind: "personal"; folder: string | null };
export interface KeeperItem { row: number; body: RecordBody; locations: KeeperLocation[]; keeperType: string; attachments: string[] }
export interface KeeperSkipped { row: number; title?: string; reason: string }
export interface KeeperExport { source: KeeperSource; sharedFolders: KeeperSharedFolder[]; items: KeeperItem[]; skipped: KeeperSkipped[] }

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const text = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "");
const str = (v: unknown) => text(v).trim();
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const bool = (v: unknown) => v === true || v === "true";

/** Keeper folder paths use "\" between levels ("\\" is a literal backslash); flattened as "A / B". */
export function flattenPath(path: string): string {
  return path.replace(/\\\\/g, "\u0000").split("\\").map((p) => p.replace(/\u0000/g, "\\").trim()).filter(Boolean).join(" / ");
}

export { humanize } from "@/features/import/keeperRecord";

function toItem(r: Record<string, unknown>, row: number): { item?: KeeperItem; skip?: KeeperSkipped } {
  const keeperType = str(r.$type) || str(r.type) || "";
  const { draft, attachments: refs } = keeperDraft({
    keeperType, title: str(r.title), login: str(r.login), password: text(r.password), url: str(r.login_url), notes: text(r.notes),
    custom: Object.entries(obj(r.custom_fields) ?? {}),
  });
  const attachments: string[] = [];
  for (let i = 0; i < refs; i++) attachments.push(`File ${i + 1}`);
  for (const a of [...arr(r.attachments), ...arr(r.files)]) {
    const o = obj(a);
    attachments.push(str(o?.name) || str(o?.title) || str(o?.file_name) || (typeof a === "string" ? a : "") || `File ${attachments.length + 1}`);
  }
  // Commander lists files under "attachments"; "$fileRef" placeholders for the same files are not counted twice.
  const named = attachments.filter((a) => !/^File \d+$/.test(a));
  const files = named.length ? named : attachments;

  if (!draft.title) draft.title = (draft.url ?? draft.custom?.find((f) => f.kind === "url")?.value ?? "").replace(/^https?:\/\//, "").split("/")[0] || "";
  if (!draft.title) return { skip: { row, reason: "No title" } };
  const body = buildBody(draft);
  if (typeof body === "string") return { skip: { row, title: draft.title, reason: body } };

  const locations: KeeperLocation[] = [];
  for (const f of arr(r.folders)) {
    const o = obj(f);
    const shared = flattenPath(str(o?.shared_folder));
    const folder = flattenPath(typeof f === "string" ? f : str(o?.folder));
    const loc: KeeperLocation = shared ? { kind: "shared", folder: shared, sub: folder || null } : { kind: "personal", folder: folder || null };
    if (!locations.some((l) => l.kind === loc.kind && l.folder === loc.folder)) locations.push(loc);
  }
  if (!locations.length) locations.push({ kind: "personal", folder: null });
  return { item: { row, body, locations, keeperType: keeperType || "login", attachments: files } };
}

function sharedFolder(o: Record<string, unknown>): KeeperSharedFolder | null {
  const path = str(o.path) || str(o.name);
  const name = flattenPath(path);
  if (!name) return null;
  const members: KeeperMember[] = [];
  for (const p of arr(o.permissions)) {
    const m = obj(p);
    const n = str(m?.name) || str(m?.email) || str(m?.username);
    if (!m || !n) continue;
    const email = EMAIL.test(n) ? n.toLowerCase() : null;
    if (members.some((x) => (x.email ?? x.name) === (email ?? n))) continue;
    members.push({ name: n, email, manageRecords: bool(m.manage_records), manageUsers: bool(m.manage_users), canEdit: bool(m.can_edit) });
  }
  return { path, name, members, canEdit: bool(o.can_edit), manageRecords: bool(o.manage_records) };
}

/** Parses a Keeper JSON export (Commander or web vault). Throws ImportFormatError for anything else. */
export function parseKeeperExport(raw: string): KeeperExport {
  const t = raw.replace(/^﻿/, "").trim();
  if (!t) throw new ImportFormatError("The file is empty.");
  let data: unknown;
  try { data = JSON.parse(t); } catch { throw new ImportFormatError("This isn't a JSON file. Export from Keeper as JSON (see the guide)."); }
  const d = obj(data);
  if (!d || !Array.isArray(d.records)) throw new ImportFormatError("This JSON file isn't a Keeper export (no records).");
  const source: KeeperSource = Array.isArray(d.shared_folders) ? "commander" : "web-vault";
  const sharedFolders: KeeperSharedFolder[] = [];
  for (const s of arr(d.shared_folders)) {
    const o = obj(s);
    const f = o && sharedFolder(o);
    if (f && !sharedFolders.some((x) => x.name === f.name)) sharedFolders.push(f);
  }
  const items: KeeperItem[] = [], skipped: KeeperSkipped[] = [];
  d.records.forEach((x, i) => {
    const r = obj(x);
    if (!r) { skipped.push({ row: i + 1, reason: "Not a record" }); return; }
    let out: ReturnType<typeof toItem>;
    try { out = toItem(r, i + 1); } catch { out = { skip: { row: i + 1, reason: "Couldn't read this record" } }; }
    if (out.item) items.push(out.item); else skipped.push(out.skip!);
  });
  // Shared folders only named on records (web vault exports, or a partial Commander export) still become team folders.
  for (const it of items) for (const l of it.locations) {
    if (l.kind === "shared" && !sharedFolders.some((f) => f.name === l.folder)) sharedFolders.push({ path: l.folder, name: l.folder, members: [], canEdit: false, manageRecords: false });
  }
  return { source, sharedFolders, items, skipped };
}
