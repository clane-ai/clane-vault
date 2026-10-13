import type { Grant } from "@/features/vault/types";
import type { FolderKind, Plan } from "./plan";
import type { KeeperSource } from "./keeper";

export interface FolderResult { name: string; kind: FolderKind; status: "created" | "existing" | "failed"; created: number; skipped: number; failed: number; error?: string }
export interface InviteResult { email: string; url: string | null; note?: string }
export interface MigrationReport {
  source: KeeperSource; startedAt: string; finishedAt: string;
  folders: FolderResult[];
  /** Existing active people added to team folders. */ added: { email: string; folder: string; permission: Grant }[];
  /** Invite links to send (shown once). */ invites: InviteResult[];
  /** People to add once they are active ("Complete pending members"). */ pending: { email: string; folder: string; permission: Grant; reason: string }[];
  /** Keeper "manage users" holders: Clane has only the owner as folder manager. */ managers: { email: string; folder: string }[];
  teams: Plan["teams"]; attachments: Plan["attachments"]; skipped: Plan["skipped"];
  notAdded: { email: string; folder: string; reason: string }[];
  failures: string[];
  multiFolder: number;
  /** Records per type in the plan ("Payment card" → 3): counts only, never values. Absent in reports from before record types. */
  types?: { type: string; label: string; count: number }[];
}

export const reportTotals = (r: MigrationReport) => ({
  created: r.folders.reduce((n, f) => n + f.created, 0), skipped: r.folders.reduce((n, f) => n + f.skipped, 0), failed: r.folders.reduce((n, f) => n + f.failed, 0),
});

const cell = (v: unknown) => {
  const s = v == null ? "" : String(v);
  // Quote everything that needs it; a leading =,+,-,@ is neutralised so spreadsheets don't run it as a formula.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\r\n]/.test(safe) || safe !== s ? `"${safe.replace(/"/g, '""')}"` : safe;
};

/** One table: section, folder, name, detail, status. No passwords or record contents. */
export function reportCsv(r: MigrationReport): string {
  const rows: unknown[][] = [["section", "folder", "item", "detail", "status"]];
  for (const t of r.types ?? []) rows.push(["record type", "", t.label, String(t.count), "planned"]);
  for (const f of r.folders) rows.push(["folder", f.name, f.kind, `created ${f.created}; skipped ${f.skipped}; failed ${f.failed}`, f.error ? `${f.status}: ${f.error}` : f.status]);
  for (const a of r.added) rows.push(["member added", a.folder, a.email, a.permission, "added"]);
  for (const i of r.invites) rows.push(["invite", "", i.email, i.url ?? "", i.note ?? (i.url ? "send this link" : "")]);
  for (const p of r.pending) rows.push(["add after registering", p.folder, p.email, p.permission, p.reason]);
  for (const m of r.managers) rows.push(["keeper folder manager", m.folder, m.email, "manage users in Keeper; only the owner manages people in Clane", "note"]);
  for (const n of r.notAdded) rows.push(["not added", n.folder, n.email, "", n.reason]);
  for (const t of r.teams) rows.push(["keeper team (not mapped)", t.folders.join("; "), t.name, "", "add its people by hand"]);
  for (const a of r.attachments) rows.push(["attachment (not migrated)", a.folder, a.title, a.files.join("; "), "download from Keeper"]);
  for (const s of r.skipped) rows.push(["skipped record", "", s.title ?? `record ${s.row}`, `record ${s.row}`, s.reason]);
  for (const f of r.failures) rows.push(["error", "", "", f, "failed"]);
  return rows.map((row) => row.map(cell).join(",")).join("\r\n") + "\r\n";
}

export const reportJson = (r: MigrationReport) => JSON.stringify(r, null, 2);
