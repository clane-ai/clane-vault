import type { RecordBody } from "@clane-vault/crypto";
import type { Grant, VaultFolder, VaultRecord } from "@/features/vault/types";
import { typeCounts } from "@/features/import/typed";
import type { KeeperExport, KeeperItem, KeeperSkipped, KeeperSource } from "./keeper";

/**
 * The migration plan: what will be created, shown to the admin before anything is written.
 * Keeper shared folders → team folders owned by the migrating admin; personal folders → the admin's private folders.
 */
export type UserStatus = "active" | "pending_2fa" | "disabled";
export interface DirectoryUser { id: string; name: string; email: string; status: UserStatus; publicKey: string }
export interface PlanContext {
  me: { id: string; email: string };
  /** Everyone with an account (admin People list). */ users: DirectoryUser[];
  /** Emails with a live, unaccepted invite. */ invitedEmails: string[];
  folders: VaultFolder[]; records: VaultRecord[];
}

/**
 * add: active user, added now · invite: no account, invited now and added once registered ·
 * invited: already has a pending invite, added once registered · awaiting-setup: registered but 2FA not finished ·
 * disabled: account disabled, not added · self: the migrating admin (owner) · team: a Keeper team, not mapped.
 */
export type MemberStatus = "add" | "invite" | "invited" | "awaiting-setup" | "disabled" | "self" | "team";
export interface PlanMember { label: string; email: string | null; status: MemberStatus; permission: Grant; manager: boolean; userId?: string; name?: string; publicKey?: string }
export interface PlanRecord { key: string; row: number; body: RecordBody; duplicate: boolean; attachments: string[] }
export type FolderKind = "team" | "private" | "none";
export interface PlanFolder {
  key: string; name: string; kind: FolderKind;
  /** An existing folder with this name that the records go into (a team folder only if I own it). */ existingId: string | null;
  members: PlanMember[]; records: PlanRecord[]; duplicates: number;
}
export interface PlanPerson { email: string; status: MemberStatus; name?: string; folders: string[] }
export interface Plan {
  source: KeeperSource; folders: PlanFolder[]; people: PlanPerson[];
  /** Keeper teams (not mapped: Clane has no teams). */ teams: { name: string; folders: string[] }[];
  attachments: { title: string; folder: string; files: string[] }[];
  skipped: KeeperSkipped[];
  /** Records Keeper had in more than one folder: a copy goes into each. */ multiFolder: number;
}

const norm = (s: string | undefined) => (s ?? "").trim().toLowerCase();
/** The non-secret field (or the last four of a card number) that tells two records of a type apart. */
const IDENT: Partial<Record<RecordBody["type"], (d: Record<string, string>) => string>> = {
  card: (d) => (d.number ?? "").replace(/\D/g, "").slice(-4), bankAccount: (d) => d.accountNumber ?? "", server: (d) => `${d.hostname ?? ""}:${d.port ?? ""}`,
  database: (d) => `${d.host ?? ""}/${d.database ?? ""}`, sshKey: (d) => d.host ?? "", apiKey: (d) => d.keyId ?? "", wifi: (d) => d.ssid ?? "",
  softwareLicence: (d) => d.product ?? "", identity: (d) => d.docType ?? "", address: (d) => `${d.street1 ?? ""}|${d.postcode ?? ""}`,
  contact: (d) => d.email ?? "", membership: (d) => d.memberId ?? "",
};
/**
 * Two records are the same when title, username and URL match (logins and notes, as before records had types); for
 * other types, the type and its identifying field must match too.
 */
export const dupKey = (b: RecordBody) => {
  const base = `${norm(b.title)}\u0001${norm(b.username)}\u0001${norm(b.url)}`;
  const ident = IDENT[b.type];
  return ident ? `${base}\u0001${b.type}\u0001${norm(ident(b.data ?? {}))}` : base;
};
/** Records per type in the plan (before the selection), for the plan screen and the report. Counts only. */
export const planTypeCounts = (plan: Plan) => typeCounts(plan.folders.flatMap((f) => f.records.map((r) => r.body)));
export const folderKeyOf = (kind: FolderKind, name: string) => (kind === "none" ? "none" : `${kind}:${norm(name)}`);
const permissionOf = (m: { manageRecords: boolean; canEdit: boolean }): Grant => (m.manageRecords || m.canEdit ? "edit" : "view");
export const NO_FOLDER = "No folder";

export function buildPlan(ex: KeeperExport, ctx: PlanContext): Plan {
  const usersByEmail = new Map(ctx.users.map((u) => [norm(u.email), u]));
  const invited = new Set(ctx.invitedEmails.map(norm));
  const me = norm(ctx.me.email);
  const live = ctx.folders.filter((f) => !f.deleted);
  const folders = new Map<string, PlanFolder>();

  const statusOf = (email: string): Pick<PlanMember, "status" | "userId" | "name" | "publicKey"> => {
    if (email === me) return { status: "self" };
    const u = usersByEmail.get(email);
    if (!u) return { status: invited.has(email) ? "invited" : "invite" };
    const base = { userId: u.id, name: u.name, publicKey: u.publicKey };
    return { ...base, status: u.status === "active" ? "add" : u.status === "pending_2fa" ? "awaiting-setup" : "disabled" };
  };

  function folderFor(kind: FolderKind, name: string): PlanFolder {
    const key = folderKeyOf(kind, name);
    let f = folders.get(key);
    if (!f) {
      const existing = kind === "team"
        ? live.find((x) => x.kind === "team" && x.myPermission === "owner" && norm(x.name) === norm(name))
        : kind === "private" ? live.find((x) => x.kind === "private" && norm(x.name) === norm(name)) : undefined;
      f = { key, name: kind === "none" ? NO_FOLDER : name, kind, existingId: existing?.id ?? null, members: [], records: [], duplicates: 0 };
      folders.set(key, f);
    }
    return f;
  }

  // Team folders first, in export order, with their people.
  for (const sf of ex.sharedFolders) {
    const f = folderFor("team", sf.name);
    for (const m of sf.members) {
      if (!m.email) { f.members.push({ label: m.name, email: null, status: "team", permission: permissionOf(m), manager: m.manageUsers }); continue; }
      f.members.push({ label: m.email, email: m.email, permission: permissionOf(m), manager: m.manageUsers, ...statusOf(m.email) });
    }
  }

  // Duplicates: same title + username + URL already in the target folder (or earlier in this export for that folder).
  const seen = new Map<string, Set<string>>();
  const seenIn = (f: PlanFolder) => {
    let s = seen.get(f.key);
    if (!s) {
      s = new Set(ctx.records.filter((r) => !r.deleted && r.body && (f.existingId ? r.folderId === f.existingId : f.kind === "none" && r.folderId === null)).map((r) => dupKey(r.body!)));
      seen.set(f.key, s);
    }
    return s;
  };
  let multiFolder = 0;
  const attachments: Plan["attachments"] = [];
  const place = (it: KeeperItem) => {
    const targets = it.locations.map((l) => (l.kind === "shared" ? folderFor("team", l.folder) : l.folder ? folderFor("private", l.folder) : folderFor("none", "")));
    const unique = [...new Map(targets.map((t) => [t.key, t])).values()];
    if (unique.length > 1) multiFolder++;
    if (it.attachments.length) attachments.push({ title: it.body.title, folder: unique.map((u) => u.name).join(", "), files: it.attachments });
    for (const f of unique) {
      const s = seenIn(f);
      const k = dupKey(it.body);
      const duplicate = s.has(k);
      s.add(k);
      if (duplicate) f.duplicates++;
      f.records.push({ key: `${f.key}#${it.row}`, row: it.row, body: it.body, duplicate, attachments: it.attachments });
    }
  };
  ex.items.forEach(place);

  const ordered = [...folders.values()].sort((a, b) => {
    const rank = { team: 0, private: 1, none: 2 } as const;
    return rank[a.kind] - rank[b.kind] || a.name.localeCompare(b.name);
  });

  const people = new Map<string, PlanPerson>();
  const teams = new Map<string, string[]>();
  for (const f of ordered) for (const m of f.members) {
    if (m.status === "team") { teams.set(m.label, [...(teams.get(m.label) ?? []), f.name]); continue; }
    if (!m.email || m.status === "self") continue;
    const p = people.get(m.email) ?? { email: m.email, status: m.status, ...(m.name ? { name: m.name } : {}), folders: [] };
    p.folders.push(f.name);
    people.set(m.email, p);
  }
  return {
    source: ex.source, folders: ordered, people: [...people.values()], teams: [...teams.entries()].map(([name, fs]) => ({ name, folders: fs })),
    attachments, skipped: ex.skipped, multiFolder,
  };
}

/** What the admin chose on the plan screen. */
export interface Selection {
  /** Folder keys left out. */ excluded: Set<string>;
  /** Emails not to invite (people with status "invite"). */ noInvite: Set<string>;
  duplicates: "skip" | "import";
}
export const defaultSelection = (): Selection => ({ excluded: new Set(), noInvite: new Set(), duplicates: "skip" });

/** Records that would be written for a folder under the selection. */
export const recordsToWrite = (f: PlanFolder, sel: Selection) => (sel.excluded.has(f.key) ? [] : f.records.filter((r) => sel.duplicates === "import" || !r.duplicate));

/** Whether a member joins (now or after registering) under the selection. */
export const joins = (m: PlanMember, sel: Selection) =>
  m.status === "add" || m.status === "invited" || m.status === "awaiting-setup" || (m.status === "invite" && !!m.email && !sel.noInvite.has(m.email));

export interface PlanTotals { folders: number; newFolders: number; records: number; duplicates: number; skippedDuplicates: number; people: number; addNow: number; invites: number; later: number }
export function totals(plan: Plan, sel: Selection): PlanTotals {
  const included = plan.folders.filter((f) => !sel.excluded.has(f.key));
  const people = new Map<string, MemberStatus>();
  for (const f of included) for (const m of f.members) if (m.email && joins(m, sel)) people.set(m.email, m.status);
  const dupes = included.reduce((n, f) => n + f.duplicates, 0);
  return {
    folders: included.filter((f) => f.kind !== "none").length,
    newFolders: included.filter((f) => f.kind !== "none" && !f.existingId).length,
    records: included.reduce((n, f) => n + recordsToWrite(f, sel).length, 0),
    duplicates: dupes, skippedDuplicates: sel.duplicates === "skip" ? dupes : 0,
    people: people.size,
    addNow: [...people.values()].filter((s) => s === "add").length,
    invites: [...people.values()].filter((s) => s === "invite").length,
    later: [...people.values()].filter((s) => s !== "add").length,
  };
}
