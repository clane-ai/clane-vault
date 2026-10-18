import { useQuery, useQueryClient } from "@tanstack/react-query";
import { b64url, encryptFolderName, encryptNewRecord, randomBytes, serverRecordType, wrapKey } from "@clane-vault/crypto";
import { api, ApiError , type OrgApi } from "@/lib/api";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { myMembershipKey, sealFolderKeyTo } from "@/lib/orgKeys";
import { BATCH_SIZE, uploadWithRetry } from "@/features/import/useImport";
import type { Grant, VaultFolder } from "@/features/vault/types";
import { joins, recordsToWrite, type Plan, type PlanFolder, type Selection } from "./plan";
import type { InviteResult, MigrationReport } from "./report";

/**
 * What a migration already wrote, kept in memory for this browser session (never stored), so running it again after a
 * failure or a closed connection skips what is done: folders, records, members, pending entries and invites.
 * Keyed by a fingerprint of the export file. Wiped when the vault locks (it holds team folder keys and invite links).
 */
export interface MigrationLog {
  folders: Map<string, string>; folderKeys: Map<string, Uint8Array>;
  records: Set<string>; members: Set<string>; pending: Set<string>; invites: Map<string, InviteResult>;
}
const logs = new Map<string, MigrationLog>();
export function logFor(fingerprint: string): MigrationLog {
  let l = logs.get(fingerprint);
  if (!l) { l = { folders: new Map(), folderKeys: new Map(), records: new Set(), members: new Set(), pending: new Set(), invites: new Map() }; logs.set(fingerprint, l); }
  return l;
}
export function clearMigrationLogs() {
  for (const l of logs.values()) for (const k of l.folderKeys.values()) k.fill(0);
  logs.clear();
}

/** SHA-256 of the export text, hex: identifies "the same file" for the log. */
export async function fingerprint(text: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface Progress { phase: string; done: number; total: number }
export interface MigrationDeps {
  userKey: Uint8Array; publicKey: Uint8Array;
  /** Current vault folders (team folder keys for folders that already exist). */ folders: VaultFolder[];
  assertOpen: () => void;
  onProgress: (p: Progress) => void;
  /** Requests pinned to one org (default: the active org when the run starts). */ api?: OrgApi;
  /** The org the run writes to and each person's membership key there (folder keys are sealed to it; per-org key pairs). */
  orgId?: string; myId?: string; memberKeys?: ReadonlyMap<string, string | null>;
  /** My own membership key there, verified on this device (never the server's list): my copy of new folder keys. */
  myKey?: string | null;
}

const isCode = (e: unknown, status: number, ...codes: string[]) => e instanceof ApiError && e.status === status && (codes.length === 0 || codes.includes(e.code));
const PENDING_REASON = { invite: "invited now", invited: "already invited earlier", "awaiting-setup": "registered, hasn't finished 2FA setup" } as const;

/** Writes the plan: folders, members, pending members, records (batches of 25, one retry), invites. */
export async function runMigration(plan: Plan, sel: Selection, log: MigrationLog, d: MigrationDeps): Promise<MigrationReport> {
  // Pinned to the org the migration started in (never the one the user switches to meanwhile).
  const http = d.api ?? api.pinned();
  const startedAt = new Date().toISOString();
  const included = plan.folders.filter((f) => !sel.excluded.has(f.key));
  const total = included.reduce((n, f) => n + recordsToWrite(f, sel).length, 0);
  let done = 0;
  const report: MigrationReport = { source: plan.source, startedAt, finishedAt: startedAt, folders: [], added: [], invites: [], pending: [], managers: [], teams: plan.teams,
    attachments: plan.attachments.filter((a) => included.some((f) => a.folder.split(", ").includes(f.name))), skipped: plan.skipped, notAdded: [], failures: [], multiFolder: plan.multiFolder };
  d.onProgress({ phase: "Preparing", done, total });

  async function ensureFolder(f: PlanFolder): Promise<{ id: string | null; folderKey?: Uint8Array; status: "created" | "existing" }> {
    if (f.kind === "none") return { id: null, status: "existing" };
    const known = log.folders.get(f.key) ?? f.existingId;
    if (f.kind === "private") {
      if (known) return { id: known, status: log.folders.has(f.key) && !f.existingId ? "created" : "existing" };
      const id = crypto.randomUUID();
      const encName = await encryptFolderName(id, f.name, d.userKey);
      d.assertOpen();
      await http.post("/folders", { id, encName });
      log.folders.set(f.key, id);
      return { id, status: "created" };
    }
    if (known) {
      const fk = log.folderKeys.get(known) ?? d.folders.find((x) => x.id === known)?.folderKey;
      if (!fk) throw new Error("This team folder's key isn't available. Reload the page and run the migration again.");
      return { id: known, folderKey: fk, status: f.existingId ? "existing" : "created" };
    }
    const id = crypto.randomUUID();
    const folderKey = randomBytes(32);
    const encName = await encryptFolderName(id, f.name, folderKey);
    const mine = await sealFolderKeyTo(folderKey, { orgId: d.orgId ?? "", folderId: id }, { id: d.myId ?? "", publicKey: b64url.encode(d.publicKey), membershipKey: d.myKey ?? null }, d.myId ?? "");
    d.assertOpen();
    await http.post("/folders", { id, kind: "team", encName, ...mine });
    log.folders.set(f.key, id);
    log.folderKeys.set(id, folderKey);
    return { id, folderKey, status: "created" };
  }

  async function people(f: PlanFolder, id: string, folderKey: Uint8Array) {
    for (const m of f.members) {
      if (!m.email || m.status === "self" || m.status === "team") continue;
      if (m.status === "disabled") { report.notAdded.push({ email: m.email, folder: f.name, reason: "account disabled" }); continue; }
      if (!joins(m, sel)) { report.notAdded.push({ email: m.email, folder: f.name, reason: "not invited (unticked)" }); continue; }
      if (m.manager) report.managers.push({ email: m.email, folder: f.name });
      const key = `${f.key}|${m.email}`;
      try {
        if (m.status === "add") {
          if (!log.members.has(key)) {
            const sealed = await sealFolderKeyTo(folderKey, { orgId: d.orgId ?? "", folderId: id }, { id: m.userId!, publicKey: m.publicKey!, membershipKey: d.memberKeys?.get(m.userId!) ?? null, email: m.email }, d.myId ?? "");
            d.assertOpen();
            try { await http.post(`/folders/${id}/members`, { userId: m.userId, permission: m.permission, ...sealed }); }
            catch (e) { if (!isCode(e, 409)) throw e; }
            log.members.add(key);
          }
          report.added.push({ email: m.email, folder: f.name, permission: m.permission });
        } else {
          if (!log.pending.has(key)) {
            try { await http.post(`/folders/${id}/pending-members`, { email: m.email, permission: m.permission }); }
            catch (e) { if (!isCode(e, 409)) throw e; }
            log.pending.add(key);
          }
          report.pending.push({ email: m.email, folder: f.name, permission: m.permission, reason: PENDING_REASON[m.status as keyof typeof PENDING_REASON] ?? "" });
        }
      } catch (e) {
        if ((e as Error).message === "Vault locked") throw e;
        report.notAdded.push({ email: m.email, folder: f.name, reason: "couldn't be added; try again" });
      }
    }
  }

  for (const f of included) {
    const toWrite = recordsToWrite(f, sel);
    const skipped = f.records.length - toWrite.length;
    const result = { name: f.name, kind: f.kind, status: "existing" as "created" | "existing" | "failed", created: 0, skipped, failed: 0 } as MigrationReport["folders"][number];
    report.folders.push(result);
    d.onProgress({ phase: `Folder ${f.name}`, done, total });
    let target: Awaited<ReturnType<typeof ensureFolder>>;
    try { target = await ensureFolder(f); }
    catch (e) {
      if ((e as Error).message === "Vault locked") throw e;
      result.status = "failed"; result.error = e instanceof Error && !(e instanceof ApiError) ? e.message : "couldn't create the folder";
      result.failed = toWrite.filter((r) => !log.records.has(r.key)).length;
      result.created = toWrite.length - result.failed;
      done += toWrite.length;
      report.failures.push(`${f.name}: ${result.error}`);
      continue;
    }
    result.status = target.status;
    if (f.kind === "team") await people(f, target.id!, target.folderKey!);

    const pending = toWrite.filter((r) => !log.records.has(r.key));
    result.created = toWrite.length - pending.length;
    done += result.created;
    for (let i = 0; i < pending.length; i += BATCH_SIZE) {
      const batch = pending.slice(i, i + BATCH_SIZE);
      const items = await Promise.all(batch.map(async (r) => {
        const id = crypto.randomUUID();
        const enc = await encryptNewRecord(id, r.body, d.userKey);
        try {
          if (f.kind === "team") {
            const folderWrapped = await wrapKey(enc.recordKey, target.folderKey!, `record-key:${id}`);
            return { id, folderId: target.id, type: serverRecordType(r.body), encBody: enc.encBody, wrappedRecordKey: folderWrapped, ownerWrappedRecordKey: enc.wrappedRecordKey };
          }
          return { id, folderId: target.id, type: serverRecordType(r.body), encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
        } finally { enc.recordKey.fill(0); }
      }));
      d.assertOpen();
      if (await uploadWithRetry(items, http)) { result.created += batch.length; batch.forEach((r) => log.records.add(r.key)); }
      else result.failed += batch.length;
      done += batch.length;
      d.onProgress({ phase: `Folder ${f.name}`, done, total });
    }
    if (result.failed) report.failures.push(`${f.name}: ${result.failed} ${result.failed === 1 ? "record" : "records"} couldn't be uploaded`);
  }

  // Invites last: one per person with no account who joins at least one included folder.
  const toInvite = [...new Set(included.flatMap((f) => f.members.filter((m) => m.status === "invite" && m.email && joins(m, sel)).map((m) => m.email!)))];
  for (const email of toInvite) {
    d.onProgress({ phase: `Inviting ${email}`, done, total });
    let r = log.invites.get(email);
    if (!r) {
      try {
        // The same answer whoever the address belongs to: a copyable link (self-hosted) or an emailed one (hosted).
        const res = await http.post<{ invited: true; emailed: boolean; inviteUrl?: string }>("/admin/invites", { email, role: "member" });
        r = res.inviteUrl ? { email, url: res.inviteUrl } : { email, url: null, note: res.emailed ? "invite emailed" : "invited; ask them to check their email" };
      } catch (e) {
        r = { email, url: null, note: isCode(e, 409, "invite_cooldown") ? "declined recently; invite them again tomorrow" : isCode(e, 429, "invite_limit") ? "daily invite limit reached; invite them from People later" : "couldn't create the invite; invite them from People" };
      }
      if (r.url || r.note === "invite emailed" || r.note?.startsWith("invited;")) log.invites.set(email, r);
    }
    report.invites.push(r);
  }
  report.finishedAt = new Date().toISOString();
  d.onProgress({ phase: "Done", done: total, total });
  return report;
}

export function useMigration() {
  const { keys, generation, org, user } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  async function run(plan: Plan, sel: Selection, log: MigrationLog, folders: VaultFolder[], onProgress: (p: Progress) => void) {
    if (!keys) throw new Error("Vault locked");
    const gen = generation();
    const userKey = keys.userKey.slice(), publicKey = keys.publicKey.slice();
    if (userKey.every((b) => b === 0)) throw new Error("Vault locked");
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    try {
      // Everyone's membership key in this org (and mine): what folder keys are sealed to.
      const people = await oapi.get<{ users: { id: string; membershipKey?: string | null }[] }>("/users").then((r) => r.users).catch(() => []);
      const memberKeys = new Map(people.map((u) => [u.id, u.membershipKey ?? null]));
      // Mine, opened with my user key (a key the server lists for me could be anyone's). None or unreadable: my account key.
      const myKey = org && user ? await myMembershipKey(oapi, org.id, user.id, userKey).catch(() => null) : null;
      return await runMigration(plan, sel, log, { userKey, publicKey, folders, assertOpen, onProgress, api: oapi, orgId: org?.id, myId: user?.id, memberKeys, myKey });
    }
    finally {
      userKey.fill(0);
      await Promise.all([qc.invalidateQueries({ queryKey: ["vault"] }), qc.invalidateQueries({ queryKey: ["pending-members"] }), qc.invalidateQueries({ queryKey: ["admin-people"] })]);
    }
  }
  return { run };
}

export interface PendingMember { id: string; folderId: string; email: string; permission: Grant; createdAt: string; user: { id: string; name: string; publicKey: string; membershipKey?: string | null } | null }

/** Pending team-folder members of folders I own; `ready` are the ones whose account is active now. */
export function usePendingMembers(enabled: boolean) {
  const oapi = useOrgApi();
  const q = useQuery({ queryKey: ["pending-members", useScope()], queryFn: () => oapi.get<{ pending: PendingMember[] }>("/pending-members").then((r) => r.pending), enabled, staleTime: 30_000, refetchInterval: enabled ? 60_000 : false });
  const pending = q.data ?? [];
  return { pending, ready: pending.filter((p) => p.user), isLoading: q.isLoading, refetch: () => q.refetch() };
}

/** Adds every ready pending member to their folder: seals the folder key (held in the vault cache) to their public key. */
export function useCompletePending() {
  const { generation, org, user } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  return async (ready: PendingMember[], folders: VaultFolder[]) => {
    const gen = generation();
    const out = { added: [] as { email: string; folder: string }[], failed: [] as { email: string; folder: string }[] };
    for (const p of ready) {
      const folder = folders.find((f) => f.id === p.folderId);
      const name = folder?.name ?? "a team folder";
      if (!folder?.folderKey || !p.user) { out.failed.push({ email: p.email, folder: name }); continue; }
      const fk = folder.folderKey.slice();
      try {
        const sealed = await sealFolderKeyTo(fk, { orgId: org?.id ?? "", folderId: p.folderId }, { id: p.user.id, publicKey: p.user.publicKey, membershipKey: p.user.membershipKey ?? null, email: p.email }, user?.id ?? "");
        if (generation() !== gen) throw new Error("Vault locked");
        await oapi.post(`/folders/${p.folderId}/pending-members/${p.id}/complete`, { userId: p.user.id, ...sealed });
        out.added.push({ email: p.email, folder: name });
      } catch (e) {
        if ((e as Error).message === "Vault locked") throw e;
        if (isCode(e, 409, "already_member")) out.added.push({ email: p.email, folder: name });
        else out.failed.push({ email: p.email, folder: name });
      } finally { fk.fill(0); }
    }
    await Promise.all([qc.invalidateQueries({ queryKey: ["pending-members"] }), qc.invalidateQueries({ queryKey: ["vault"] })]);
    return out;
  };
}
