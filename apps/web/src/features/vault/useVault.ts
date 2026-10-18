import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  b64url, CryptoError, encryptFolderName, encryptNewRecord, encryptRecordBody, randomBytes, serverRecordType, wrapKey,
  type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
import { ApiError, forOrg } from "@/lib/api";
import { useSession, type Org } from "@/lib/session";
import { useOrgApi, useScope, useScopeOrg } from "@/lib/scope";
import { dropSync, loadSync, orgKey, saveSync } from "@/lib/offline";
import { assertPinned, myMembershipKey, pinKey, sealFolderKeyTo, sealShareTo } from "@/lib/orgKeys";
import { decryptSync } from "./decrypt";
import type { FolderMember, Grant, Permission, Person, SyncResponse, VaultFolder, VaultRecord } from "./types";

export class ConflictError extends Error { constructor() { super("Someone else changed this record. We loaded their version."); } }

const isZero = (k: Uint8Array) => k.every((b) => b === 0);
/** Offline the vault is read-only: nothing offers editing, sharing or trashing ("use only" stays "use only"). */
const readOnly = (p: Permission): Permission => (p === "use" ? "use" : "view");

export function useVault() {
  const { keys, user, generation, offline, org } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  // Keyed by user and space (Personal or the org): switching never shows another space's vault from the cache.
  // Offline data (from this device's copy) never shares a cache entry with online data.
  const scope = useScope();
  const KEY = offline ? ["vault", scope, "offline"] : ["vault", scope];

  // Work on private copies of the keys so lock() zeroing the session keys mid-flight never yields keys wrapped under zeros.
  async function withKey<T>(fn: (keys: UnlockedKeys, assertOpen: () => void) => Promise<T>): Promise<T> {
    if (!keys) throw new Error("Vault locked");
    const gen = generation();
    const copy: UnlockedKeys = { userKey: keys.userKey.slice(), privateKey: keys.privateKey.slice(), publicKey: keys.publicKey.slice() };
    if (isZero(copy.userKey)) throw new Error("Vault locked");
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    try { return await fn(copy, assertOpen); } finally { copy.userKey.fill(0); copy.privateKey.fill(0); }
  }
  /** Same for a record or folder key held in the vault cache. */
  async function withSecret<T>(secret: Uint8Array | null | undefined, what: string, fn: (k: Uint8Array, assertOpen: () => void) => Promise<T>): Promise<T> {
    if (!secret) throw new Error(`This ${what} can't be opened`);
    const gen = generation();
    const copy = secret.slice();
    if (isZero(copy)) throw new Error("Vault locked");
    const assertOpen = () => { if (generation() !== gen) throw new Error("Vault locked"); };
    try { return await fn(copy, assertOpen); } finally { copy.fill(0); }
  }

  const q = useQuery({
    queryKey: KEY,
    queryFn: () => withKey(async (k, assertOpen) => {
      let sync: SyncResponse, savedAt: string | null = null;
      if (offline) {
        const saved = user ? await loadSync(user.id, orgKey(org?.id)) : null;
        if (!saved) throw new Error("No offline copy");
        ({ sync, savedAt } = saved);
      } else {
        // The space only: an org's items in an org (?space=org), private ones in Personal (no X-Org-Id).
        sync = await oapi.get<SyncResponse>(org ? "/sync?space=org" : "/sync");
        // The offline copy: ciphertext as received, unless the org's policy forbids offline copies.
        if (user) void (org?.policies?.offlineAllowed === false ? dropSync(user.id, orgKey(org.id)) : saveSync(user.id, orgKey(org?.id), sync));
      }
      // Membership keys are bound to the org this client asked for, never the server's word.
      const out = { ...(await decryptSync(sync, k, user?.id, org?.id ?? null)), privateLocked: !!sync.privateLocked, savedAt };
      if (offline) {
        out.records = out.records.map((r) => ({ ...r, permission: readOnly(r.permission) }));
        out.folders = out.folders.map((f) => ({ ...f, myPermission: readOnly(f.myPermission ?? "view") }));
      }
      try { assertOpen(); } catch (e) { out.records.forEach((r) => r.recordKey?.fill(0)); out.folders.forEach((f) => f.folderKey?.fill(0)); throw e; }
      return out;
    }),
    staleTime: 15_000,
    ...(offline ? { retry: false, refetchOnWindowFocus: false } : {}),
  });
  const refetch = () => qc.invalidateQueries({ queryKey: KEY });
  const after = { onSuccess: refetch };
  const folderById = (id: string | null) => (id ? q.data?.folders.find((f) => f.id === id) : undefined);

  const createRecord = useMutation({ mutationFn: async (input: { folderId: string | null; body: RecordBody;
    /** Called once the record exists, with its key (zeroed right after): queued files start uploading here. */ onCreated?: (id: string, recordKey: Uint8Array) => void }) => {
    const id = crypto.randomUUID();
    const team = folderById(input.folderId);
    return withKey(async (k, assertOpen) => {
      const enc = await encryptNewRecord(id, input.body, k.userKey);
      try {
        if (team?.kind === "team") {
          // Team records: the folder's wrap lets members open it, the owner's own wrap survives leaving the folder.
          const folderWrapped = await withSecret(team.folderKey, "folder", (fk) => wrapKey(enc.recordKey, fk, `record-key:${id}`));
          assertOpen();
          await oapi.post("/records", { id, folderId: input.folderId, type: serverRecordType(input.body), encBody: enc.encBody, wrappedRecordKey: folderWrapped, ownerWrappedRecordKey: enc.wrappedRecordKey });
        } else {
          assertOpen();
          await oapi.post("/records", { id, folderId: input.folderId, type: serverRecordType(input.body), encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey });
        }
        input.onCreated?.(id, enc.recordKey);
      } finally { enc.recordKey.fill(0); }
      return id;
    });
  }, ...after });

  const updateRecord = useMutation({ mutationFn: async (v: { r: VaultRecord; body: RecordBody }) => {
    const encBody = await withSecret(v.r.recordKey, "record", async (rk, assertOpen) => { const e = await encryptRecordBody(v.r.id, v.body, rk); assertOpen(); return e; });
    try {
      await oapi.put(`/records/${v.r.id}`, { encBody, revision: v.r.revision, type: serverRecordType(v.body) });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.code !== "in_trash") { await refetch(); throw new ConflictError(); }
      throw e;
    }
  }, ...after });

  /** Moves a record (owner only). Into a team folder the record key is re-wrapped under that folder's key. */
  const moveRecord = useMutation({ mutationFn: async (v: { r: VaultRecord; folderId: string | null }) => {
    const target = folderById(v.folderId);
    // My own wrap goes along every time: the server uses it when I own the record only through a team folder I own.
    const ownerWrappedRecordKey = await withKey((k) => withSecret(v.r.recordKey, "record", (rk) => wrapKey(rk, k.userKey, `record-key:${v.r.id}`)));
    if (target?.kind === "team") {
      const folderWrappedRecordKey = await withSecret(v.r.recordKey, "record", (rk, assertOpen) =>
        withSecret(target.folderKey, "folder", async (fk) => { const w = await wrapKey(rk, fk, `record-key:${v.r.id}`); assertOpen(); return w; }));
      return oapi.put(`/records/${v.r.id}/folder`, { folderId: v.folderId, folderWrappedRecordKey, ownerWrappedRecordKey });
    }
    return oapi.put(`/records/${v.r.id}/folder`, { folderId: v.folderId, ownerWrappedRecordKey });
  }, ...after });

  const useSimple = <V,>(fn: (v: V) => Promise<unknown>) => useMutation({ mutationFn: fn, ...after });
  const trash = useSimple((id: string) => oapi.del(`/records/${id}`));
  const restore = useSimple((id: string) => oapi.post(`/records/${id}/restore`));
  const purge = useSimple((id: string) => oapi.del(`/records/${id}/purge`));
  const delFolder = useSimple((id: string) => oapi.del(`/folders/${id}`));
  const updateMember = useSimple((v: { folderId: string; userId: string; permission: Grant }) => oapi.patch(`/folders/${v.folderId}/members/${v.userId}`, { permission: v.permission }));
  const removeMember = useSimple((v: { folderId: string; userId: string }) => oapi.del(`/folders/${v.folderId}/members/${v.userId}`));
  const updateShare = useSimple((v: { recordId: string; userId: string; permission: Grant }) => oapi.patch(`/records/${v.recordId}/shares/${v.userId}`, { permission: v.permission }));
  const unshare = useSimple((v: { recordId: string; userId: string }) => oapi.del(`/records/${v.recordId}/shares/${v.userId}`));

  const createFolder = useMutation({ mutationFn: async (name: string) => {
    const id = crypto.randomUUID();
    return withKey(async (k, assertOpen) => {
      const encName = await encryptFolderName(id, name, k.userKey);
      assertOpen();
      await oapi.post("/folders", { id, encName });
      return id;
    });
  }, ...after });

  /** A person's keys as the server lists them right now (their membership key may have just been created or replaced). */
  async function freshPerson(p: Person): Promise<Person> {
    const users = await oapi.get<{ users: Person[] }>("/users").then((r) => r.users);
    void qc.setQueryData(["people", scope], users);
    return users.find((u) => u.id === p.id) ?? p;
  }
  /** Runs `fn` for a recipient; once more with their fresh keys if the server says it sealed to a stale key. */
  async function toRecipient<T>(p: Person, fn: (p: Person) => Promise<T>): Promise<T> {
    try { return await fn(p); }
    catch (e) { if (e instanceof ApiError && e.code === "stale_recipient_key") return fn(await freshPerson(p)); throw e; }
  }

  /** Seals the folder key to each person's key in this org (their membership key, or their account key while they have none). */
  async function addMembers(folderId: string, folderKey: Uint8Array, people: { person: Person; permission: Grant }[], assertOpen: () => void) {
    if (!org) throw new Error("No organisation");
    for (const { person, permission } of people) {
      await toRecipient(person, async (p) => {
        if (user) assertPinned(user.id, org.id, p);
        const sealed = await sealFolderKeyTo(folderKey, { orgId: org.id, folderId }, p);
        assertOpen();
        await oapi.post(`/folders/${folderId}/members`, { userId: p.id, permission, ...sealed });
        if (user) pinKey(user.id, org.id, p.id, p.membershipKey, p.publicKey);
      });
    }
  }

  const createTeam = useMutation({ mutationFn: async (v: { name: string; people: { person: Person; permission: Grant }[] }) => {
    const id = crypto.randomUUID();
    if (!org) throw new Error("No organisation");
    return withKey(async (k, assertOpen) => {
      const folderKey = randomBytes(32);
      try {
        // My own copy goes to my membership key here (asked fresh: this device may have just created it), and only to
        // one I can open: a key the server merely lists as mine could be anyone's, and the folder's key would go to them.
        const mine = await myMembershipKey(oapi, org.id, user!.id, k.userKey).catch((e: unknown) => { if (e instanceof CryptoError) throw e; return q.data?.membershipKey ?? null; });
        const me = { id: user!.id, publicKey: b64url.encode(k.publicKey), membershipKey: mine };
        const encName = await encryptFolderName(id, v.name, folderKey);
        const sealed = await sealFolderKeyTo(folderKey, { orgId: org.id, folderId: id }, me);
        assertOpen();
        await oapi.post("/folders", { id, kind: "team", encName, ...sealed });
        await addMembers(id, folderKey, v.people, assertOpen);
      } finally { folderKey.fill(0); }
      return id;
    });
  }, onSettled: refetch });

  const addMember = useMutation({ mutationFn: async (v: { folder: VaultFolder; person: Person; permission: Grant }) =>
    withSecret(v.folder.folderKey, "folder", (fk, assertOpen) => addMembers(v.folder.id, fk, [{ person: v.person, permission: v.permission }], assertOpen)), ...after });

  /**
   * Gives a member their folder key again after their key changed (an account reset): an explicit action of a key
   * holder, sealed to the member's current key in this org (docs/design/2026-10-08-per-org-keypairs.md §8).
   */
  const giveAccessAgain = useMutation({ mutationFn: async (v: { folder: VaultFolder; member: FolderMember }) => {
    if (!org) throw new Error("No organisation");
    return withSecret(v.folder.folderKey, "folder", async (fk, assertOpen) => {
      // Agent fields go along: sealing checks an agent's attestation (ruling R41).
      const m = v.member;
      const sealed = await sealFolderKeyTo(fk, { orgId: org.id, folderId: v.folder.id },
        { id: m.userId, publicKey: m.publicKey, membershipKey: m.membershipKey ?? null, kind: m.kind, email: m.email, attestation: m.attestation, gatewayKeyId: m.gatewayKeyId });
      assertOpen();
      await oapi.put(`/folders/${v.folder.id}/members/${v.member.userId}/key`, sealed);
      if (user) pinKey(user.id, org.id, v.member.userId, v.member.membershipKey, v.member.publicKey);
    });
  }, ...after });

  const renameFolder = useMutation({ mutationFn: async (v: { id: string; name: string }) => {
    const f = folderById(v.id);
    if (f?.kind === "team") return withSecret(f.folderKey, "folder", async (fk, assertOpen) => { const encName = await encryptFolderName(v.id, v.name, fk); assertOpen(); return oapi.patch(`/folders/${v.id}`, { encName }); });
    return withKey(async (k, assertOpen) => {
      const encName = await encryptFolderName(v.id, v.name, k.userKey);
      assertOpen();
      return oapi.patch(`/folders/${v.id}`, { encName });
    });
  }, ...after });

  const share = useMutation({ mutationFn: async (v: { r: VaultRecord; person: Person; permission: Grant }) =>
    withSecret(v.r.recordKey, "record", async (rk, assertOpen) => {
      if (!org) throw new Error("No organisation");
      return toRecipient(v.person, async (p) => {
        if (user) assertPinned(user.id, org.id, p);
        const sealed = await sealShareTo(rk, { orgId: org.id, recordId: v.r.id }, p);
        assertOpen();
        const res = await oapi.post(`/records/${v.r.id}/shares`, { userId: p.id, permission: v.permission, ...sealed });
        if (user) pinKey(user.id, org.id, p.id, p.membershipKey, p.publicKey);
        return res;
      });
    }), ...after });

  /**
   * Personal space: shares a private record inside one of my organisations (direct shares always belong to an org).
   * Sealed to the person's key in that org and sent with that org's X-Org-Id; the share then shows in that org.
   */
  const shareIn = useMutation({ mutationFn: async (v: { r: VaultRecord; in: Org; person: Person; permission: Grant }) =>
    withSecret(v.r.recordKey, "record", async (rk, assertOpen) => {
      const there = forOrg(v.in.id);
      const send = async (p: Person) => {
        if (user) assertPinned(user.id, v.in.id, p);
        const sealed = await sealShareTo(rk, { orgId: v.in.id, recordId: v.r.id }, p);
        assertOpen();
        const res = await there.post(`/records/${v.r.id}/shares`, { userId: p.id, permission: v.permission, ...sealed });
        if (user) pinKey(user.id, v.in.id, p.id, p.membershipKey, p.publicKey);
        return res;
      };
      try { return await send(v.person); }
      catch (e) {
        if (!(e instanceof ApiError && e.code === "stale_recipient_key")) throw e;
        const fresh = (await there.get<{ users: Person[] }>("/users")).users.find((u) => u.id === v.person.id) ?? v.person;
        return send(fresh);
      }
    }), ...after });

  return {
    folders: q.data?.folders ?? [], records: q.data?.records ?? [], isLoading: q.isLoading, error: q.error,
    /** Own private items were left out (session without the authenticator code yet). */ privateLocked: !!q.data?.privateLocked,
    /** Offline: when this device saved the copy being shown. */ savedAt: q.data?.savedAt ?? null,
    retry: () => q.refetch(),
    createRecord: (input: { folderId: string | null; body: RecordBody; onCreated?: (id: string, recordKey: Uint8Array) => void }) => createRecord.mutateAsync(input),
    /** Refetches the vault (after a file upload finished). */ refresh: refetch,
    updateRecord: (r: VaultRecord, body: RecordBody) => updateRecord.mutateAsync({ r, body }),
    moveRecord: (r: VaultRecord, folderId: string | null) => moveRecord.mutateAsync({ r, folderId }),
    trashRecord: (id: string) => trash.mutateAsync(id), restoreRecord: (id: string) => restore.mutateAsync(id), purgeRecord: (id: string) => purge.mutateAsync(id),
    createFolder: (name: string) => createFolder.mutateAsync(name), renameFolder: (id: string, name: string) => renameFolder.mutateAsync({ id, name }),
    deleteFolder: (id: string) => delFolder.mutateAsync(id),
    createTeamFolder: (name: string, people: { person: Person; permission: Grant }[]) => createTeam.mutateAsync({ name, people }),
    addMember: (folder: VaultFolder, person: Person, permission: Grant) => addMember.mutateAsync({ folder, person, permission }),
    giveAccessAgain: (folder: VaultFolder, member: FolderMember) => giveAccessAgain.mutateAsync({ folder, member }),
    updateMember: (folderId: string, userId: string, permission: Grant) => updateMember.mutateAsync({ folderId, userId, permission }),
    removeMember: (folderId: string, userId: string) => removeMember.mutateAsync({ folderId, userId }),
    shareRecord: (r: VaultRecord, person: Person, permission: Grant) => share.mutateAsync({ r, person, permission }),
    shareRecordIn: (r: VaultRecord, inOrg: Org, person: Person, permission: Grant) => shareIn.mutateAsync({ r, in: inOrg, person, permission }),
    updateShare: (recordId: string, userId: string, permission: Grant) => updateShare.mutateAsync({ recordId, userId, permission }),
    unshare: (recordId: string, userId: string) => unshare.mutateAsync({ recordId, userId }),
  };
}

/** Active members of the org (the active space's, or an InOrg override's), with their public and membership keys, for the share and member pickers. */
export function usePeople() {
  const org = useScopeOrg();
  const oapi = useOrgApi();
  // Fresh whenever a picker opens: new members, and their current membership keys (what folder keys are sealed to).
  return useQuery({ queryKey: ["people", useScope()], enabled: !!org, queryFn: () => oapi.get<{ users: Person[] }>("/users").then((r) => r.users), staleTime: 0 });
}

export interface ActivityEvent { action: string; at: string; actor: string | null; target: string | null }
export function useRecordActivity(recordId: string, revision: number | string) {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["activity", useScope(), recordId, revision], queryFn: () => oapi.get<{ events: ActivityEvent[] }>(`/records/${recordId}/activity`).then((r) => r.events) });
}
