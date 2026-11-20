import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  agentUpdateMessage, b64url, CryptoError, decryptRecordBody, encryptFolderAgents, encryptFolderName, encryptNewRecord, encryptRecordBody, randomBytes, sealPersonalAgentRecordKey, sealRevealStub, serverRecordType,
  sha256B64, verifyGatewayMessage, wrapKey,
  type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
import { toast } from "sonner";
import { ApiError, forOrg } from "@/lib/api";
import { useSession, type Org } from "@/lib/session";
import { useOrgApi, useScope, useScopeOrg } from "@/lib/scope";
import { dropSync, loadSync, orgKey, saveSync } from "@/lib/offline";
import {
  assertPinned, ensureGatewayPinned, isAgent, KeyChangedError, myMembershipKey, PERSONAL_SLOT, pinKey, pinnedGateway, pinStatus, sealFolderKeyTo, sealShareTo, verifyPersonalAgentKey,
} from "@/lib/orgKeys";
import type { MyAgent, MyAgents } from "@/features/settings/myAgents";
import { decryptSync } from "./decrypt";
import type { FolderMember, Grant, Permission, Person, SyncResponse, VaultFolder, VaultRecord } from "./types";

export class ConflictError extends Error { constructor() { super("Someone else changed this record. We loaded their version."); } }
/** Restore previous: the overwrite's body is under a record key that was rotated since (overwrites outlive a rotation). */
export class OverwriteKeyError extends Error { constructor() { super("The previous version can't be opened any more: this item's key changed after the agent's change."); } }

/** *Changed by agent*: whether the pinned personal gateway signed `agent-update:<me>:<agent>:<id>:<revision>:<sha256(encBody)>` for the current body. */
async function agentChangeSigned(me: string, r: SyncResponse["records"][number]): Promise<boolean | null> {
  const gw = pinnedGateway(me, PERSONAL_SLOT);
  if (!gw || !r.agentChange) return null;
  const message = agentUpdateMessage({ ownerUserId: me, agentId: r.agentChange.agentId, id: r.id, revision: r.revision, encBodyHash: await sha256B64(r.encBody) });
  return verifyGatewayMessage(r.agentChange.signature, "u1", message, gw);
}

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
      const out = { ...(await decryptSync(sync, k, user?.id, org?.id ?? null)), privateLocked: !!sync.privateLocked, savedAt, agentInbox: sync.agentInbox };
      // Changed by agent (Personal, records I own): checked against this device's gateway pin, never taken on the server's word.
      if (!org && user) for (const sr of sync.records) {
        if (!sr.agentChange || sr.ownerId !== user.id) continue;
        const rec = out.records.find((x) => x.id === sr.id);
        if (rec) rec.agentChange = { ...sr.agentChange, signed: await agentChangeSigned(user.id, sr) };
      }
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
          await grantFolderAgents(input.folderId, { id, recordKey: enc.recordKey });
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
    // A renamed item: its *Can reveal* stubs carry the title the agent lists, so they are sealed again (best effort).
    if (v.body.title !== v.r.body?.title || v.body.type !== v.r.body?.type) {
      const mine = user ? qc.getQueryData<MyAgents>(["my-agents", user.id])?.agents ?? [] : [];
      for (const g of v.r.agentGrants ?? []) {
        const a = g.reveal?.length ? mine.find((x) => x.id === g.agentId) : undefined;
        if (a) await sealStub(v.r.id, v.body, a, g.reveal!).catch(() => undefined);
      }
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
    await oapi.put(`/records/${v.r.id}/folder`, { folderId: v.folderId, ownerWrappedRecordKey });
    await grantFolderAgents(v.folderId, v.r);
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
    if (!user) throw new Error("Not signed in");
    for (const { person, permission } of people) {
      await toRecipient(person, async (p) => {
        assertPinned(user.id, org.id, p);
        if (isAgent(p)) await ensureGatewayPinned(oapi, user.id, org.id);
        const sealed = await sealFolderKeyTo(folderKey, { orgId: org.id, folderId }, p, user.id);
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
        const sealed = await sealFolderKeyTo(folderKey, { orgId: org.id, folderId: id }, me, user!.id);
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
    if (!user) throw new Error("Not signed in");
    return withSecret(v.folder.folderKey, "folder", async (fk, assertOpen) => {
      // Agent fields go along: sealing checks an agent's attestation (ruling R41).
      const m = v.member;
      const to = { id: m.userId, publicKey: m.publicKey, membershipKey: m.membershipKey ?? null, kind: m.kind, email: m.email, attestation: m.attestation, gatewayKeyId: m.gatewayKeyId };
      if (isAgent(to)) await ensureGatewayPinned(oapi, user.id, org.id);
      const sealed = await sealFolderKeyTo(fk, { orgId: org.id, folderId: v.folder.id }, to, user.id);
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
      if (!user) throw new Error("Not signed in");
      return toRecipient(v.person, async (p) => {
        assertPinned(user.id, org.id, p);
        if (isAgent(p)) await ensureGatewayPinned(oapi, user.id, org.id);
        const sealed = await sealShareTo(rk, { orgId: org.id, recordId: v.r.id }, p, user.id);
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
      if (!user) throw new Error("Not signed in");
      const send = async (p: Person) => {
        assertPinned(user.id, v.in.id, p);
        if (isAgent(p)) await ensureGatewayPinned(there, user.id, v.in.id);
        const sealed = await sealShareTo(rk, { orgId: v.in.id, recordId: v.r.id }, p, user.id);
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

  /**
   * Personal space: gives one of my records to one of my personal agents ("use"). Nothing is sealed unless the agent's key
   * is attested by the pinned gateway and bound to my current account key, and it is the key this device pinned for it.
   */
  async function sealGrant(r: Pick<VaultRecord, "id" | "recordKey">, a: MyAgent) {
    if (!user) throw new Error("Not signed in");
    if (pinStatus(user.id, PERSONAL_SLOT, a.id, a.publicKey).status === "changed") throw new KeyChangedError(a.id);
    const pinned = await ensureGatewayPinned(oapi, user.id, PERSONAL_SLOT, "/me/agents/gateway");
    const wrappedRecordKey = await withKey((k) => withSecret(r.recordKey, "record", async (rk, assertOpen) => {
      await verifyPersonalAgentKey(user.id, a, a.owner, k.privateKey);
      const sealed = await sealPersonalAgentRecordKey(rk, { ownerUserId: user.id, agentId: a.id, recordId: r.id }, b64url.decode(a.publicKey));
      assertOpen();
      return sealed;
    }));
    await oapi.post(`/records/${r.id}/agent-grants`, { agentId: a.id, wrappedRecordKey });
    pinKey(user.id, PERSONAL_SLOT, a.id, a.publicKey);
    return pinned; // pinnedNow: the caller shows the gateway's fingerprint (trust on first use)
  }
  const grantAgent = useMutation({ mutationFn: (v: { r: VaultRecord; agent: MyAgent }) => sealGrant(v.r, v.agent), ...after });
  /**
   * A record saved into a Personal folder given to agents (Give to agent… on the folder): each of them gets Can use, as a
   * single grant. The save already went through, so a grant that fails is reported, not thrown.
   */
  async function grantFolderAgents(folderId: string | null, r: Pick<VaultRecord, "id" | "recordKey" | "agentGrants">) {
    const ids = org ? [] : folderById(folderId)?.agentIds ?? [];
    const mine = ids.length && user ? qc.getQueryData<MyAgents>(["my-agents", user.id])?.agents ?? [] : [];
    for (const id of ids) {
      const a = mine.find((x) => x.id === id && x.status === "active");
      if (!a || r.agentGrants?.some((g) => g.agentId === id && g.use)) continue;
      await sealGrant(r, a).catch(() => toast.error(`Saved, but couldn't give it to ${a.name}. Give it from Share.`));
    }
  }
  /** Personal folders: the agents it is given to, sealed under my user key (none: cleared). */
  const setFolderAgents = useMutation({ mutationFn: (v: { folderId: string; agentIds: string[] }) => withKey(async (k, assertOpen) => {
    const encAgents = v.agentIds.length ? await encryptFolderAgents(v.folderId, v.agentIds, k.userKey) : null;
    assertOpen();
    return oapi.patch(`/folders/${v.folderId}`, { encAgents });
  }), ...after });
  /** *Can reveal*: { title, type, fields } sealed to the agent (its key checked as for a grant); the agent gets no record key. */
  async function sealStub(recordId: string, body: RecordBody, a: MyAgent, fields: string[]) {
    if (!user) throw new Error("Not signed in");
    if (pinStatus(user.id, PERSONAL_SLOT, a.id, a.publicKey).status === "changed") throw new KeyChangedError(a.id);
    const pinned = await ensureGatewayPinned(oapi, user.id, PERSONAL_SLOT, "/me/agents/gateway");
    const sealedStub = await withKey(async (k) => {
      await verifyPersonalAgentKey(user.id, a, a.owner, k.privateKey);
      return sealRevealStub({ title: body.title, type: body.type, fields }, { ownerUserId: user.id, agentId: a.id, recordId }, b64url.decode(a.publicKey));
    });
    await oapi.put(`/records/${recordId}/agent-reveal/${a.id}`, { sealedStub, fields: [...fields].sort() });
    pinKey(user.id, PERSONAL_SLOT, a.id, a.publicKey);
    return pinned;
  }
  const setAgentReveal = useMutation({ mutationFn: (v: { r: VaultRecord; agent: MyAgent; fields: string[] }) => {
    if (!v.r.body) throw new Error("This record can't be opened");
    return sealStub(v.r.id, v.r.body, v.agent, v.fields);
  }, ...after });
  const revokeAgentReveal = useSimple((v: { recordId: string; agentId: string }) => oapi.del(`/records/${v.recordId}/agent-reveal/${v.agentId}`));
  const revokeAgentGrant = useSimple((v: { recordId: string; agentId: string }) => oapi.del(`/records/${v.recordId}/agent-grants/${v.agentId}`));
  const setAgentWrite = useSimple((v: { recordId: string; agentId: string; write: boolean }) => oapi.patch(`/records/${v.recordId}/agent-grants/${v.agentId}`, { write: v.write }));
  /** Restore previous: the body before the agent's change, opened with the record key and saved as any edit (a stale revision is a ConflictError). */
  async function restorePrevious(r: VaultRecord) {
    await updateRecord.mutateAsync({ r, body: await previousBody(r) });
    await ackAgentChange(r.id).catch(() => undefined); // the save already hides it; the ack keeps the server's list clean
  }
  /** The body before the agent's current change (GET agent-overwrites), opened with the record key. */
  async function previousBody(r: VaultRecord): Promise<RecordBody> {
    const { overwrites } = await oapi.get<{ overwrites: { prevEncBody: string; newRevision: number }[] }>(`/records/${r.id}/agent-overwrites`);
    const o = overwrites.find((x) => x.newRevision === r.revision);
    if (!o) throw new ConflictError();
    return withSecret(r.recordKey, "record", (rk) => decryptRecordBody(r.id, o.prevEncBody, rk)).catch((e: unknown) => { throw e instanceof CryptoError ? new OverwriteKeyError() : e; });
  }
  /** The owner has seen the agent's change (Looks right, or after Restore previous): the server stops listing it. */
  async function ackAgentChange(recordId: string) {
    await oapi.post(`/records/${recordId}/agent-overwrites/ack`);
    await refetch();
  }

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
    grantAgent: (record: VaultRecord, agent: MyAgent) => grantAgent.mutateAsync({ r: record, agent }),
    setFolderAgents: (folderId: string, agentIds: string[]) => setFolderAgents.mutateAsync({ folderId, agentIds }),
    revokeAgentGrant: (recordId: string, agentId: string) => revokeAgentGrant.mutateAsync({ recordId, agentId }),
    setAgentWrite: (recordId: string, agentId: string, write: boolean) => setAgentWrite.mutateAsync({ recordId, agentId, write }),
    setAgentReveal: (record: VaultRecord, agent: MyAgent, fields: string[]) => setAgentReveal.mutateAsync({ r: record, agent, fields }),
    revokeAgentReveal: (recordId: string, agentId: string) => revokeAgentReveal.mutateAsync({ recordId, agentId }),
    restorePrevious, previousBody,
    ackAgentChange,
    /** Personal space: deposits waiting in From agents (absent with personal agents off, or private-locked). */ agentInbox: q.data?.agentInbox,
  };
}

/** Active members of the org (the active space's, or an InOrg override's), with their public and membership keys, for the share and member pickers. */
export function usePeople(enabled = true) {
  const org = useScopeOrg();
  const oapi = useOrgApi();
  // Fresh whenever a picker opens: new members, and their current membership keys (what folder keys are sealed to).
  return useQuery({ queryKey: ["people", useScope()], enabled: enabled && !!org, queryFn: () => oapi.get<{ users: Person[] }>("/users").then((r) => r.users), staleTime: 0 });
}

export interface ActivityEvent { action: string; at: string; actor: string | null; target: string | null }
export function useRecordActivity(recordId: string, revision: number | string) {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["activity", useScope(), recordId, revision], queryFn: () => oapi.get<{ events: ActivityEvent[] }>(`/records/${recordId}/activity`).then((r) => r.events) });
}
