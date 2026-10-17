import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession } from "@/lib/session";
import { useOrgApi, useScope } from "@/lib/scope";
import { pinKey, pinStatus, sealFolderKeyTo, type Recipient } from "@/lib/orgKeys";
import type { Grant, Person, VaultFolder } from "@/features/vault/types";

/** A group of the active org with its active members' keys (any member can read them, to share a folder). */
export interface OrgGroup { id: string; name: string; members: Person[] }
/** Admin view: every member (any status), and how many live folders it is shared with. */
export interface AdminGroup { id: string; name: string; createdAt: string; folderCount: number; members: { id: string; name: string; email: string }[] }
/**
 * A group member waiting for the key of a folder I can seal (owner or editor), for explicit approval: which groups give
 * the access, and who added them to each (docs/groups.md). `declined`: a key holder said no.
 */
export interface GroupPending {
  folderId: string; userId: string; name: string; email: string; publicKey: string; membershipKey: string | null; permission: Grant; groups: string[]; declined: boolean;
  via: { groupId: string; groupName: string; addedBy: { id: string; name: string } | null }[];
}

export function useOrgGroups(enabled = true) {
  const { org } = useSession();
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["groups", useScope()], enabled: enabled && !!org, queryFn: () => oapi.get<{ groups: OrgGroup[] }>("/groups").then((r) => r.groups), staleTime: 30_000 });
}

export function useAdminGroups() {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["admin-groups", useScope()], queryFn: () => oapi.get<{ groups: AdminGroup[] }>("/admin/groups").then((r) => r.groups) });
}

/**
 * Seals a folder key to each person's key in this org (copying the folder key first, so a lock mid-way never seals zeros).
 * `accepted`: the user approved these people with their fingerprints and key-change warnings in view, so a changed key is
 * re-pinned. Otherwise a person whose key changed is skipped: with no wrap they wait in the approval queue, which warns.
 */
async function sealAll(orgId: string, folder: VaultFolder, people: Recipient[], assertOpen: () => void, me?: string, accepted = false) {
  if (!folder.folderKey) throw new Error("This folder's key isn't available");
  const fk = folder.folderKey.slice();
  try {
    const out: { userId: string; wrappedFolderKey: string; sealedTo: string | null }[] = [];
    for (const p of people) {
      if (me && !accepted && pinStatus(me, orgId, p.id, p.membershipKey, p.publicKey).status === "changed") continue;
      out.push({ userId: p.id, ...(await sealFolderKeyTo(fk, { orgId, folderId: folder.id }, p)) });
      if (me) pinKey(me, orgId, p.id, p.membershipKey, p.publicKey);
      assertOpen();
    }
    return out;
  } finally { fk.fill(0); }
}

/** Sharing a team folder with groups: add (seals to the group's current members), change permission, stop. */
export function useFolderGroups() {
  const { generation, org, user } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const done = () => Promise.all([qc.invalidateQueries({ queryKey: ["vault"] }), qc.invalidateQueries({ queryKey: ["group-pending"] })]);
  const guard = () => { const g = generation(); return () => { if (generation() !== g) throw new Error("Vault locked"); }; };
  const add = useMutation({ mutationFn: async (v: { folder: VaultFolder; group: OrgGroup; permission: Grant }) => {
    const wraps = await sealAll(org!.id, v.folder, v.group.members, guard(), user?.id);
    return oapi.post<{ added: number; pending: number }>(`/folders/${v.folder.id}/groups`, { groupId: v.group.id, permission: v.permission, wraps });
  }, onSettled: done });
  const update = useMutation({ mutationFn: (v: { folderId: string; groupId: string; permission: Grant }) => oapi.patch(`/folders/${v.folderId}/groups/${v.groupId}`, { permission: v.permission }), onSettled: done });
  const remove = useMutation({ mutationFn: (v: { folderId: string; groupId: string }) => oapi.del(`/folders/${v.folderId}/groups/${v.groupId}`), onSettled: done });
  return {
    add: (folder: VaultFolder, group: OrgGroup, permission: Grant) => add.mutateAsync({ folder, group, permission }),
    update: (folderId: string, groupId: string, permission: Grant) => update.mutateAsync({ folderId, groupId, permission }),
    remove: (folderId: string, groupId: string) => remove.mutateAsync({ folderId, groupId }),
  };
}

/**
 * Group members waiting for the key of a team folder I own or edit (docs/groups.md). Never sealed automatically: a
 * key holder approves each person explicitly (seeing who it is, through which group and who added them), or declines.
 * Only polls when such a folder is shared with a group.
 */
export function useGroupAccess(folders: VaultFolder[]) {
  const { org, user, generation } = useSession();
  const oapi = useOrgApi();
  const qc = useQueryClient();
  const holders = folders.filter((f) => f.kind === "team" && !f.deleted && f.folderKey && (f.myPermission === "owner" || f.myPermission === "edit") && (f.groups?.length ?? 0) > 0);
  const q = useQuery({ queryKey: ["group-pending", useScope()], enabled: !!org && holders.length > 0, refetchInterval: 60_000, staleTime: 15_000,
    queryFn: () => oapi.get<{ pending: GroupPending[] }>("/group-access/pending").then((r) => r.pending) });
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ["vault"] }), qc.invalidateQueries({ queryKey: ["group-pending"] })]);
  const approve = useMutation({ mutationFn: async (v: { folderId: string; people: GroupPending[] }) => {
    const folder = holders.find((f) => f.id === v.folderId);
    if (!folder) throw new Error("This folder's key isn't available");
    const gen = generation();
    const wraps = await sealAll(org!.id, folder, v.people.map((p) => ({ id: p.userId, publicKey: p.publicKey, membershipKey: p.membershipKey })), () => { if (generation() !== gen) throw new Error("Vault locked"); }, user?.id, true);
    return oapi.post<{ added: string[]; skipped: number }>(`/folders/${v.folderId}/group-access`, { wraps });
  }, onSettled: refresh });
  const decline = useMutation({ mutationFn: (v: { folderId: string; userIds: string[] }) => oapi.post<{ declined: number }>(`/folders/${v.folderId}/group-access/decline`, { userIds: v.userIds }), onSettled: refresh });
  const holderIds = new Set(holders.map((f) => f.id));
  return {
    pending: (q.data ?? []).filter((p) => holderIds.has(p.folderId)),
    approve: (folderId: string, people: GroupPending[]) => approve.mutateAsync({ folderId, people }),
    decline: (folderId: string, userIds: string[]) => decline.mutateAsync({ folderId, userIds }),
  };
}
