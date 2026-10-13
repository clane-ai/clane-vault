import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useOrgApi, useScope } from "@/lib/scope";
import { useSession } from "@/lib/session";
import { useOrgsInfo } from "@/features/orgs/orgs";

/** GET /admin/storage: the active org's file storage (docs/attachments.md). Never a file name or type. */
export interface OrgStorage {
  enabled: boolean; used: number; quota: number; files: number;
  limits: { maxFileMb: number; serverMaxFileMb: number; maxPerRecord: number; maxRecordMb: number };
  policy: { allowed: boolean; maxFileMb: number | null; previews: boolean; linksAllowAttachments: boolean };
  members: { userId: string; name: string; email: string; files: number; bytes: number }[];
  largest: { recordId: string; ownerId: string; ownerName: string; folderId: string | null; files: number; bytes: number }[];
}

/** GET /admin/instance/storage: the server's (instance admins). */
export interface InstanceStorage {
  enabled: boolean; backend: "db" | "s3"; s3: { bucket: string; prefix: string; endpoint?: string } | null;
  used: number; quota: number; warn: boolean;
  quotas: { orgMb: number; userMb: number; instanceMb: number; dailyUploadMb: number; maxFileMb: number };
  perOrg: { orgId: string; name: string; files: number; bytes: number; quota: number }[]; personal: { files: number; bytes: number };
  rows: { db: number; s3: number; uploading: number; pendingDelete: number }; tombstones: number;
  gc: { at: string; abandoned: number; deleted: number; tombstones: number; failures: number; orphanPassAt: string | null; orphansFound: number } | null;
  backup: { chunkDataExcluded: boolean; lastSuccess: { startedAt: string; bytes: number | null; attachmentBytes: number | null } | null };
}

export function useOrgStorage() {
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["admin-storage", useScope()], queryFn: () => oapi.get<OrgStorage>("/admin/storage") });
}

export const INSTANCE_STORAGE_KEY = ["admin-instance-storage"] as const;
export function useInstanceStorage(opts: { enabled?: boolean } = {}) {
  const { user } = useSession();
  const instanceAdmin = !!useOrgsInfo().data?.instanceAdmin;
  return useQuery({ queryKey: [...INSTANCE_STORAGE_KEY, user?.id ?? ""], enabled: !!user && instanceAdmin && opts.enabled !== false, staleTime: 5 * 60_000,
    queryFn: () => api.get<InstanceStorage>("/admin/instance/storage") });
}

/** Used share of a quota, 0–100. */
export const usedPercent = (used: number, quota: number) => (quota > 0 ? Math.min(100, Math.round((100 * used) / quota)) : 0);
