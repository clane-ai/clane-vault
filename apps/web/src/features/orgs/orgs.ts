import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { spacePrefix } from "@/lib/paths";
import { api } from "@/lib/api";
import { useSession, type Org, type OrgRole } from "@/lib/session";
import { useOrgApi } from "@/lib/scope";
import type { PasswordPolicy } from "@/lib/policies";

/** An invitation to an organisation, for someone who already has an account. */
/** `passwordPolicy`: the org's master password rule, checked before accepting (docs/policies.md). */
export interface Invitation { orgId: string; orgName: string; role: OrgRole; invitedBy: string | null; invitedAt: string; passwordPolicy?: PasswordPolicy }
/** `hostedMode`: invite links are only ever emailed (never shown to admins). */
export interface OrgsInfo { orgs: Org[]; invitations: Invitation[]; allowOrgCreation: boolean; instanceAdmin: boolean; hostedMode?: boolean }
export interface OrgDetails {
  id: string; name: string; slug: string; createdAt: string; isDefault: boolean; myRole: OrgRole;
  memberCount: number; teamFolderCount: number; owner: { id: string; name: string } | null; logoVersion?: string | null;
}

export const ORGS_KEY = "me-orgs";
export const ROLE_LABEL: Record<OrgRole, string> = { owner: "Owner", admin: "Admin", member: "Member" };

/**
 * The caller's organisations, pending invitations, whether they may create one and whether they're an instance admin.
 * Polls, so an invitation or a removal shows up without a reload; a changed list updates the session (and the
 * active org, if it went away).
 */
export function useOrgsInfo() {
  const { user, applyOrgs } = useSession();
  const q = useQuery({ queryKey: [ORGS_KEY, user?.id ?? ""], queryFn: () => api.get<OrgsInfo>("/me/orgs"), enabled: !!user, staleTime: 30_000, refetchInterval: 60_000 });
  useEffect(() => { if (q.data && applyOrgs) applyOrgs(q.data.orgs); }, [q.data, applyOrgs]);
  return q;
}

/**
 * Re-reads the org list. `open`: then go to that org's vault (a new or just-joined org), or to Personal (null: after
 * leaving or deleting the active org). The URL decides the space, so this navigates (lib/paths).
 */
export function useReloadOrgs() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { user, applyOrgs } = useSession();
  return async (open?: string | null) => {
    const info = await api.get<OrgsInfo>("/me/orgs");
    qc.setQueryData([ORGS_KEY, user?.id ?? ""], info);
    applyOrgs(info.orgs);
    if (open !== undefined) navigate(`${spacePrefix(open ? info.orgs.find((o) => o.id === open) : null)}/vault`);
    return info;
  };
}

/** Details of the active org (Organisation settings). */
export function useOrgDetails() {
  const { org, user } = useSession();
  const oapi = useOrgApi();
  return useQuery({ queryKey: ["org", user?.id ?? "", org?.id ?? "-"], queryFn: () => oapi.get<OrgDetails>("/org"), enabled: !!org });
}
