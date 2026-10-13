import { useMemo } from "react";
import type { VaultView } from "@/features/vault/filter";
import { adminPath, findOrg, folderPath, listPath, ORG_VIEWS, PERSONAL_VIEWS, recordPath, spacePrefix, spaceOf, type AdminSection, type PathContext } from "./paths";
import { useSession, type Org } from "./session";

/** The org whose admin pages old /admin/... links open from Personal: one the user administers, else the first. */
export function adminOrgOf(org: Org | null, orgs: Org[]): Org | null {
  return org ?? orgs.find((o) => o.role !== "member") ?? orgs[0] ?? null;
}

/**
 * What a pathname asks for, against the user's orgs: undefined when it names no space (Settings, Server, old paths),
 * null for Personal, the org, or "unknown" for an org reference that isn't one of the user's orgs (deleted, left, never
 * a member: all look the same).
 */
export function wantedSpace(pathname: string, orgs: Org[]): Org | null | "unknown" | undefined {
  const s = spaceOf(pathname);
  if (!s) return undefined;
  if (s.kind === "personal") return null;
  return findOrg(orgs, s.ref) ?? "unknown";
}

/** URLs in the active space (lib/paths), for links and navigation. */
export function useSpacePaths() {
  const { org, orgs } = useSession();
  return useMemo(() => {
    const prefix = spacePrefix(org);
    const adminOrg = adminOrgOf(org, orgs);
    const ctx: PathContext = { space: prefix, adminOrg: adminOrg ? spacePrefix(adminOrg) : null };
    return {
      prefix, ctx, personal: !org,
      /** The lists this space has (Personal has no "Shared with me"). */ views: org ? ORG_VIEWS : PERSONAL_VIEWS,
      list: (v: VaultView) => listPath(prefix, v),
      record: (v: VaultView, id: string) => recordPath(prefix, v, id),
      folder: (id: string | null) => folderPath(prefix, id),
      /** An admin page of the active org (server sections: /server/...). */
      admin: (section?: AdminSection | null, detailId?: string | null) => adminPath(org ? prefix : null, section, detailId),
      /** Another space's vault. */
      vaultOf: (o: Org | null) => `${spacePrefix(o)}/vault`,
    };
  }, [org, orgs]);
}
