import { createContext, createElement, useContext, useMemo, type ReactNode } from "react";
import { forOrg, type OrgApi } from "./api";
import { useSession, type Org } from "./session";

/**
 * A subtree working in another org than the active space: the Personal space's share sheet shares a private record
 * inside an organisation the user picks, so its people picker and requests talk to that org.
 */
const OrgOverride = createContext<Org | null>(null);
export function InOrg({ org, children }: { org: Org; children: ReactNode }) {
  return createElement(OrgOverride.Provider, { value: org }, children);
}

/** The org this component works in: an InOrg override, else the active space's org (null: Personal). */
export function useScopeOrg(): Org | null {
  const over = useContext(OrgOverride);
  const { org } = useSession();
  return over ?? org;
}

/** Cache scope for space-scoped queries: the user and the org ("-": Personal), so nothing is ever shared across spaces. */
export function useScope(): string {
  const s = useSession();
  const org = useScopeOrg();
  return `${s.user?.id ?? ""}:${org?.id ?? "-"}`;
}

/**
 * API calls pinned to the org this component renders for: a mutation or query started in org A sends X-Org-Id A
 * even if the user switches space before it finishes (Personal: no header).
 */
export function useOrgApi(): OrgApi {
  const org = useScopeOrg()?.id ?? null;
  return useMemo(() => forOrg(org), [org]);
}
