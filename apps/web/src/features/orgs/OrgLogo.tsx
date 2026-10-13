import { useQuery } from "@tanstack/react-query";
import { UserRound } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { initials } from "@/features/vault/people";

/**
 * An organisation's logo as a blob URL (docs/branding.md). The server gives it to the org's members only, so it is
 * fetched with the bearer token (an <img> can't send it). Keyed by version (a hash of the bytes): a new upload is a
 * new URL, never stale, and the cache holds nothing tied to an org id (org-scoped caches are dropped on a switch).
 * Null while loading, when there's no logo, or when it can't be fetched (callers show the initials).
 */
export function useOrgLogoUrl(orgId: string | null | undefined, version: string | null | undefined): string | null {
  const q = useQuery({
    queryKey: ["org-logo", version ?? ""],
    enabled: !!orgId && !!version,
    staleTime: Infinity, gcTime: 30 * 60_000, retry: false,
    queryFn: async () => {
      const blob = await api.blob(`/orgs/${orgId}/logo?v=${encodeURIComponent(version!)}`);
      // Only an image the browser should draw: anything else is ignored.
      return blob && /^image\/(png|jpeg|webp)$/.test(blob.type) ? URL.createObjectURL(blob) : null;
    },
  });
  return (orgId && version && q.data) || null;
}

/**
 * The org's square avatar: its logo when it has one, else its initials (a person for the Personal space: no org).
 * `tone`: the dark sidebar or a light menu.
 */
export function OrgAvatar({ org, size = 28, tone = "dark", className }: {
  org: { id: string; name: string; logoVersion?: string | null } | null | undefined; size?: number; tone?: "dark" | "light"; className?: string;
}) {
  const url = useOrgLogoUrl(org?.id, org?.logoVersion);
  const box = cn("grid shrink-0 place-items-center overflow-hidden rounded-[7px] font-display font-semibold", className);
  const style = { width: size, height: size, fontSize: Math.max(9, Math.round(size * 0.39)) };
  if (url) return <span aria-hidden="true" data-testid="org-logo" className={cn(box, tone === "dark" ? "bg-white" : "bg-card ring-1 ring-border-default")} style={style}>
    <img src={url} alt="" className="size-full object-contain" />
  </span>;
  return <span aria-hidden="true" className={cn(box, tone === "dark" ? "bg-orange-500/20 text-[var(--text-on-dark)]" : "bg-well text-text-secondary")} style={style}>
    {org ? initials(org.name) : <UserRound className="size-3.5" />}
  </span>;
}
