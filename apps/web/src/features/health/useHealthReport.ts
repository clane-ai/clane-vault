import { useEffect, useMemo, useState } from "react";
import { useOrgPolicies } from "@/lib/policies";
import { useSession } from "@/lib/session";
import { useOrgApi } from "@/lib/scope";
import type { VaultFolder, VaultRecord } from "@/features/vault/types";
import type { PasswordScores } from "@/features/vault/usePasswordScores";
import { healthReport, orgScopedReport, reportPayload } from "./health";
import { breachedRecords, breachOptIn, setBreachOptIn } from "./hibp";

/** The last report posted from this tab (user, org and counts), so the vault and the health page post a change once. */
let lastPosted = "";

/**
 * The password health report for these records (docs/password-health.md), with the opt-in breach check, and its counts
 * posted to the active org whenever they change. Used by the vault (in the background) and the Password health page.
 * `scores`: the passwords' zxcvbn scores (usePasswordScores); nothing is posted while some are still being scored.
 */
export function useHealthReport(records: VaultRecord[], loading: boolean, folders: VaultFolder[], scores: PasswordScores) {
  const { user, org } = useSession();
  const oapi = useOrgApi();
  const allowed = useOrgPolicies().breachCheckAllowed;
  const [optIn, setOptInState] = useState(() => breachOptIn(user?.id));
  const [breached, setBreached] = useState<Set<string> | null>(null);
  const [checking, setChecking] = useState<"idle" | "busy" | "failed">("idle");
  const on = allowed && optIn;

  useEffect(() => {
    if (!on || loading) { setBreached(null); setChecking("idle"); return; }
    let alive = true;
    setChecking("busy");
    breachedRecords(records).then((s) => { if (alive) { setBreached(s); setChecking("idle"); } }).catch(() => { if (alive) { setBreached(null); setChecking("failed"); } });
    return () => { alive = false; };
  }, [on, records, loading]);

  const { isWeak, pending } = scores;
  const report = useMemo(() => healthReport(records, { breached: on ? breached : null, isWeak }), [records, breached, on, isWeak]);
  // Admins get the org's part only: the user's private records stay out of the posted counts.
  const teamIds = useMemo(() => new Set(folders.filter((f) => f.kind === "team").map((f) => f.id)), [folders]);
  const posted = useMemo(() => orgScopedReport(report, records, teamIds), [report, records, teamIds]);

  useEffect(() => {
    if (!org || !user || loading || pending || checking === "busy" || (on && checking !== "failed" && !breached)) return;
    const body = reportPayload(posted);
    const key = `${user.id}:${org.id}:${JSON.stringify(body)}`;
    if (lastPosted === key) return;
    lastPosted = key;
    // Counts and the score only; nothing else about the vault leaves the device.
    void oapi.post("/me/health-report", body).catch(() => { if (lastPosted === key) lastPosted = ""; });
  }, [org, user, posted, loading, pending, checking, on, breached, oapi]);

  const setOptIn = (v: boolean) => { if (user) { setBreachOptIn(user.id, v); setOptInState(v); } };
  return { report, allowed, optIn: on, setOptIn, checking, scoring: pending };
}
