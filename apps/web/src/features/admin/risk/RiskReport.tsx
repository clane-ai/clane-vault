import { createPortal } from "react-dom";
import { pct, SEVERITY_LABEL, trendLabel, type RiskOverview } from "./model";

const STATUS: Record<string, string> = { critical: "Needs action", completed: "Completed", ignored: "Ignored", not_applicable: "Doesn't apply", unknown: "Not visible" };

/**
 * The printable report ("Download report", or the browser's own Print on this page): plain tables in black on white,
 * rendered at the end of <body> only while printing; risk-print.css hides everything else. Save as PDF from the
 * print dialog. No server-side PDF.
 */
export function RiskReport({ d, orgName }: { d: RiskOverview; orgName: string }) {
  const u = d.utilisation, h = d.health;
  const rows: [string, string][] = [
    ["Members with records", `${u.withRecords} of ${u.members} (${pct(u.withRecords, u.members)}%)`],
    ["Signed in within 30 days", `${u.active30d} of ${u.members} (${pct(u.active30d, u.members)}%)`],
    ["Invitations accepted", `${u.invitations.accepted} accepted, ${u.invitations.pending} pending`],
    ["Two-step sign-in", `Required for everyone (100%); ${u.twoFactor.idpMfaSessions} with an IdP MFA session`],
    ["Recovery kit saved", `${u.recoveryKit} of ${u.members} (${pct(u.recoveryKit, u.members)}%)`],
    ["Password health reported (30 days)", `${u.healthReported30d} of ${u.members} (${pct(u.healthReported30d, u.members)}%)`],
  ];
  return createPortal(
    <div className="risk-print" data-testid="risk-print">
      <h1>Security risk report</h1>
      <p>{orgName} · generated {new Date(d.generatedAt).toLocaleString()}</p>
      <h2>Score: {d.score.value} / 100</h2>
      <p>Benchmarks {d.score.benchmarks}/100 ({d.score.counted.earned} of {d.score.counted.possible} weighted points){d.score.health !== null ? `; password health ${d.score.health}/100; score = 70% benchmarks + 30% health` : "; no password health reports yet, score = benchmarks"}.</p>
      <h2>Utilisation</h2>
      <table><tbody>{rows.map(([k, v]) => <tr key={k}><th>{k}</th><td>{v}</td></tr>)}</tbody></table>
      <h2>Security benchmarks</h2>
      <table>
        <thead><tr><th>Status</th><th>Benchmark</th><th>Severity</th><th>Detail</th></tr></thead>
        <tbody>{d.benchmarks.map((b) => <tr key={b.key}><td>{STATUS[b.status]}</td><td>{b.title}</td><td>{SEVERITY_LABEL[b.severity]}</td><td>{b.detail}</td></tr>)}</tbody>
      </table>
      <h2>High-priority alerts (last {d.windowDays} days)</h2>
      <table>
        <thead><tr><th>Alert</th><th>Action</th><th>Last {d.windowDays} days</th><th>Previous</th><th>Trend</th></tr></thead>
        <tbody>{[...d.alerts].sort((a, b) => b.current - a.current).map((a) => <tr key={a.action}><td>{a.label}</td><td>{a.action}</td><td>{a.current}</td><td>{a.previous}</td><td>{trendLabel(a)}</td></tr>)}</tbody>
      </table>
      <h2>Password health</h2>
      <p>{h.reported} of {h.members} members reported. Average score {h.averageScore ?? "—"}; {h.atRisk} at risk. Passwords {h.passwords}: weak {h.weak}, reused {h.reused}, old {h.old}, breached {h.breached ?? "—"}.</p>
    </div>,
    document.body,
  );
}
