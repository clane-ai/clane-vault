import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
// Default: no refresh cookie, so SessionProvider boots to signed_out. Tests override with server.use().
// Recovery defaults: policy off, and the signed-in user already has a kit (so no banner and no escrows unless a test says so).
export const server = setupServer(
  http.post("/api/v1/auth/refresh", () => HttpResponse.json({ error: "session_expired" }, { status: 401 })),
  http.get("/api/v1/auth/recovery/options", () => HttpResponse.json({ adminRecoveryEnabled: false })),
  http.get("/api/v1/me/security", () => HttpResponse.json({ recoveryKit: { createdAt: "2026-01-01T00:00:00.000Z" }, adminRecoveryEnabled: false })),
  http.get("/api/v1/admin/recovery-requests", () => HttpResponse.json({ requests: [] })),
  // Organisations: none by default (tests that need one say so).
  http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [], invitations: [], allowOrgCreation: true, instanceAdmin: false })),
  // Single sign-on: no organisation offers it unless a test says so.
  http.post("/api/v1/auth/sso/discover", () => HttpResponse.json({ orgs: [] })),
  // Groups, policies, password health and the event log (docs/groups.md, docs/policies.md): empty unless a test says so.
  http.get("/api/v1/groups", () => HttpResponse.json({ groups: [] })),
  http.get("/api/v1/group-access/pending", () => HttpResponse.json({ pending: [] })),
  http.get("/api/v1/admin/groups", () => HttpResponse.json({ groups: [] })),
  http.get("/api/v1/admin/settings/policies", () => HttpResponse.json({ policies: { autoLockMinutes: null, minPasswordLength: 12, minPasswordScore: 0, links: { allowed: true, maxExpiryHours: 168, requirePassword: false },
    offlineAllowed: true, extensionAllowed: true, breachCheckAllowed: true, ipAllowlist: [], ownerBreakGlass: true }, changedAt: null, changedBy: null, yourIp: "127.0.0.1" })),
  http.post("/api/v1/me/health-report", () => new HttpResponse(null, { status: 204 })),
  http.get("/api/v1/admin/health", () => HttpResponse.json({ members: [] })),
  http.get("/api/v1/admin/events", () => HttpResponse.json({ events: [], nextBefore: null })),
  http.get("/api/v1/admin/events/actions", () => HttpResponse.json({ actions: [] })),
  // Provisioning (docs/provisioning.md): no invitations, no checklist and domain auto-join off unless a test says so.
  http.get("/api/v1/admin/invites", () => HttpResponse.json({ invites: [], cap: { perDay: 50, sentToday: 0, remaining: 50 }, counts: { pending: 0, expired: 0 }, emailConfigured: false, hostedMode: false })),
  http.get("/api/v1/admin/onboarding", () => HttpResponse.json({ show: false, dismissed: false, done: 0, total: 5, steps: [] })),
  http.get("/api/v1/admin/settings/domain-join", () => HttpResponse.json({ enabled: false, role: "member", groups: [], domains: [], emailConfigured: false, joinUrl: "http://localhost:5173/join", canEdit: true, updatedAt: null, updatedBy: null })),
);
