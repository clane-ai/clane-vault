/** Shapes of the provisioning API (docs/provisioning.md) and the words the UI uses for them. */

export type BulkStatus = "valid" | "invited" | "invalid_email" | "invalid_role" | "unknown_group" | "duplicate" | "member" | "already_invited" | "cooldown" | "over_cap" | "seat_limit" | "failed";
export interface BulkRow { row: number; email: string; name: string | null; role: string; groups: string[]; status: BulkStatus; detail?: string; emailed?: boolean; inviteUrl?: string }
export interface InviteCap { perDay: number; sentToday: number; remaining: number }
export interface BulkResponse { dryRun: boolean; counts: Partial<Record<BulkStatus, number>>; cap: InviteCap; results: BulkRow[] }

export interface PendingInvite {
  id: string; email: string; role: string; source: "admin" | "domain" | string; groups: { id: string; name: string }[];
  createdAt: string; expiresAt: string; expired: boolean; lastSentAt: string | null; resendCount: number; invitedBy: { id: string; name: string } | null;
}
export interface InvitesResponse { invites: PendingInvite[]; cap: InviteCap; counts: { pending: number; expired: number }; emailConfigured: boolean; hostedMode: boolean }
export interface ResendResponse { id: string; email: string; emailed: boolean; inviteUrl?: string }
export interface ResendAllResponse { resent: number; skipped: number; results: { id: string; email: string; status: string; emailed?: boolean; inviteUrl?: string }[]; cap: InviteCap }

export const STATUS_LABEL: Record<BulkStatus, { label: string; tone: "neutral" | "green" | "orange" | "red" | "blue" }> = {
  valid: { label: "Ready", tone: "green" },
  invited: { label: "Invited", tone: "green" },
  invalid_email: { label: "Invalid address", tone: "red" },
  invalid_role: { label: "Invalid role", tone: "red" },
  unknown_group: { label: "Unknown group", tone: "red" },
  duplicate: { label: "Duplicate", tone: "neutral" },
  member: { label: "Already a member", tone: "neutral" },
  already_invited: { label: "Already invited", tone: "neutral" },
  cooldown: { label: "Declined recently", tone: "orange" },
  over_cap: { label: "Over today's limit", tone: "orange" },
  seat_limit: { label: "No seat left", tone: "orange" },
  failed: { label: "Failed", tone: "red" },
};

export const ONBOARDING_KEY = "admin-onboarding";
export const INVITES_KEY = "admin-invites";
