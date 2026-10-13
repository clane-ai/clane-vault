import type { Match } from "./domain";

export type Permission = "owner" | "edit" | "view" | "use";
/** `policies`: the org's client-side policies (docs/policies.md); older servers send none. */
export interface Org { id: string; name: string; slug: string; role: "owner" | "admin" | "member"; isDefault: boolean; policies?: { autoLockMinutes?: number | null; extensionAllowed?: boolean } }
export type Phase = "setup" | "signed_out" | "locked" | "unlocked";
/** Why the vault can't be shown for the active org: its SSO is required, the session needs a TOTP step-up, or the org turned the extension off. */
export type Blocked = "sso_required" | "totp_step_up_required" | "extension_disabled" | null;

export interface StateView {
  phase: Phase; serverUrl: string | null; webVaultUrl: string | null;
  user: { id: string; email: string; name: string } | null; orgs: Org[]; orgId: string | null;
  /** The idle lock in effect: the user's choice, shortened by any org policy (`autoLockPolicy`). */
  autoLockMinutes: number; autoLockPolicy: number | null; saveOffers: boolean; lastEmail: string; blocked: Blocked;
}

/** What the popup sees of an item: never a password or TOTP secret. */
export interface ItemView {
  id: string; title: string; username?: string; url?: string; host?: string; folder: string | null;
  permission: Permission; hasPassword: boolean; hasTotp: boolean; match: Match;
}

/** Messages from the popup (trusted extension page). */
export type PopupMessage =
  | { type: "state" }
  | { type: "setServer"; url: string }
  | { type: "signIn"; email: string; password: string; code?: string }
  | { type: "unlock"; password: string }
  | { type: "lock" }
  | { type: "signOut" }
  /** `orgId` null (or ""): the Personal space. */
  | { type: "switchOrg"; orgId: string | null }
  | { type: "stepUp"; code: string }
  | { type: "items"; pageUrl?: string }
  | { type: "copy"; id: string; field: "username" | "password" | "totp" }
  /** `confirm` + `origin`: the user's "Fill anyway" for that page origin (from the confirm response). */
  | { type: "fill"; id: string; tabId: number; confirm?: "mismatch" | "insecure" | "both"; origin?: string }
  | { type: "settings"; autoLockMinutes?: number; saveOffers?: boolean }
  | { type: "copied" };

/** Messages from the content script (untrusted page context: values only go in, never secrets out). */
export type ContentMessage =
  | { type: "login.submitted"; username: string; password: string }
  | { type: "prompt.pending" }
  | { type: "prompt.answer"; action: "save" | "update" | "never" | "dismiss" };

export type SignInResult =
  | { ok: true }
  | { ok: false; error: string; retryAfterSeconds?: number };

export type FillResponse =
  | { ok: true }
  | { ok: false; confirm: "mismatch" | "insecure" | "both"; pageHost: string; pageOrigin: string; itemHost: string | null }
  | { ok: false; error: string };

export interface PromptView { kind: "save" | "update"; host: string; username: string }

export const POPUP_SOURCE = "popup";
