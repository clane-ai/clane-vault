import type { RecordBody } from "@clane-vault/crypto";

export type Permission = "owner" | "edit" | "view" | "use";
/** Permissions that can be granted to someone else ("owner" is the creator's alone). */
export type Grant = "edit" | "view" | "use";
/** `permission` is effective (the highest of the direct grant and group grants); `directPermission` null: access only through groups. */
/**
 * `membershipKey`: the member's current membership key in this org (what to seal to; null: none yet, their account key).
 * `needsAccess`: their copy of the folder key was sealed to a key they lost (account reset): a key holder gives it again.
 */
export interface FolderMember {
  userId: string; name: string; email: string; publicKey: string; membershipKey?: string | null; needsAccess?: boolean; permission: Permission; directPermission?: Permission | null;
  /** Agents (use only): the gateway's attestation of their key, checked before sealing (lib/orgKeys verifyAgentKey). */ kind?: "person" | "agent"; attestation?: string | null; gatewayKeyId?: string | null;
}
/** A group a team folder is shared with (docs/groups.md). */
export interface FolderGroupGrant { id: string; name: string; permission: Grant; memberIds: string[] }
export interface ShareInfo { userId: string; name: string; permission: Permission; needsAccess?: boolean }
/** `membershipKey`: their membership key in the active org (docs/design/2026-10-08-per-org-keypairs.md). */
export interface Person {
  id: string; name: string; email: string; publicKey: string; membershipKey?: string | null;
  /** Agents (use only): the gateway's attestation of their key, checked before sealing (lib/orgKeys verifyAgentKey). */ kind?: "person" | "agent"; attestation?: string | null; gatewayKeyId?: string | null;
}

export interface SyncFolder {
  id: string; kind: "private" | "team"; encName: string; ownerId?: string; deletedAt: string | null;
  /** Team folders only. */ wrappedFolderKey?: string; myPermission?: Permission; members?: FolderMember[]; groups?: FolderGroupGrant[];
  /** The key my copy is sealed to: null = my account key, else a membership public key (or "acct:…" after a reset). */ sealedTo?: string | null;
}
/**
 * The coarse type the server keeps (docs/record-types.md): "login" or "item"; "note" on rows from before record types.
 * The real type is `body.type`.
 */
export type ServerRecordKind = "login" | "item" | "note";
/**
 * A file on a record (docs/attachments.md) as the server sends it: ciphertext metadata and facts the server knows.
 * `wrappedFileKey` and `nonceBase` are absent for "use only" holders (they can't download).
 */
export interface SyncAttachment {
  id: string; encMeta: string; wrappedFileKey?: string; nonceBase?: string; size: number; chunkSize: number; chunkCount: number;
  createdBy: string; createdByName: string; createdAt: string;
}
export interface SyncRecord {
  id: string; folderId: string | null; type: ServerRecordKind; encBody: string; revision: number; updatedAt: string; deletedAt: string | null;
  permission: Permission; wrappedRecordKey: string; holderType: "user" | "folder";
  /** The team folder whose key wraps wrappedRecordKey (holderType "folder"). */ keyFolderId?: string | null;
  /** A direct share to me: the key it is sealed to (as SyncFolder.sealedTo). */ sealedTo?: string | null;
  ownerId?: string; ownerName?: string; sharedWith?: ShareInfo[]; sharedBy?: string;
  /** Personal space: the orgs this record of mine is shared in (its shares are managed there). */ sharedIn?: string[];
  /** Files (ready ones). Absent from servers before 1.6. */ attachments?: SyncAttachment[];
}
/** `privateLocked`: the session skipped the authenticator code (an org's trusted IdP MFA): own private items are left out until a step-up. */
/** Membership key material (wrapped under my user key) for the active org: what opens what is sealed to me there. */
export interface MembershipKeyRow { publicKey: string; wrappedPrivateKey: string; state: "current" | "retiring" }
export interface SyncResponse { folders: SyncFolder[]; records: SyncRecord[]; serverTime: string; privateLocked?: boolean; orgId?: string; membershipKeys?: MembershipKeyRow[] }

export interface VaultFolder {
  id: string; name: string; kind: "private" | "team"; deleted: boolean;
  ownerId?: string; myPermission?: Permission; members?: FolderMember[]; groups?: FolderGroupGrant[];
  /** Team folder key, held only while unlocked (wiped on lock). */ folderKey?: Uint8Array | null;
}
export interface VaultRecord {
  id: string; folderId: string | null; /** Server metadata only: use body.type. */ type: ServerRecordKind; body: RecordBody | null; revision: number; updatedAt: string; deleted: boolean;
  permission: Permission; recordKey: Uint8Array | null; error?: "cannot_open";
  ownerId?: string; ownerName?: string; sharedWith?: ShareInfo[]; sharedBy?: string;
  /** Personal space: the orgs this record of mine is shared in (its shares are managed there). */ sharedIn?: string[];
  /** Files on the record, still encrypted: names and keys are opened on demand (features/attachments). */ attachments?: SyncAttachment[];
}

export const PERMISSION_LABEL: Record<Permission, string> = { owner: "Owner", edit: "Can edit", view: "Can view", use: "Use only" };
/** Folders a record can be put into: my private folders and team folders where I can edit. */
export const canFileInto = (f: VaultFolder) => !f.deleted && (f.kind === "private" || f.myPermission === "owner" || f.myPermission === "edit");

export type FolderGlyphKind = "private" | "team" | "none";
/** A folder's icon (FolderGlyph; null: "No folder"): a shared folder whose key I don't hold yet shows a lock. */
export function glyphFor(f: { kind: "private" | "team"; folderKey?: Uint8Array | null } | null): { kind: FolderGlyphKind; locked: boolean } {
  if (!f) return { kind: "none", locked: false };
  return { kind: f.kind, locked: f.kind === "team" && f.folderKey === null };
}
