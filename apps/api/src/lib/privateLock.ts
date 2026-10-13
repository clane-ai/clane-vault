import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { recordOrgOf } from "./access.js";

/**
 * A session that skipped the authenticator code (an org's trusted IdP MFA, docs/sso.md) is confined to that org: the
 * caller's own private records and folders (no organisation) stay locked until a TOTP step-up. Run after requireAuth
 * and the org check; answers 403 `totp_step_up_required`.
 */
export const isPrivateLocked = (req: FastifyRequest) => !!req.auth?.totpSkippedForOrg;

/** The caller's own record outside any organisation (no folder or a private folder). */
export async function isOwnPrivateRecord(app: FastifyInstance, userId: string, recordId: string): Promise<boolean> {
  const r = await app.prisma.record.findUnique({ where: { id: recordId }, select: { ownerId: true, folder: { select: { kind: true, orgId: true } } } });
  return !!r && r.ownerId === userId && recordOrgOf(r) === null;
}
/** A target folder for a record that is private: no folder, or a private folder. */
async function privateTarget(app: FastifyInstance, folderId: unknown): Promise<boolean> {
  if (folderId === null) return true;
  if (typeof folderId !== "string") return false;
  const f = await app.prisma.folder.findUnique({ where: { id: folderId }, select: { kind: true } });
  return f?.kind === "private";
}

const deny = (reply: FastifyReply) => reply.code(403).send({ error: "totp_step_up_required" });

/** preHandler for /records*, /folders*, /links* and /records/batch. */
export function privateLockGuard(app: FastifyInstance) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (reply.sent || !isPrivateLocked(req)) return;
    const url = req.routeOptions.url ?? "";
    const params = (req.params ?? {}) as { id?: string };
    const body = (req.body ?? {}) as { folderId?: unknown; kind?: unknown; recordId?: unknown; records?: { folderId?: unknown }[] };
    const me = req.auth.userId;
    if (url.endsWith("/records/batch")) {
      for (const r of body.records ?? []) if (await privateTarget(app, r.folderId ?? null)) return deny(reply);
      return;
    }
    if (url.endsWith("/records") && req.method === "POST") { if (await privateTarget(app, body.folderId ?? null)) return deny(reply); return; }
    if (url.includes("/records/:id")) {
      if (params.id && await isOwnPrivateRecord(app, me, params.id)) return deny(reply);
      if (url.endsWith("/records/:id/folder") && "folderId" in body && await privateTarget(app, body.folderId)) return deny(reply);
      return;
    }
    if (url.endsWith("/folders") && req.method === "POST") { if (body.kind !== "team") return deny(reply); return; }
    if (url.includes("/folders/:id") && params.id) {
      const f = await app.prisma.folder.findUnique({ where: { id: params.id }, select: { kind: true } });
      if (f?.kind === "private") return deny(reply);
      return;
    }
    if (url.endsWith("/links") && req.method === "POST") { if (typeof body.recordId === "string" && await isOwnPrivateRecord(app, me, body.recordId)) return deny(reply); return; }
    if (url.includes("/links/:id") && params.id) {
      const l = await app.prisma.shareLink.findUnique({ where: { id: params.id }, select: { recordId: true } });
      if (l && await isOwnPrivateRecord(app, me, l.recordId)) return deny(reply);
    }
  };
}
