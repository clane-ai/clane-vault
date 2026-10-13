import { createHash, randomBytes } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import type { Config } from "../config.js";

const key = (cfg: Config) => new TextEncoder().encode(cfg.jwtSecret);

/** No role in the token: roles are per organisation and always read from the database. */
export const signAccess = (cfg: Config, p: { userId: string; sessionId: string }) =>
  new SignJWT({ scope: "access", sid: p.sessionId }).setProtectedHeader({ alg: "HS256" })
    .setSubject(p.userId).setIssuedAt().setExpirationTime("15m").sign(key(cfg));

/** `ssoOrgId`: the account is being set up from an SSO sign-in of that org; the session it leads to counts as SSO. */
export const signSetup = (cfg: Config, userId: string, opts: { ssoOrgId?: string; ssoProofId?: string } = {}) =>
  new SignJWT({ scope: "setup", ...(opts.ssoOrgId ? { sso: opts.ssoOrgId } : {}), ...(opts.ssoProofId ? { ssop: opts.ssoProofId } : {}) }).setProtectedHeader({ alg: "HS256" }).setSubject(userId).setIssuedAt().setExpirationTime("15m").sign(key(cfg));

/**
 * Recovery (docs/recovery.md): proves the holder passed the kit/link check and fresh 2FA, and lets them set a new
 * master password once. `ref` pins what was checked (the kit's creation time, or the request id), so a regenerated
 * kit or a used/expired request makes the token useless.
 */
export const signRecovery = (cfg: Config, userId: string, p: { via: "kit" | "admin"; ref: string }) =>
  new SignJWT({ scope: "recovery", via: p.via, ref: p.ref }).setProtectedHeader({ alg: "HS256" }).setSubject(userId).setIssuedAt().setExpirationTime("10m").sign(key(cfg));

/** Admin approval of a recovery request: issued after the admin's fresh 2FA, for one request, for 5 minutes. */
export const signApproval = (cfg: Config, adminId: string, requestId: string) =>
  new SignJWT({ scope: "recovery-approve", rid: requestId }).setProtectedHeader({ alg: "HS256" }).setSubject(adminId).setIssuedAt().setExpirationTime("5m").sign(key(cfg));

/**
 * A one-time link's file download token (docs/design/2026-10-12-attachments.md §5.1): issued by a successful
 * open of a link that carries files, bound to that link, valid for 30 minutes.
 */
export const signLinkDownload = (cfg: Config, linkId: string) =>
  new SignJWT({ scope: "link-download" }).setProtectedHeader({ alg: "HS256" }).setSubject(linkId).setIssuedAt().setExpirationTime("30m").sign(key(cfg));
export async function verifyLinkDownload(cfg: Config, token: string, linkId: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, key(cfg), { algorithms: ["HS256"] });
    return payload.scope === "link-download" && payload.sub === linkId;
  } catch { return false; }
}

export async function verifyToken(cfg: Config, token: string, scope: "access" | "setup" | "recovery" | "recovery-approve") {
  const { payload } = await jwtVerify(token, key(cfg), { algorithms: ["HS256"] });
  if (payload.scope !== scope || typeof payload.sub !== "string") throw new Error("wrong token scope");
  return { sub: payload.sub, sid: payload.sid as string | undefined,
    via: payload.via as string | undefined, ref: payload.ref as string | undefined, rid: payload.rid as string | undefined, sso: payload.sso as string | undefined, ssoProof: payload.ssop as string | undefined };
}

export const hashToken = (secret: string) => createHash("sha256").update(secret).digest("hex");

export function newRefreshToken(sessionId: string) {
  const secret = randomBytes(32).toString("base64url");
  return { token: `${sessionId}.${secret}`, hash: hashToken(secret) };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function splitRefresh(cookie: string | undefined) {
  if (!cookie) return null;
  const [sessionId, secret] = cookie.split(".");
  return sessionId && secret && UUID.test(sessionId) ? { sessionId, secret } : null;
}
