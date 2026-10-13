import type { EmailSettings, PrismaClient } from "@prisma/client";
import nodemailer from "nodemailer";
import type { Config } from "../config.js";
import { logEvent } from "./events.js";
import { type DelegatedStore, delegatedScope, type M365Transport, sendM365 } from "./m365.js";
import { PrivateHostError, resolvePublic } from "./netGuard.js";
import type { SettingsBox } from "./settingsBox.js";

export const EMAIL_TIMEOUT_MS = 10_000;
/** SMTP ports an organisation may use in HOSTED_MODE. */
export const SMTP_PORTS = [25, 465, 587, 2525];
type Log = { warn: (o: object, m: string) => void };
export interface Message { subject: string; text: string }

/** A ready-to-use way to send: where it came from and how. Secrets live only in memory here. */
export type Transport =
  | { source: "org" | "instance" | "env"; provider: "resend"; from: string; apiKey: string }
  | { source: "org" | "instance"; provider: "smtp"; from: string; host: string; port: number; security: "none" | "starttls" | "tls"; username?: string; password?: string;
      /** Hosted mode, an org's own server: refuse private addresses. */ publicOnly?: boolean;
      /** Hosted mode: never AUTH over an unencrypted connection. */ refusePlainAuth?: boolean }
  | M365Transport;

export type SendResult = { ok: true } | { ok: false; detail: string };

/** `Name <address>`, quoting the name when needed (names are cleaned of newlines and control characters on input). */
export function fromHeader(name: string | null | undefined, address: string): string {
  if (!name) return address;
  return /^[\w .'-]+$/.test(name) ? `${name} <${address}>` : `"${name.replace(/["\\]/g, "")}" <${address}>`;
}

/** Removes every occurrence of the secrets (and long tokens that look like keys) from a message shown to admins. */
export function scrub(text: string, secrets: (string | undefined)[]): string {
  let t = text;
  for (const s of secrets) if (s && s.length >= 4) t = t.split(s).join("[redacted]");
  return t.replace(/\b(re_|sk_|key-)[A-Za-z0-9_-]{8,}/g, "[redacted]").replace(/[\r\n]+/g, " ").slice(0, 240);
}

/** A short, credential-free summary of an SMTP failure (nodemailer error codes). */
export function smtpErrorSummary(err: unknown, t: { host: string; port: number }, secrets: (string | undefined)[]): string {
  const e = err as { code?: string; responseCode?: number; command?: string; message?: string };
  const where = `${t.host}:${t.port}`;
  const code = e.responseCode ? ` (server said ${e.responseCode})` : "";
  if (err instanceof PrivateHostError) return `${t.host} resolves to a private network address, which isn't allowed on this server.`;
  // Socket errors arrive as ESOCKET/ECONNECTION with the system error in the message.
  const sys = /\b(ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|ECONNRESET|EHOSTUNREACH|ENETUNREACH)\b/.exec(e.message ?? "")?.[1];
  switch (sys ?? e.code) {
    case "ECONNRESET": return `${where} closed the connection. Check the port and the security setting.`;
    case "EHOSTUNREACH": case "ENETUNREACH": return `Couldn't reach ${where} (no route to host).`;
    case "EAUTH": return `The SMTP server rejected the username or password${code}.`;
    case "ENOAUTH": return "The SMTP server needs a username and password.";
    case "ECONNREFUSED": return `Couldn't connect to ${where}: connection refused.`;
    case "ENOTFOUND": case "EDNS": case "EAI_AGAIN": return `Couldn't find the SMTP server ${t.host} (DNS lookup failed).`;
    case "ETIMEDOUT": return `No answer from ${where} within ${EMAIL_TIMEOUT_MS / 1000} s.`;
    case "ETLS": return `TLS failed with ${where}. Check the security setting (STARTTLS usually on 587, TLS on 465).`;
    case "EPLAINAUTH": return "This server doesn't send an SMTP password over an unencrypted connection: choose STARTTLS or TLS.";
    case "EPORT": return `Port ${t.port} isn't allowed on this server (use 25, 465, 587 or 2525).`;
    case "ESOCKET": case "ECONNECTION": return `Connection to ${where} failed. Check the host, port and security setting.`;
    case "EENVELOPE": return `The SMTP server refused the sender or recipient${code}. Check the from address.`;
    case "EMESSAGE": return `The SMTP server refused the message${code}.`;
    // Never the server's or the system's raw message (it could carry details of the network or the credentials).
    default: void secrets; return `Sending failed${code}.`;
  }
}

async function sendResend(t: Extract<Transport, { provider: "resend" }>, to: string, msg: Message): Promise<SendResult> {
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${t.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ from: t.from, to: [to], ...msg }),
      signal: AbortSignal.timeout(EMAIL_TIMEOUT_MS),
    });
    if (res.ok) return { ok: true };
    const why = res.status === 401 || res.status === 403 ? "the API key was rejected" : res.status === 422 ? "the from address or recipient was refused (is the domain verified in Resend?)" : `HTTP ${res.status}`;
    return { ok: false, detail: `Resend refused the email: ${why}.` };
  } catch (e) {
    const name = (e as Error).name;
    return { ok: false, detail: name === "TimeoutError" || name === "AbortError" ? `No answer from Resend within ${EMAIL_TIMEOUT_MS / 1000} s.` : "Couldn't reach Resend." };
  }
}

async function sendSmtp(t: Extract<Transport, { provider: "smtp" }>, to: string, msg: Message): Promise<SendResult> {
  try {
    // HOSTED_MODE, an org's own server: allowed ports only, resolved once to a public address and connected by IP
    // (TLS still checks the certificate against the host name).
    if (t.refusePlainAuth && t.username && t.security === "none") throw Object.assign(new Error("plain auth"), { code: "EPLAINAUTH" });
    if (t.publicOnly && !SMTP_PORTS.includes(t.port)) throw Object.assign(new Error("port"), { code: "EPORT" });
    const ip = t.publicOnly ? await resolvePublic(t.host) : null;
    const tr = nodemailer.createTransport({
      host: ip ?? t.host, ...(ip ? { tls: { servername: t.host } } : {}), port: t.port, secure: t.security === "tls", requireTLS: t.security === "starttls", ignoreTLS: t.security === "none",
      ...(t.username ? { auth: { user: t.username, pass: t.password ?? "" } } : {}),
      connectionTimeout: EMAIL_TIMEOUT_MS, greetingTimeout: EMAIL_TIMEOUT_MS, socketTimeout: EMAIL_TIMEOUT_MS, dnsTimeout: EMAIL_TIMEOUT_MS,
      logger: false, debug: false,
    });
    try { await tr.sendMail({ from: t.from, to, subject: msg.subject, text: msg.text }); }
    finally { tr.close(); }
    return { ok: true };
  } catch (e) {
    return { ok: false, detail: smtpErrorSummary(e, t, [t.password, t.username]) };
  }
}

export function deliver(t: Transport, to: string, msg: Message): Promise<SendResult> {
  return t.provider === "resend" ? sendResend(t, to, msg) : t.provider === "m365" ? sendM365(t, to, msg) : sendSmtp(t, to, msg);
}

export const scopeOf = (orgId: string | null) => (orgId ? `org:${orgId}` : "instance");
export const secretAad = (row: { id: string; scope: string }) => `email-settings:${row.id}:${row.scope}:secret`;
/** A Microsoft 365 delegated refresh token is bound to its settings row like the secret. */
export const refreshAad = (row: { id: string; scope: string }) => `email-settings:${row.id}:${row.scope}:m365-refresh`;
/** Whether a row is Microsoft 365 with delegated sign-in. */
export const isDelegated = (row: Pick<EmailSettings, "provider" | "m365AuthMode">) => row.provider === "m365" && row.m365AuthMode === "delegated";

/**
 * Sends the product's emails (docs/email.md). Which settings apply: the organisation's own (for that org's invites and
 * notices), else the instance's (admin GUI), else RESEND_API_KEY / EMAIL_FROM. Never throws from `send`.
 */
export class Mailer {
  constructor(private deps: { prisma: PrismaClient; config: Config; box: SettingsBox }) {}

  /** The transport a row describes (secret opened in memory). Null when the row can't be used (e.g. secret missing). */
  transportOf(row: EmailSettings, source: "org" | "instance"): Transport | null {
    let secret: string | undefined;
    if (row.secretEnc) {
      try { secret = this.deps.box.open(row.secretEnc, secretAad(row)); }
      catch { return null; } // SERVER_SECRET changed: the admin enters the secret again
    }
    const from = fromHeader(row.fromName, row.fromAddress);
    if (row.provider === "resend") return secret ? { source, provider: "resend", from, apiKey: secret } : null;
    if (row.provider === "m365") {
      if (!secret || !row.m365TenantId || !row.m365ClientId) return null;
      const base = { source, provider: "m365" as const, fromName: row.fromName, tenantId: row.m365TenantId, clientId: row.m365ClientId, clientSecret: secret, cacheId: row.id };
      if (!isDelegated(row)) return { ...base, sender: row.fromAddress };
      // Delegated: only while connected (a connection that needs reconnecting has no refresh token).
      if (!row.m365RefreshEnc || !row.m365Account || row.m365ReconnectAt) return null;
      return { ...base, mode: "delegated", sender: row.fromAddress || row.m365Account, account: row.m365Account,
        scope: delegatedScope(!!row.fromAddress && row.fromAddress !== row.m365Account), store: this.delegatedStore(row) };
    }
    if (!row.smtpHost || !row.smtpPort) return null;
    return { source, provider: "smtp", from, host: row.smtpHost, port: row.smtpPort, security: row.smtpSecurity ?? "starttls",
      ...(row.smtpUsername ? { username: row.smtpUsername, password: secret ?? "" } : {}), publicOnly: source === "org" && !!this.deps.config.hostedMode, refusePlainAuth: !!this.deps.config.hostedMode };
  }

  /** The refresh token of a delegated row, read and rotated with a version check (docs/email.md, "Microsoft 365 — delegated sign-in"). */
  private delegatedStore(row: EmailSettings): DelegatedStore {
    const { prisma, box } = this.deps;
    return {
      load: async () => {
        const r = await prisma.emailSettings.findUnique({ where: { id: row.id }, select: { id: true, scope: true, m365RefreshEnc: true, m365RefreshVersion: true, m365ReconnectAt: true, m365TenantId: true, m365ClientId: true } });
        // Settings changed under us (another app): nothing to refresh with.
        if (!r?.m365RefreshEnc || r.m365ReconnectAt || r.m365TenantId !== row.m365TenantId || r.m365ClientId !== row.m365ClientId) return null;
        try { return { refreshToken: box.open(r.m365RefreshEnc, refreshAad(r)), version: r.m365RefreshVersion }; }
        catch { return null; }
      },
      rotate: async (version, refreshToken) => {
        const n = await prisma.emailSettings.updateMany({ where: { id: row.id, m365RefreshVersion: version, m365ReconnectAt: null },
          data: { m365RefreshEnc: box.seal(refreshToken, refreshAad(row)), m365RefreshVersion: { increment: 1 } } });
        return n.count === 1;
      },
      broken: async (version, reason) => {
        const n = await prisma.emailSettings.updateMany({ where: { id: row.id, m365RefreshVersion: version, m365ReconnectAt: null },
          data: { m365RefreshEnc: null, m365RefreshVersion: { increment: 1 }, m365ReconnectAt: new Date(), m365ReconnectReason: reason.slice(0, 300) } });
        if (n.count === 1) await this.reconnectNeeded(row, reason).catch(() => undefined);
      },
    };
  }

  /**
   * A delegated connection stopped working: logged once (email.m365_reconnect_needed), and the people who can fix it
   * (instance admins for the server's settings, the org's owners and admins for an org's) are emailed through a path
   * that doesn't use Microsoft 365 (an org's: the server's settings unless they are Microsoft 365; the server's: the
   * environment's Resend), if there is one.
   */
  private async reconnectNeeded(row: EmailSettings, reason: string): Promise<void> {
    const { prisma, config } = this.deps;
    await logEvent(prisma, { ...(row.orgId ? { orgId: row.orgId } : {}), action: "email.m365_reconnect_needed", meta: { scope: row.orgId ? "org" : "instance", account: row.m365Account ?? null, reason: reason.slice(0, 200) } });
    let via: Transport | null = null;
    if (row.orgId) {
      const inst = await prisma.emailSettings.findUnique({ where: { scope: "instance" } });
      if (inst && inst.provider !== "m365") via = this.transportOf(inst, "instance");
    }
    via ??= this.envTransport();
    if (!via) return;
    const to = row.orgId
      ? await prisma.user.findMany({ where: { status: "active", memberships: { some: { orgId: row.orgId, status: "active", role: { in: ["owner", "admin"] } } } }, select: { email: true } })
      : await prisma.user.findMany({ where: { status: "active", instanceAdmin: true }, select: { email: true } });
    const org = row.orgId ? await prisma.organization.findUnique({ where: { id: row.orgId }, select: { name: true } }) : null;
    const where = org ? `the email settings of ${org.name} (Admin → Email)` : "the server's email settings (Server → Email)";
    const msg = { subject: `${config.productName}: Microsoft 365 email needs signing in again`,
      text: `${config.productName} can no longer send email as ${row.m365Account ?? "the connected Microsoft 365 account"}: ${reason}

Open ${where} and choose Reconnect (Sign in with Microsoft). Until then, emails ${org ? "use the server's settings, if any" : "use the environment's settings, if any"}.` };
    for (const u of to.slice(0, 50)) await deliver(via, u.email, msg).catch(() => undefined);
  }

  envTransport(): Transport | null {
    const c = this.deps.config;
    return c.resendApiKey && c.emailFrom ? { source: "env", provider: "resend", from: c.emailFrom, apiKey: c.resendApiKey } : null;
  }

  /** The transport for an email about `orgId` (null: an account or instance email). */
  async resolve(orgId?: string | null): Promise<Transport | null> {
    const rows = await this.deps.prisma.emailSettings.findMany({ where: { scope: { in: [scopeOf(null), ...(orgId ? [scopeOf(orgId)] : [])] } } });
    const org = orgId ? rows.find((r) => r.orgId === orgId) : undefined;
    const inst = rows.find((r) => r.scope === "instance");
    return (org && this.transportOf(org, "org")) ?? (inst && this.transportOf(inst, "instance")) ?? this.envTransport();
  }

  async configured(orgId?: string | null): Promise<boolean> {
    return !!(await this.resolve(orgId));
  }

  /** Sends one plain-text email. False (never throws) when email isn't configured or sending fails. */
  async send(to: string, msg: Message, log: Log, orgId?: string | null): Promise<boolean> {
    try {
      const t = await this.resolve(orgId);
      if (!t) return false;
      const r = await deliver(t, to, msg);
      if (!r.ok) log.warn({ source: t.source, provider: t.provider }, "email not sent");
      return r.ok;
    } catch {
      log.warn({}, "email not sent");
      return false;
    }
  }
}
