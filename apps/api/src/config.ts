import { createPrivateKey } from "node:crypto";
import { Cron } from "croner";
import { z } from "zod";
import { AGE_RECIPIENT } from "./lib/backup/age.js";
import type { S3Settings } from "./lib/backup/destinations.js";

export const DEFAULT_PRODUCT_NAME = "Clane Vault";

const blank = (v: unknown) => (v === "" ? undefined : v);
const schema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  SERVER_SECRET: z.string().min(32),
  ACCEPT_NEW_SERVER_SECRET: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  PUBLIC_URL: z.string().url(),
  BASE_PATH: z.preprocess(blank, z.string().optional()),
  COOKIE_SECURE: z.enum(["true", "false"]).default("true"),
  PORT: z.coerce.number().int().default(3001),
  TRUST_PROXY: z.string().regex(/^(true|false|\d+)$/, "TRUST_PROXY must be true, false or a hop count").default("false"),
  PRODUCT_NAME: z.preprocess((v) => (typeof v === "string" ? v.trim() : v) || undefined, z.string().max(60).default(DEFAULT_PRODUCT_NAME)),
  DEFAULT_ORG_NAME: z.preprocess((v) => (typeof v === "string" ? v.trim() : v) || undefined, z.string().max(80).optional()),
  ALLOW_ORG_CREATION: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  HOSTED_MODE: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  BILLING_MODE: z.preprocess(blank, z.enum(["off", "hosted"]).default("off")),
  INVITES_PER_ORG_PER_DAY: z.preprocess(blank, z.coerce.number().int().min(1).max(100000).default(50)),
  MAX_OWNED_ORGS: z.preprocess(blank, z.coerce.number().int().min(1).max(10000).default(5)),
  KDF_MIN_MEMORY_KIB: z.coerce.number().int().min(1024).default(65536),
  ADMIN_RECOVERY_RESET_DELAY_HOURS: z.preprocess(blank, z.coerce.number().min(0).max(720).default(24)),
  ADMIN_RECOVERY_APPROVER_MIN_AGE_DAYS: z.preprocess(blank, z.coerce.number().min(0).max(365).default(7)),
  RATE_LIMIT_PER_MINUTE: z.preprocess(blank, z.coerce.number().int().min(10).max(100000).default(300)),
  RESEND_API_KEY: z.preprocess(blank, z.string().min(1).optional()),
  EMAIL_FROM: z.preprocess(blank, z.string().min(3).optional()),
  SSO_ALLOW_HTTP_ISSUER: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  BACKUP_ENABLED: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  BACKUP_SCHEDULE: z.preprocess(blank, z.string().default("30 2 * * *")),
  BACKUP_AGE_RECIPIENT: z.preprocess(blank, z.string().trim().optional()),
  BACKUP_RETENTION_DAYS: z.preprocess(blank, z.coerce.number().int().min(1).max(3650).default(14)),
  BACKUP_LOCAL_DIR: z.preprocess(blank, z.string().optional()),
  BACKUP_S3_ENDPOINT: z.preprocess(blank, z.string().url().optional()),
  BACKUP_S3_REGION: z.preprocess(blank, z.string().default("us-east-1")),
  BACKUP_S3_BUCKET: z.preprocess(blank, z.string().optional()),
  BACKUP_S3_PREFIX: z.string().default("clane-vault/"),
  BACKUP_S3_ACCESS_KEY_ID: z.preprocess(blank, z.string().optional()),
  BACKUP_S3_SECRET_ACCESS_KEY: z.preprocess(blank, z.string().optional()),
  BACKUP_S3_FORCE_PATH_STYLE: z.preprocess(blank, z.enum(["true", "false"]).default("true")),
  // File attachments (docs/attachments.md).
  ATTACHMENTS_ENABLED: z.preprocess(blank, z.enum(["true", "false"]).default("true")),
  ATTACHMENT_STORAGE: z.preprocess(blank, z.enum(["db", "s3"]).default("db")),
  ATTACHMENT_S3_ENDPOINT: z.preprocess(blank, z.string().url().optional()),
  ATTACHMENT_S3_REGION: z.preprocess(blank, z.string().default("us-east-1")),
  ATTACHMENT_S3_BUCKET: z.preprocess(blank, z.string().optional()),
  ATTACHMENT_S3_PREFIX: z.string().default("attachments/"),
  ATTACHMENT_S3_ACCESS_KEY_ID: z.preprocess(blank, z.string().optional()),
  ATTACHMENT_S3_SECRET_ACCESS_KEY: z.preprocess(blank, z.string().optional()),
  ATTACHMENT_S3_FORCE_PATH_STYLE: z.preprocess(blank, z.enum(["true", "false"]).default("true")),
  // The client's crypto ceiling is 100 MiB per file, so that is the most an operator can allow.
  ATTACHMENT_MAX_FILE_MB: z.preprocess(blank, z.coerce.number().int().min(1).max(100).default(100)),
  ATTACHMENT_MAX_PER_RECORD: z.preprocess(blank, z.coerce.number().int().min(1).max(1000).default(25)),
  ATTACHMENT_MAX_RECORD_MB: z.preprocess(blank, z.coerce.number().int().min(1).max(1_000_000).default(250)),
  ATTACHMENT_ORG_QUOTA_MB: z.preprocess(blank, z.coerce.number().int().min(0).max(100_000_000).default(2048)),
  ATTACHMENT_USER_QUOTA_MB: z.preprocess(blank, z.coerce.number().int().min(0).max(100_000_000).default(512)),
  ATTACHMENT_INSTANCE_QUOTA_MB: z.preprocess(blank, z.coerce.number().int().min(0).max(1_000_000_000).default(10240)),
  ATTACHMENT_DAILY_UPLOAD_MB: z.preprocess(blank, z.coerce.number().int().min(1).max(100_000_000).default(2048)),
  // Public demo (docs/demo.md): throwaway sandboxes, deleted after DEMO_TTL_MINUTES.
  DEMO_MODE: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
  DEMO_TTL_MINUTES: z.preprocess(blank, z.coerce.number().int().min(5).max(7 * 24 * 60).default(120)),
  DEMO_SANDBOXES_PER_IP_PER_HOUR: z.preprocess(blank, z.coerce.number().int().min(1).max(10000).default(5)),
  // Agent access (docs/agents.md): off unless GATEWAY_INTERNAL_URL is set, and then the next three are required too.
  GATEWAY_INTERNAL_URL: z.preprocess(blank, z.string().url().optional()),
  GATEWAY_PUBLIC_URL: z.preprocess(blank, z.string().url().optional()),
  GATEWAY_API_TOKEN: z.preprocess(blank, z.string().min(32).optional()),
  AGENT_TOKEN_PRIVATE_KEY: z.preprocess(blank, z.string().optional()),
  GATEWAY_ACCEPT_NEW_IDENTITY: z.preprocess(blank, z.enum(["true", "false"]).default("false")),
});

export interface BackupConfig {
  enabled: boolean;
  /** 5-field cron, UTC. */
  schedule: string;
  ageRecipient?: string;
  retentionDays: number;
  localDir?: string;
  s3?: S3Settings;
}

/** File attachments (docs/attachments.md, spec 2026-10-12-attachments.md §3.4). Sizes in MiB. */
export interface AttachmentConfig {
  enabled: boolean;
  storage: "db" | "s3";
  /** Required with storage "s3": a bucket of its own (not the backup bucket). */
  s3?: S3Settings;
  maxFileMb: number; maxPerRecord: number; maxRecordMb: number;
  orgQuotaMb: number; userQuotaMb: number; instanceQuotaMb: number; dailyUploadMb: number;
  /** Per-user requests per minute (chunk uploads and downloads each; creates). Tests lower them. */
  chunkRatePerMinute?: number; createRatePerMinute?: number;
  /** The public link chunk route, per client address. */
  publicChunkRatePerMinute?: number;
  /** Set by attachmentConfig() from the instance's BILLING_MODE, so quota checks apply the plan's pooled storage. */
  billingMode?: Config["billingMode"];
}

export const DEFAULT_ATTACHMENTS: AttachmentConfig = {
  enabled: true, storage: "db", maxFileMb: 100, maxPerRecord: 25, maxRecordMb: 250, orgQuotaMb: 2048, userQuotaMb: 512, instanceQuotaMb: 10240, dailyUploadMb: 2048,
};

/** Agent access (docs/agents.md). Absent on Config = agent features off. */
export interface AgentConfig {
  gatewayInternalUrl: string; gatewayPublicUrl: string; gatewayApiToken: string;
  /** PKCS#8 PEM, P-256: signs agent access tokens (ES256). */
  tokenPrivateKeyPem: string;
  /** GATEWAY_ACCEPT_NEW_IDENTITY=true: accept and pin a changed gateway identity. */
  acceptNewGatewayIdentity: boolean;
}

export interface Config {
  /** Product name shown to people: authenticator-app issuer, invite emails. PRODUCT_NAME, default "Clane Vault". */
  productName: string;
  /**
   * Path the app is served under ("" = the root, or e.g. "/vault"): the API is at `${basePath}/api/v1` and the web app at
   * `${basePath}/`. From BASE_PATH, or else from PUBLIC_URL's path (docs: deploy/client/README.md). Optional: absent = "".
   */
  basePath?: string;
  databaseUrl: string; jwtSecret: string; serverSecret: string; publicUrl: string; cookieSecure: boolean; port: number; kdfMinMemoryKiB: number; trustProxy: boolean | number;
  /** Invite emails go out through Resend only when both are set; otherwise admins copy the link. */
  resendApiKey?: string; emailFrom?: string;
  /** Requests per minute per client address across the API (RATE_LIMIT_PER_MINUTE, default 300). Sensitive routes have their own lower limits. */
  rateLimitPerMinute?: number;
  /**
   * Admin recovery for an account whose 2FA was reset: the link only lets the member set up a new authenticator this
   * many hours after the reset (ADMIN_RECOVERY_RESET_DELAY_HOURS, default 24), and never when the same admin did both.
   */
  adminRecoveryResetDelayHours?: number;
  /**
   * Admin recovery for an account whose 2FA was reset: the approving admin must have been an admin at least this many
   * days before the reset (ADMIN_RECOVERY_APPROVER_MIN_AGE_DAYS, default 7), so a freshly invited "second admin" can't
   * be used to get around the two-person rule.
   */
  adminRecoveryApproverMinAgeDays?: number;
  /** Scheduled, encrypted database backups. Absent means off. */
  backup?: BackupConfig;
  /** Name given to the default organisation when it has none (DEFAULT_ORG_NAME, default "<productName> org"). */
  defaultOrgName?: string;
  /**
   * ACCEPT_NEW_SERVER_SECRET=true: start even though SERVER_SECRET differs from the one the database was set up with
   * (lib/serverSecretCheck.ts), and remember the new one. For a secret that is lost for good; remove it afterwards.
   */
  acceptNewServerSecret?: boolean;
  /** Whether any signed-in user may create an organisation (ALLOW_ORG_CREATION, default false; hosted operators set true). */
  allowOrgCreation?: boolean;
  /**
   * HOSTED_MODE (default false): invite links are never shown to admins (email only; refused without email set up)
   * and registering also needs a 6-digit code emailed to the invited address.
   */
  hostedMode?: boolean;
  /** BILLING_MODE (default off): "hosted" turns on plans and limits (lib/plans.ts); off leaves every limit unset. */
  billingMode?: "off" | "hosted";
  /** Invites an org may send per 24 h (INVITES_PER_ORG_PER_DAY, default 50). */
  invitesPerOrgPerDay?: number;
  /** Organisations one account may own (MAX_OWNED_ORGS, default 5). */
  maxOwnedOrgs?: number;
  /** SSO_ALLOW_HTTP_ISSUER (default false): allow http:// OpenID Connect issuers. Development and tests only. */
  ssoAllowHttpIssuer?: boolean;
  /** File attachments; absent: the defaults (DEFAULT_ATTACHMENTS). */
  attachments?: AttachmentConfig;
  /**
   * Public demo (DEMO_MODE, default false; docs/demo.md): visitors get a throwaway sandbox without an authenticator, deleted
   * after `ttlMinutes` (DEMO_TTL_MINUTES, default 120). No email is sent, SSO and organisation creation are off, file
   * uploads are capped small. `sandboxesPerIpPerHour` (DEMO_SANDBOXES_PER_IP_PER_HOUR, default 5) limits sign-ups.
   * Absent: off.
   */
  demo?: DemoConfig;
  /** Agent access; absent: off (no agent, /agent/* or /oauth/* route exists). */
  agents?: AgentConfig }

export interface DemoConfig { ttlMinutes: number; sandboxesPerIpPerHour: number }

/** Attachment caps a demo instance never goes above, in MiB: per file, and for one sandbox (its quotas and its day). */
export const DEMO_ATTACHMENT_CAPS = { maxFileMb: 5, sandboxMb: 20 } as const;

/** One path segment of BASE_PATH: unreserved URL characters only (no dot-segments). */
const SEGMENT = /^[A-Za-z0-9._~-]+$/;
export const basePathSchema = z.string().transform((v, ctx) => {
  const segs = v.trim().split("/").filter((s) => s !== "");
  for (const s of segs) {
    if (!SEGMENT.test(s) || s === "." || s === "..") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "BASE_PATH may only contain path segments of A-Z a-z 0-9 . _ ~ -" });
      return z.NEVER;
    }
  }
  return segs.length ? `/${segs.join("/")}` : "";
});

/** "" for the root, else "/a/b": leading slash, no trailing slash. Throws on characters outside [A-Za-z0-9._~/-]. */
export function normaliseBasePath(v: string): string {
  const r = basePathSchema.safeParse(v);
  if (!r.success) throw new Error(r.error.issues[0]?.message ?? "invalid BASE_PATH");
  return r.data;
}

/**
 * BASE_PATH when set (PUBLIC_URL's path must then be the same), else PUBLIC_URL's path. Returns the base path and
 * PUBLIC_URL without a trailing slash (it includes the base path: https://host/vault).
 */
export function resolveBasePath(publicUrlRaw: string, basePathRaw?: string): { basePath: string; publicUrl: string } {
  const u = new URL(publicUrlRaw);
  if (u.search || u.hash) throw new Error("PUBLIC_URL must not have a query or fragment");
  const fromUrl = normaliseBasePath(decodeURIComponent(u.pathname));
  const basePath = basePathRaw === undefined ? fromUrl : normaliseBasePath(basePathRaw);
  if (basePath !== fromUrl)
    throw new Error(`PUBLIC_URL's path (${fromUrl || "/"}) must equal BASE_PATH (${basePath || "/"}): set PUBLIC_URL=${u.origin}${basePath}`);
  return { basePath, publicUrl: `${u.origin}${basePath}` };
}

/** Where the API is mounted: `${basePath}/api/v1`. */
export const apiPrefix = (c: Pick<Config, "basePath">): string => `${c.basePath ?? ""}/api/v1`;

/** Throws on an invalid 5-field cron expression. */
export function checkSchedule(expr: string): void {
  new Cron(expr, { paused: true, timezone: "UTC", mode: "5-part" }).stop();
}

function backupConfig(e: z.infer<typeof schema>): BackupConfig {
  const prefix = e.BACKUP_S3_PREFIX === "" || e.BACKUP_S3_PREFIX.endsWith("/") ? e.BACKUP_S3_PREFIX : `${e.BACKUP_S3_PREFIX}/`;
  const b: BackupConfig = {
    enabled: e.BACKUP_ENABLED === "true", schedule: e.BACKUP_SCHEDULE.trim(), retentionDays: e.BACKUP_RETENTION_DAYS,
    ...(e.BACKUP_AGE_RECIPIENT ? { ageRecipient: e.BACKUP_AGE_RECIPIENT } : {}),
    ...(e.BACKUP_LOCAL_DIR ? { localDir: e.BACKUP_LOCAL_DIR } : {}),
    ...(e.BACKUP_S3_BUCKET ? { s3: { region: e.BACKUP_S3_REGION, bucket: e.BACKUP_S3_BUCKET, prefix, forcePathStyle: e.BACKUP_S3_FORCE_PATH_STYLE === "true",
      ...(e.BACKUP_S3_ENDPOINT ? { endpoint: e.BACKUP_S3_ENDPOINT } : {}),
      ...(e.BACKUP_S3_ACCESS_KEY_ID ? { accessKeyId: e.BACKUP_S3_ACCESS_KEY_ID } : {}),
      ...(e.BACKUP_S3_SECRET_ACCESS_KEY ? { secretAccessKey: e.BACKUP_S3_SECRET_ACCESS_KEY } : {}) } } : {}),
  };
  if (b.enabled) {
    // Backups are never written unencrypted: no recipient, no backups (and no start).
    if (!b.ageRecipient) throw new Error("BACKUP_AGE_RECIPIENT is required when BACKUP_ENABLED=true");
    if (!AGE_RECIPIENT.test(b.ageRecipient)) throw new Error("BACKUP_AGE_RECIPIENT must be an age public key (age1…)");
    if (!b.localDir && !b.s3) throw new Error("BACKUP_ENABLED=true needs BACKUP_S3_BUCKET and/or BACKUP_LOCAL_DIR");
    if (b.s3 && !!b.s3.accessKeyId !== !!b.s3.secretAccessKey) throw new Error("Set both BACKUP_S3_ACCESS_KEY_ID and BACKUP_S3_SECRET_ACCESS_KEY");
    try { checkSchedule(b.schedule); } catch { throw new Error("BACKUP_SCHEDULE is not a valid 5-field cron expression"); }
  }
  return b;
}

function agentConfig(e: z.infer<typeof schema>): AgentConfig | undefined {
  const set = [e.GATEWAY_INTERNAL_URL, e.GATEWAY_PUBLIC_URL, e.GATEWAY_API_TOKEN, e.AGENT_TOKEN_PRIVATE_KEY];
  if (set.every((v) => v === undefined)) return undefined;
  if (set.some((v) => v === undefined)) throw new Error("GATEWAY_INTERNAL_URL, GATEWAY_PUBLIC_URL, GATEWAY_API_TOKEN and AGENT_TOKEN_PRIVATE_KEY go together (docs/agents.md)");
  const pem = e.AGENT_TOKEN_PRIVATE_KEY!.replace(/\\n/g, "\n");
  try {
    const k = createPrivateKey(pem);
    if (k.asymmetricKeyType !== "ec" || k.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error();
  } catch { throw new Error("AGENT_TOKEN_PRIVATE_KEY must be a P-256 PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)"); }
  return { gatewayInternalUrl: e.GATEWAY_INTERNAL_URL!, gatewayPublicUrl: e.GATEWAY_PUBLIC_URL!, gatewayApiToken: e.GATEWAY_API_TOKEN!,
    tokenPrivateKeyPem: pem, acceptNewGatewayIdentity: e.GATEWAY_ACCEPT_NEW_IDENTITY === "true" };
}

function attachmentConfig(e: z.infer<typeof schema>): AttachmentConfig {
  const prefix = e.ATTACHMENT_S3_PREFIX === "" || e.ATTACHMENT_S3_PREFIX.endsWith("/") ? e.ATTACHMENT_S3_PREFIX : `${e.ATTACHMENT_S3_PREFIX}/`;
  const a: AttachmentConfig = {
    enabled: e.ATTACHMENTS_ENABLED === "true", storage: e.ATTACHMENT_STORAGE,
    maxFileMb: e.ATTACHMENT_MAX_FILE_MB, maxPerRecord: e.ATTACHMENT_MAX_PER_RECORD, maxRecordMb: e.ATTACHMENT_MAX_RECORD_MB,
    orgQuotaMb: e.ATTACHMENT_ORG_QUOTA_MB, userQuotaMb: e.ATTACHMENT_USER_QUOTA_MB, instanceQuotaMb: e.ATTACHMENT_INSTANCE_QUOTA_MB, dailyUploadMb: e.ATTACHMENT_DAILY_UPLOAD_MB,
    ...(e.ATTACHMENT_S3_BUCKET ? { s3: { region: e.ATTACHMENT_S3_REGION, bucket: e.ATTACHMENT_S3_BUCKET, prefix, forcePathStyle: e.ATTACHMENT_S3_FORCE_PATH_STYLE === "true",
      ...(e.ATTACHMENT_S3_ENDPOINT ? { endpoint: e.ATTACHMENT_S3_ENDPOINT } : {}),
      ...(e.ATTACHMENT_S3_ACCESS_KEY_ID ? { accessKeyId: e.ATTACHMENT_S3_ACCESS_KEY_ID } : {}),
      ...(e.ATTACHMENT_S3_SECRET_ACCESS_KEY ? { secretAccessKey: e.ATTACHMENT_S3_SECRET_ACCESS_KEY } : {}) } } : {}),
  };
  if (a.storage === "s3") {
    if (!a.s3) throw new Error("ATTACHMENT_STORAGE=s3 needs ATTACHMENT_S3_BUCKET (and its endpoint and credentials)");
    if (!!a.s3.accessKeyId !== !!a.s3.secretAccessKey) throw new Error("Set both ATTACHMENT_S3_ACCESS_KEY_ID and ATTACHMENT_S3_SECRET_ACCESS_KEY");
  }
  return a;
}

/** A demo instance's attachment limits: the configured ones, but never above DEMO_ATTACHMENT_CAPS (lib/attachments/quota.ts applies it). */
export function demoAttachments(a: AttachmentConfig): AttachmentConfig {
  const { maxFileMb, sandboxMb } = DEMO_ATTACHMENT_CAPS;
  return { ...a, maxFileMb: Math.min(a.maxFileMb, maxFileMb), maxRecordMb: Math.min(a.maxRecordMb, sandboxMb), orgQuotaMb: Math.min(a.orgQuotaMb, sandboxMb),
    userQuotaMb: Math.min(a.userQuotaMb, sandboxMb),
    // A sandbox's visitor is its only account that can upload, and it lives for hours: this caps the sandbox as a whole.
    dailyUploadMb: Math.min(a.dailyUploadMb, sandboxMb) };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const e = schema.parse(env);
  if (e.DEMO_MODE === "true" && e.HOSTED_MODE === "true") throw new Error("DEMO_MODE=true can't be combined with HOSTED_MODE=true: a demo instance holds throwaway sandboxes only");
  if (e.SSO_ALLOW_HTTP_ISSUER === "true" && (e.HOSTED_MODE === "true" || env.NODE_ENV === "production"))
    throw new Error("SSO_ALLOW_HTTP_ISSUER=true is for development only: not with HOSTED_MODE=true or NODE_ENV=production");
  if (env.NODE_ENV === "production") {
    for (const k of ["JWT_SECRET", "SERVER_SECRET"] as const) {
      if (e[k].startsWith("change-me")) throw new Error(`${k} is still a placeholder; set a real secret in production`);
    }
  }
  const { basePath, publicUrl } = resolveBasePath(e.PUBLIC_URL, e.BASE_PATH);
  const agents = agentConfig(e);
  return { productName: e.PRODUCT_NAME, basePath, databaseUrl: e.DATABASE_URL, jwtSecret: e.JWT_SECRET, serverSecret: e.SERVER_SECRET, publicUrl, cookieSecure: e.COOKIE_SECURE === "true", port: e.PORT, kdfMinMemoryKiB: e.KDF_MIN_MEMORY_KIB, rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE, adminRecoveryResetDelayHours: e.ADMIN_RECOVERY_RESET_DELAY_HOURS, adminRecoveryApproverMinAgeDays: e.ADMIN_RECOVERY_APPROVER_MIN_AGE_DAYS, trustProxy: e.TRUST_PROXY === "true" ? true : e.TRUST_PROXY === "false" ? false : Number(e.TRUST_PROXY),
    ...(e.RESEND_API_KEY && e.EMAIL_FROM ? { resendApiKey: e.RESEND_API_KEY, emailFrom: e.EMAIL_FROM } : {}), backup: backupConfig(e),
    ...(e.DEFAULT_ORG_NAME ? { defaultOrgName: e.DEFAULT_ORG_NAME } : {}), allowOrgCreation: e.ALLOW_ORG_CREATION === "true", acceptNewServerSecret: e.ACCEPT_NEW_SERVER_SECRET === "true",
    hostedMode: e.HOSTED_MODE === "true", billingMode: e.BILLING_MODE, invitesPerOrgPerDay: e.INVITES_PER_ORG_PER_DAY, maxOwnedOrgs: e.MAX_OWNED_ORGS,
    ssoAllowHttpIssuer: e.SSO_ALLOW_HTTP_ISSUER === "true",
    attachments: attachmentConfig(e),
    ...(agents ? { agents } : {}),
    ...(e.DEMO_MODE === "true" ? { demo: { ttlMinutes: e.DEMO_TTL_MINUTES, sandboxesPerIpPerHour: e.DEMO_SANDBOXES_PER_IP_PER_HOUR } } : {}) };
}
