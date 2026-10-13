import { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { authenticator } from "otplib";
import { configureKdfFloor, createAccount, type KdfParams, type UnlockedKeys, type AccountMaterial } from "@clane-vault/crypto";
import { buildApp } from "../src/app.js";
import type { Config } from "../src/config.js";

configureKdfFloor({ m: 1024, t: 1 });

export const FAST_KDF: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };

export async function resetDb(prisma: PrismaClient) {
  await prisma.$executeRawUnsafe(`TRUNCATE "RecoveryRequest","MembershipEscrow","MembershipKey","AccountKeyArchive","PendingFolderMember","Event","RecordAccess","Record","Folder","Session","Invite","Membership","OrgLogo","Organization","User","InstanceBrand" CASCADE`);
  // Every test starts with the default organisation only (what the API creates on a fresh install).
  await prisma.organization.create({ data: { name: "Test org", slug: "default", createdAt: new Date("2020-01-01T00:00:00Z") } });
}

/** The default organisation's id. */
export const defaultOrgId = async (prisma: PrismaClient) => (await prisma.organization.findFirstOrThrow({ orderBy: [{ createdAt: "asc" }, { id: "asc" }], select: { id: true } })).id;

/** The X-Org-Id header for a test user's active org (none when they have none). */
export const orgHeader = (u: { orgId?: string | null }): Record<string, string> => (u.orgId ? { "x-org-id": u.orgId } : {});

/** A test app on the shared test database; `overrides` change the configuration (e.g. attachment limits). */
export async function makeTestApp(overrides: Partial<Config> = {}): Promise<{ app: FastifyInstance; prisma: PrismaClient; config: Config }> {
  const config: Config = {
    databaseUrl: process.env.TEST_DATABASE_URL!,
    jwtSecret: "test-jwt-secret-test-jwt-secret-test-jwt-secret",
    serverSecret: "test-server-secret-test-server-secret-test-server",
    publicUrl: "http://localhost:5173",
    cookieSecure: false,
    port: 0,
    kdfMinMemoryKiB: 1024, productName: "Clane Vault", allowOrgCreation: true,
    // Admin recovery: test admins are minutes old; tests that check the approver age set it explicitly.
    adminRecoveryApproverMinAgeDays: 0,
    trustProxy: false,
    ...overrides,
  };
  const prisma = new PrismaClient({ datasourceUrl: config.databaseUrl });
  await resetDb(prisma);
  const app = await buildApp({ config, prisma });
  app.addHook("onClose", () => prisma.$disconnect());
  return { app, prisma, config };
}

export async function createInvite(prisma: PrismaClient, email: string, role: "owner" | "admin" | "member" = "member", orgId?: string): Promise<string> {
  const token = randomBytes(24).toString("base64url");
  await prisma.invite.create({ data: { orgId: orgId ?? await defaultOrgId(prisma), email, role, tokenHash: createHash("sha256").update(token).digest("hex"), expiresAt: new Date(Date.now() + 7 * 864e5) } });
  return token;
}

const usedStep = new Map<string, number>();
/**
 * A TOTP code for a time step this secret hasn't used yet (the server accepts each step once). Uses the next step,
 * which the ±1 window accepts, and waits only when both are used up.
 */
export async function freshTotp(secret: string): Promise<string> {
  for (;;) {
    const now = Math.floor(Date.now() / 30_000);
    const step = Math.max(now, (usedStep.get(secret) ?? -Infinity) + 1);
    if (step <= now + 1) {
      usedStep.set(secret, step);
      return authenticator.clone({ epoch: step * 30_000 }).generate(secret);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}
/** A 6-digit code that no step in the window accepts. */
export function wrongTotp(secret: string): string {
  const now = Math.floor(Date.now() / 30_000);
  const valid = new Set([-1, 0, 1, 2].map((d) => authenticator.clone({ epoch: (now + d) * 30_000 }).generate(secret)));
  for (let i = 0; ; i++) { const c = String(i).padStart(6, "0"); if (!valid.has(c)) return c; }
}

let seq = 0;
let ipSeq = 0;
/** Each test account is created from its own address, so long test files don't hit the per-address rate limits. */
const nextIp = () => `10.77.${(++ipSeq >> 8) & 255}.${ipSeq & 255}`;
/** A signed-in account, active in `orgId` (default: the default organisation) with `role`. */
export async function createActiveUser(t: { app: FastifyInstance; prisma: PrismaClient }, opts: { email?: string; role?: "owner" | "admin" | "member"; password?: string; orgId?: string } = {}) {
  const ip = nextIp();
  const email = opts.email ?? `user${++seq}@clane.ai`;
  const password = opts.password ?? `password for ${email}`;
  const orgId = opts.orgId ?? await defaultOrgId(t.prisma);
  const inviteToken = await createInvite(t.prisma, email, opts.role, orgId);
  const acct = await createAccount(password, FAST_KDF);
  const reg = await t.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/register", payload: { inviteToken, name: email.split("@")[0], authKey: acct.authKey, material: acct.material } });
  const { setupToken } = reg.json();
  const auth = { authorization: `Bearer ${setupToken}` };
  const setup = await t.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/totp/setup", headers: auth, payload: {} });
  const totpSecret = setup.json().secret as string;
  const verify = await t.app.inject({ remoteAddress: ip, method: "POST", url: "/api/v1/auth/totp/verify", headers: auth, payload: { code: await freshTotp(totpSecret) } });
  const body = verify.json();
  const c = verify.cookies.find((x) => x.name === "cv_refresh")!;
  return { id: body.user.id as string, email, password, orgId, accessToken: body.accessToken as string, cookie: `cv_refresh=${c.value}`, totpSecret, keys: acct.keys as UnlockedKeys, material: acct.material as AccountMaterial };
}
