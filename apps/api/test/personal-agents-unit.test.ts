import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { makeTestApp, resetDb, createActiveUser } from "./helpers.js";
import { createTestPersonalAgent } from "./agentHelpers.js";
import { AgentLimitError } from "../src/lib/agents.js";
import { assertPersonalAgentSlot, logLifecycle, personalAgentRules, strictest } from "../src/lib/personalAgents.js";
import { loadConfig } from "../src/config.js";
import { readPolicies } from "../src/lib/policies.js";
import { execSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrismaClient } from "@prisma/client";

const hosted = await makeTestApp({ billingMode: "hosted" });
const plain = await makeTestApp({});
afterAll(async () => { await Promise.all([hosted.app.close(), plain.app.close()]); });
beforeEach(async () => { await resetDb(hosted.prisma); });

const pem = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const agents = (personalAgents: boolean) => ({ gatewayInternalUrl: "http://gw.invalid", gatewayPublicUrl: "https://gw.test/mcp", gatewayApiToken: "x".repeat(32), tokenPrivateKeyPem: pem, acceptNewGatewayIdentity: false, personalAgents });
const cfgHosted = { ...hosted.config, agents: agents(true) };
const block = (o: Partial<{ allowed: boolean; maxPerMember: number | null; write: boolean; reveal: "off" | "approval" | "standing" }> = {}) => ({ allowed: true, maxPerMember: null, write: true, reveal: "approval" as const, ...o });

describe("strictest", () => {
  it("no organisation: the allowance, capped at 20", () => {
    expect(strictest(5, [])).toEqual({ allowed: true, blockedByOrgId: null, max: 5, write: true, reveal: "standing" });
    expect(strictest(null, []).max).toBe(20);
    expect(strictest(50, []).max).toBe(20);
  });
  it("takes the strictest of every organisation", () => {
    expect(strictest(5, [{ orgId: "a", p: block() }, { orgId: "b", p: block({ allowed: false, maxPerMember: 1, write: false, reveal: "standing" }) }]))
      .toEqual({ allowed: false, blockedByOrgId: "b", max: 1, write: false, reveal: "approval" });
    expect(strictest(null, [{ orgId: "a", p: block({ reveal: "off" }) }, { orgId: "b", p: block() }]).reveal).toBe("off");
  });
});

describe("personalAgentRules", () => {
  async function join(userId: string, plan: "team" | "business", policies: object = {}) {
    const o = await hosted.prisma.organization.create({ data: { name: plan, slug: `${plan}-${Math.random().toString(36).slice(2)}`, plan, billingStatus: "active", seatsPaid: 10, policies } });
    await hosted.prisma.membership.create({ data: { orgId: o.id, userId, role: "member", status: "active" } });
    return o.id;
  }
  it("hosted: the highest allowance of the person's organisations, then the policies", async () => {
    const u = await createActiveUser(hosted);
    await hosted.prisma.membership.updateMany({ where: { userId: u.id }, data: { status: "disabled" } });
    expect((await personalAgentRules(hosted.prisma, cfgHosted, u.id)).max).toBe(1);
    await join(u.id, "team");
    expect((await personalAgentRules(hosted.prisma, cfgHosted, u.id)).max).toBe(2);
    const biz = await join(u.id, "business");
    expect(await personalAgentRules(hosted.prisma, cfgHosted, u.id)).toMatchObject({ allowed: true, max: 5 });
    await hosted.prisma.organization.update({ where: { id: biz }, data: { policies: { personalAgents: { maxPerMember: 3 } } } });
    expect((await personalAgentRules(hosted.prisma, cfgHosted, u.id)).max).toBe(3);
  });
  it("a Team organisation's block applies although Team can't edit policies", async () => {
    const u = await createActiveUser(hosted);
    await hosted.prisma.organization.updateMany({ data: { policies: { personalAgents: { allowed: false } } } });
    expect(await personalAgentRules(hosted.prisma, cfgHosted, u.id)).toMatchObject({ allowed: false, blockedByOrgId: expect.any(String) });
  });
  it("billing off: no allowance, only the ceiling", async () => {
    const u = await createActiveUser(plain);
    expect((await personalAgentRules(plain.prisma, { ...plain.config, agents: agents(true) }, u.id)).max).toBe(20);
  });
  it("PERSONAL_AGENTS=off, or agent access off: not allowed, and no organisation to blame", async () => {
    const u = await createActiveUser(plain);
    const off = { allowed: false, blockedByOrgId: null, max: 0, write: false, reveal: "off" };
    expect(await personalAgentRules(plain.prisma, { ...plain.config, agents: agents(false) }, u.id)).toEqual(off);
    expect(await personalAgentRules(plain.prisma, plain.config, u.id)).toEqual(off);
  });
  it("PERSONAL_AGENTS is read from the environment, default on", () => {
    const env = { DATABASE_URL: "postgres://x", PUBLIC_URL: "http://localhost:5173", JWT_SECRET: "j".repeat(40), SERVER_SECRET: "s".repeat(40), GATEWAY_INTERNAL_URL: "http://gw:3100", GATEWAY_PUBLIC_URL: "https://gw.test/mcp", GATEWAY_API_TOKEN: "x".repeat(32), AGENT_TOKEN_PRIVATE_KEY: pem };
    expect(loadConfig(env).agents!.personalAgents).toBe(true);
    expect(loadConfig({ ...env, PERSONAL_AGENTS: "off" }).agents!.personalAgents).toBe(false);
  });
});

describe("assertPersonalAgentSlot and logLifecycle", () => {
  it("counts live agents against the rules, ignoring revoked ones", async () => {
    const u = await createActiveUser(hosted); // Team: 2
    await createTestPersonalAgent(hosted, { ownerUserId: u.id, revoked: true });
    await createTestPersonalAgent(hosted, { ownerUserId: u.id });
    await hosted.prisma.$transaction((tx) => assertPersonalAgentSlot(tx, cfgHosted, u.id));
    await createTestPersonalAgent(hosted, { ownerUserId: u.id });
    await expect(hosted.prisma.$transaction((tx) => assertPersonalAgentSlot(tx, cfgHosted, u.id))).rejects.toMatchObject({ used: 2, allowed: 2 });
    await expect(hosted.prisma.$transaction((tx) => assertPersonalAgentSlot(tx, cfgHosted, u.id))).rejects.toBeInstanceOf(AgentLimitError);
  });
  it("logs one event per active organisation with exactly the admin-visible fields", async () => {
    const u = await createActiveUser(hosted);
    const o2 = await hosted.prisma.organization.create({ data: { name: "Second", slug: "second" } });
    await hosted.prisma.membership.create({ data: { orgId: o2.id, userId: u.id, role: "member", status: "active" } });
    const o3 = await hosted.prisma.organization.create({ data: { name: "Gone", slug: "gone" } });
    await hosted.prisma.membership.create({ data: { orgId: o3.id, userId: u.id, role: "member", status: "disabled" } });
    const a = await createTestPersonalAgent(hosted, { ownerUserId: u.id });
    await hosted.prisma.$transaction((tx) => logLifecycle(tx, u.id, "suspended", a.id));
    const ev = await hosted.prisma.event.findMany({ where: { action: "personal_agent.suspended" } });
    expect(ev).toHaveLength(2);
    for (const e of ev) expect(e).toMatchObject({ actorId: u.id, meta: { agentId: a.id }, targetUserId: null, recordId: null, folderId: null, ip: null, userAgent: null });
    expect(new Set(ev.map((e) => e.orgId))).toEqual(new Set([u.orgId, o2.id]));
  });
});

describe("migration", () => {
  const mk = async (tag: string) => (await createActiveUser(hosted, { email: `${tag}@x.test` })).id;
  it("an agent has exactly one of orgId and ownerUserId", async () => {
    const u = await mk("a"), orgId = (await hosted.prisma.organization.findFirstOrThrow()).id;
    const mkUser = async (n: string) => (await hosted.prisma.user.create({ data: { kind: "agent", email: `agent+${n}@agents.invalid`, name: n, authHash: "", kdfSalt: "", kdfParams: {}, wrappedUserKey: "", publicKey: n, wrappedPrivateKey: "" } })).id;
    const row = async (n: string, extra: object) => hosted.prisma.agent.create({ data: { userId: await mkUser(n), createdById: u, publicKey: n, kekId: "k", attestation: "g1.x", ...extra } });
    await expect(row("both", { orgId, ownerUserId: u })).rejects.toThrow(/Agent_one_owner_check/);
    await expect(row("neither", {})).rejects.toThrow(/Agent_one_owner_check/);
    await expect(row("org", { orgId })).resolves.toBeTruthy();
    await expect(row("own", { ownerUserId: u })).resolves.toBeTruthy();
  });
  it("deleting the owner deletes their personal agents", async () => {
    const u = await mk("b");
    const a = await createTestPersonalAgent(hosted, { ownerUserId: u });
    await hosted.prisma.user.delete({ where: { id: u } });
    expect(await hosted.prisma.agent.findUnique({ where: { userId: a.id } })).toBeNull();
  });
});

describe("a corrupt stored block fails closed", () => {
  it("keeps the valid fields and defaults only the invalid ones", () => {
    const stored = { personalAgents: { allowed: false, maxPerMember: 99, reveal: "always" } };
    const want = { allowed: false, maxPerMember: null, write: true, reveal: "approval" };
    expect(readPolicies(stored).personalAgents).toEqual(want);
    expect(readPolicies(stored, { features: { policyEdit: false } as never }).personalAgents).toEqual(want);
    expect(readPolicies({ personalAgents: "x", autoLockMinutes: 0 }).personalAgents.allowed).toBe(true);
  });
});

describe("migration on existing rows", () => {
  it("leaves organisation agents untouched, then the CHECK refuses both and neither", async () => {
    const base = new URL(process.env.TEST_DATABASE_URL!), dbName = `pamig_${Date.now()}`;
    const url = new URL(base.toString()); url.pathname = `/${dbName}`;
    const dir = mkdtempSync(join(tmpdir(), "cv-pamig-"));
    const admin = new PrismaClient({ datasourceUrl: base.toString() });
    await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
    const deploy = () => execSync(`npx prisma migrate deploy --schema "${join(dir, "schema.prisma")}"`, { env: { ...process.env, DATABASE_URL: url.toString() }, stdio: "pipe" });
    const db = new PrismaClient({ datasourceUrl: url.toString() });
    try {
      const NEW = "20261115000000_personal_agents";
      cpSync("prisma/schema.prisma", join(dir, "schema.prisma"));
      for (const m of readdirSync("prisma/migrations")) if (m < NEW) cpSync(join("prisma/migrations", m), join(dir, "migrations", m), { recursive: true });
      cpSync("prisma/migrations/migration_lock.toml", join(dir, "migrations", "migration_lock.toml"));
      deploy();
      const org = "00000000-0000-4000-8000-0000000000a1", person = "00000000-0000-4000-8000-0000000000b1", agentUser = "00000000-0000-4000-8000-0000000000c1";
      const user = (id: string, kind: string) => db.$executeRawUnsafe(`INSERT INTO "User" (id,email,name,kind,"kdfSalt","kdfParams","authHash","wrappedUserKey","publicKey","wrappedPrivateKey") VALUES ('${id}','${id}@x.test','n','${kind}','','{}','','','pk-${id}','')`);
      await db.$executeRawUnsafe(`INSERT INTO "Organization" (id,name,slug) VALUES ('${org}','O','o')`);
      await user(person, "person"); await user(agentUser, "agent");
      await db.$executeRawUnsafe(`INSERT INTO "Agent" ("userId","orgId","createdById","publicKey","kekId","attestation") VALUES ('${agentUser}','${org}','${person}','pk-a','k','g1.x')`);
      cpSync(join("prisma/migrations", NEW), join(dir, "migrations", NEW), { recursive: true });
      deploy();
      const rows = await db.$queryRawUnsafe<{ orgId: string | null; ownerUserId: string | null; publicKey: string }[]>(`SELECT "orgId","ownerUserId","publicKey" FROM "Agent"`);
      expect(rows).toEqual([{ orgId: org, ownerUserId: null, publicKey: "pk-a" }]);
      const ins = (id: string, o: string, w: string) => db.$executeRawUnsafe(`INSERT INTO "Agent" ("userId","orgId","ownerUserId","createdById","publicKey","kekId","attestation") VALUES ('${id}',${o},${w},'${person}','pk-${id}','k','g1.x')`);
      await user("00000000-0000-4000-8000-0000000000c2", "agent"); await user("00000000-0000-4000-8000-0000000000c3", "agent");
      await expect(ins("00000000-0000-4000-8000-0000000000c2", `'${org}'`, `'${person}'`)).rejects.toThrow(/Agent_one_owner_check/);
      await expect(ins("00000000-0000-4000-8000-0000000000c3", "NULL", "NULL")).rejects.toThrow(/Agent_one_owner_check/);
    } finally {
      await db.$disconnect();
      await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
      await admin.$disconnect();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
