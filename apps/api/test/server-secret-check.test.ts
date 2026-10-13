import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { authenticator } from "otplib";
import { checkServerSecret, ServerSecretMismatch } from "../src/lib/serverSecretCheck.js";
import { secretBox } from "../src/lib/secretBox.js";
import { consumeTotp } from "../src/lib/totp.js";
import { createActiveUser, makeTestApp, resetDb } from "./helpers.js";

// A changed SERVER_SECRET stops the server at startup with a clear message (docs: deploy/client/README.md).
const t = await makeTestApp();
afterAll(() => t.app.close());
beforeEach(async () => {
  await resetDb(t.prisma);
  await t.prisma.serverSecretCheck.deleteMany();
});

const A = "a".repeat(40);
const B = "b".repeat(40);
const warnings = () => {
  const msgs: string[] = [];
  return { msgs, log: { warn: (m: string) => msgs.push(m) } };
};
/** Seals a fresh authenticator secret for a user under `secret`, as 2FA setup does. */
const enrolUnder = async (userId: string, secret: string) =>
  t.prisma.user.update({ where: { id: userId }, data: { totpSecretEnc: secretBox(secret).seal(authenticator.generateSecret(20)), totpEnabledAt: new Date() } });

describe("server secret check", () => {
  it("remembers the secret on first start and accepts it afterwards", async () => {
    expect(await checkServerSecret(t.prisma, A)).toEqual({ status: "created", unreadableTotp: 0 });
    expect(await checkServerSecret(t.prisma, A)).toEqual({ status: "ok", unreadableTotp: 0 });
  });

  it("refuses a different secret with a message that says what to do", async () => {
    await checkServerSecret(t.prisma, A);
    const err = await checkServerSecret(t.prisma, B).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ServerSecretMismatch);
    expect((err as Error).message).toMatch(/SERVER_SECRET does not match this database/);
    expect((err as Error).message).toMatch(/ACCEPT_NEW_SERVER_SECRET=true/);
  });

  it("ACCEPT_NEW_SERVER_SECRET switches the database to the new secret", async () => {
    await checkServerSecret(t.prisma, A);
    const w = warnings();
    expect((await checkServerSecret(t.prisma, B, { accept: true, log: w.log })).status).toBe("accepted");
    expect(w.msgs.join(" ")).toMatch(/Reset every account's 2FA/);
    expect((await checkServerSecret(t.prisma, B)).status).toBe("ok");
    await expect(checkServerSecret(t.prisma, A)).rejects.toBeInstanceOf(ServerSecretMismatch);
  });

  it("an upgraded database whose 2FA secrets were all sealed under another secret is refused", async () => {
    const u1 = await createActiveUser(t, { email: "one@example.com" });
    const u2 = await createActiveUser(t, { email: "two@example.com" });
    await enrolUnder(u1.id, A);
    await enrolUnder(u2.id, A);
    await expect(checkServerSecret(t.prisma, B)).rejects.toBeInstanceOf(ServerSecretMismatch);
    expect(await t.prisma.serverSecretCheck.count()).toBe(0);
    expect((await checkServerSecret(t.prisma, A)).status).toBe("created");
  });

  it("an upgraded database with some unreadable 2FA secrets starts and names how many", async () => {
    const u1 = await createActiveUser(t, { email: "one@example.com" });
    const u2 = await createActiveUser(t, { email: "two@example.com" });
    await enrolUnder(u1.id, A);
    await enrolUnder(u2.id, B);
    const w = warnings();
    expect(await checkServerSecret(t.prisma, B, { log: w.log })).toEqual({ status: "created", unreadableTotp: 1 });
    expect(w.msgs.join(" ")).toMatch(/1 of 2 sampled accounts/);
  });

  it("sign-in with an authenticator sealed under another secret logs why instead of a bare decrypt error", async () => {
    const u = await createActiveUser(t, { email: "one@example.com" });
    const user = await enrolUnder(u.id, A);
    await expect(consumeTotp(t.prisma, secretBox(B), user, "123456")).rejects.toThrow(/SERVER_SECRET differs/);
  });
});
