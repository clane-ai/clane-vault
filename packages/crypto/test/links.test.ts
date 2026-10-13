import { describe, expect, it } from "vitest";
import {
  configureKdfFloor, createLink, openLink, openPasswordLink, deriveLinkAccess, encryptLinkLabel, decryptLinkLabel,
  b64url, randomBytes, DEFAULT_KDF, type KdfParams, type LinkBody, linkSnapshot,
} from "../src/index.js";

configureKdfFloor({ m: 1024, t: 1 });
const FAST: KdfParams = { alg: "argon2id", m: 1024, t: 2, p: 1 };
const body: LinkBody = { title: "Customer portal", username: "acme-admin", password: "figma123!Xq", url: "portal.example.com", notes: "Change on first sign-in" };

describe("one-time links", () => {
  it("round-trips with the key in the fragment, and the fragment is the link key", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body);
    expect(l.fragment).toBe(b64url.encode(l.linkKey));
    expect(l.accessHash).toBeUndefined();
    expect(l.passwordSalt).toBeUndefined();
    expect(await openLink(id, l.encPayload, l.fragment)).toEqual(body);
  });

  it("never puts plaintext fields in the payload", async () => {
    const l = await createLink(crypto.randomUUID(), body, { password: "pw", kdf: FAST });
    for (const v of Object.values(body)) expect(l.encPayload).not.toContain(v);
    const l2 = await createLink(crypto.randomUUID(), body);
    for (const v of Object.values(body)) expect(l2.encPayload).not.toContain(v);
  });

  it("binds the payload to the link id", async () => {
    const l = await createLink(crypto.randomUUID(), body);
    await expect(openLink(crypto.randomUUID(), l.encPayload, l.fragment)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("rejects a wrong or malformed key", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body);
    await expect(openLink(id, l.encPayload, b64url.encode(randomBytes(32)))).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(openLink(id, l.encPayload, "c2hvcnQ")).rejects.toMatchObject({ code: "bad_key" });
    await expect(openLink(id, l.encPayload, "not base64!")).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("only carries the snapshot fields (no TOTP secret, no blanks)", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, { title: " T ", password: "x", notes: "", totpSecret: "JBSWY3DPEHPK3PXP" } as LinkBody);
    expect(await openLink(id, l.encPayload, l.fragment)).toEqual({ title: "T", password: "x" });
    await expect(createLink(id, { title: "" })).rejects.toThrow(/title/);
  });

  it("password links: the key is still in the fragment, the URL never ends in #p, the access hash is deterministic", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body, { password: "blue cactus", kdf: FAST });
    expect(l.fragment).toBe(b64url.encode(l.linkKey));
    expect(l.fragment).not.toBe("p");
    expect(l.encPayload.startsWith("w1.")).toBe(true);
    expect(l.passwordSalt).toBeTruthy();
    const ok = await deriveLinkAccess("blue cactus", l.passwordSalt!, l.fragment, FAST);
    expect(ok.accessHash).toBe(l.accessHash);
    expect(await openPasswordLink(id, l.encPayload, ok.wrapKey)).toEqual(body);
    expect(ok.accessHash).not.toBe(b64url.encode(ok.wrapKey));
  });

  it("password links: the fragment without the password cannot open it", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body, { password: "blue cactus", kdf: FAST });
    await expect(openLink(id, l.encPayload, l.fragment)).rejects.toMatchObject({ code: "bad_key" });
    // The fragment is not the data key either: forcing a v1 open of the payload part fails.
    await expect(openLink(id, `v1.${l.encPayload.split(".")[2]}`, l.fragment)).rejects.toMatchObject({ code: "decrypt_failed" });
    const bad = await deriveLinkAccess("red cactus", l.passwordSalt!, l.fragment, FAST);
    expect(bad.accessHash).not.toBe(l.accessHash);
    await expect(openPasswordLink(id, l.encPayload, bad.wrapKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("password links: the password without the right fragment cannot open it, and gives a different access hash", async () => {
    const id = crypto.randomUUID();
    const l = await createLink(id, body, { password: "blue cactus", kdf: FAST });
    const other = b64url.encode(randomBytes(32));
    const k = await deriveLinkAccess("blue cactus", l.passwordSalt!, other, FAST);
    expect(k.accessHash).not.toBe(l.accessHash);
    await expect(openPasswordLink(id, l.encPayload, k.wrapKey)).rejects.toMatchObject({ code: "decrypt_failed" });
    await expect(deriveLinkAccess("blue cactus", l.passwordSalt!, "", FAST)).rejects.toMatchObject({ code: "bad_key" });
    await expect(deriveLinkAccess("blue cactus", l.passwordSalt!, "p", FAST)).rejects.toBeTruthy();
  });

  it("password links: wrapped key is bound to the link id", async () => {
    const l = await createLink(crypto.randomUUID(), body, { password: "pw", kdf: FAST });
    const k = await deriveLinkAccess("pw", l.passwordSalt!, l.fragment, FAST);
    await expect(openPasswordLink(crypto.randomUUID(), l.encPayload, k.wrapKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("uses the default (spec) Argon2id parameters when none are given", async () => {
    expect(DEFAULT_KDF.m).toBe(65536);
    const id = crypto.randomUUID();
    const l = await createLink(id, body, { password: "pw" });
    const k = await deriveLinkAccess("pw", l.passwordSalt!, l.fragment);
    expect(k.accessHash).toBe(l.accessHash);
    const fast = await deriveLinkAccess("pw", l.passwordSalt!, l.fragment, FAST);
    expect(fast.accessHash).not.toBe(l.accessHash);
  }, 30_000);

  it("label round-trips under the user key and is bound to the link", async () => {
    const userKey = randomBytes(32), id = crypto.randomUUID();
    const enc = await encryptLinkLabel(id, "Acme Ltd", userKey);
    expect(await decryptLinkLabel(id, enc, userKey)).toBe("Acme Ltd");
    await expect(decryptLinkLabel(crypto.randomUUID(), enc, userKey)).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("carries a record's type, template data and custom fields, never TOTP secrets", async () => {
    const id = crypto.randomUUID();
    const snap = linkSnapshot({ v: 2, type: "server", title: "Build box", username: "root", password: "pw", data: { hostname: "10.0.0.5", port: "22" },
      fields: [{ id: "a", label: "Console", kind: "url", value: "https://idrac" }, { id: "b", label: "OTP", kind: "totp", value: "JBSWY3DPEHPK3PXP" }] });
    const l = await createLink(id, snap);
    expect(await openLink(id, l.encPayload, l.fragment)).toEqual({ title: "Build box", type: "server", username: "root", password: "pw", data: { hostname: "10.0.0.5", port: "22" }, fields: [{ id: "a", label: "Console", kind: "url", value: "https://idrac" }] });
    const direct = await createLink(id, { title: "x", type: "note", fields: [{ id: "b", label: "OTP", kind: "totp", value: "JBSWY3DPEHPK3PXP" }] });
    expect(await openLink(id, direct.encPayload, direct.fragment)).toEqual({ title: "x", type: "note" });
    await expect(createLink(id, { title: "x", type: "card", data: { hostname: "h" } })).rejects.toThrow(/hostname/);
  });
});
