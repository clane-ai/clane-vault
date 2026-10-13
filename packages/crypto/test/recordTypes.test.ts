import { describe, expect, it } from "vitest";
import {
  encryptNewRecord, decryptRecord, randomBytes, type RecordBody, aeadEncrypt, utf8,
  MAX_BODY_BYTES, MAX_CUSTOM_FIELDS, RECORD_TYPES, RECORD_TYPE_DEFS, RECORD_TYPE_GROUPS, serverRecordType, luhnValid, cardBrand, expiryValid, normalizeRecordBody, isSecretKind,
} from "../src/index.js";

describe("record types (v2 bodies)", () => {
  const userKey = randomBytes(32);
  const rt = async (b: RecordBody) => { const id = crypto.randomUUID(); const e = await encryptNewRecord(id, b, userKey); return (await decryptRecord(id, e.encBody, e.wrappedRecordKey, userKey)).body; };
  /** Encrypts raw JSON as a body, bypassing encrypt's validation (what an old client or a v1 row holds). */
  const raw = async (json: unknown) => {
    const id = crypto.randomUUID(), rk = randomBytes(32);
    const encBody = await aeadEncrypt(rk, utf8.encode(JSON.stringify(json)), `record-body:${id}`);
    return decryptRecord(id, encBody, await aeadEncrypt(userKey, rk, `record-key:${id}`), userKey);
  };
  const card: RecordBody = {
    type: "card", title: "Company Visa", notes: "Travel only",
    data: { cardholder: "Ada Lovelace", number: "4242424242424242", expiry: "12/29", cvv: "123", pin: "9876", billingAddress: "1 Main St\nDublin" },
    fields: [{ id: "f1", label: "Limit", kind: "text", value: "5000 EUR" }, { id: "f2", label: "Portal 2FA", kind: "totp", value: "JBSWY3DPEHPK3PXP" }],
  };

  it("reads a v1 body unchanged (no version added, legacy fields kept)", async () => {
    const v1 = { type: "login", title: "Old", username: "u", password: "p", url: "x.com", totpSecret: "JBSWY3DPEHPK3PXP", notes: "n" };
    expect((await raw(v1)).body).toEqual(v1);
    const note = { type: "note", title: "Old note", username: "kept as v1 always did", notes: "n" };
    expect((await raw(note)).body).toEqual(note);
  });

  it("refuses a v1 body of a type v1 never had, and unknown versions", async () => {
    await expect(raw({ type: "card", title: "x" })).rejects.toMatchObject({ code: "bad_envelope" });
    await expect(raw({ v: 3, type: "login", title: "x" })).rejects.toMatchObject({ code: "bad_envelope" });
  });

  it("writes v2 and round-trips every type with its template data and custom fields", async () => {
    expect(await rt(card)).toEqual({ v: 2, ...card });
    for (const t of RECORD_TYPES) {
      const def = RECORD_TYPE_DEFS[t];
      const b: RecordBody = { type: t, title: def.label, notes: "n" };
      for (const f of def.fields) {
        const v = f.options ? f.options[0]!.value : f.kind === "totp" ? "JBSWY3DPEHPK3PXP" : f.kind === "date" ? "2027-01-31" : `${f.key}-value`;
        if (f.core) (b as unknown as Record<string, string>)[f.key] = v; else (b.data ??= {})[f.key] = v;
      }
      expect(await rt(b)).toEqual({ v: 2, ...b });
    }
  });

  it("lists every type once in the picker groups", () => {
    expect(RECORD_TYPE_GROUPS.map((g) => g.label)).toEqual(["Logins & access", "Payments & finance", "Identity", "Other"]);
    expect(RECORD_TYPE_GROUPS.flatMap((g) => g.types.map((t) => t.id)).sort()).toEqual([...RECORD_TYPES].sort());
  });

  it("does not leak template or custom field values into the ciphertext", async () => {
    const e = await encryptNewRecord(crypto.randomUUID(), card, userKey);
    for (const v of [...Object.values(card.data!), ...card.fields!.map((f) => f.value), ...card.fields!.map((f) => f.label), "card"]) expect(e.encBody).not.toContain(v);
  });

  it("drops blank data and custom field values, trims labels", async () => {
    const b = await rt({ type: "wifi", title: "Office", data: { ssid: "Clane", security: "" }, fields: [{ id: "a", label: "  Floor ", kind: "text", value: "2" }, { id: "b", label: "Empty", kind: "text", value: "" }] });
    expect(b).toEqual({ v: 2, type: "wifi", title: "Office", data: { ssid: "Clane" }, fields: [{ id: "a", label: "Floor", kind: "text", value: "2" }] });
  });

  it("rejects fields that aren't part of the type's template", async () => {
    await expect(rt({ type: "card", title: "x", password: "nope" })).rejects.toThrow(/password/);
    await expect(rt({ type: "note", title: "x", username: "nope" })).rejects.toThrow(/username/);
    await expect(rt({ type: "card", title: "x", data: { hostname: "h" } })).rejects.toThrow(/hostname/);
    await expect(rt({ type: "card", title: "x", data: { number: 4242 as unknown as string } })).rejects.toThrow(/text/);
    await expect(rt({ type: "nope" as RecordBody["type"], title: "x" })).rejects.toThrow(/type/);
  });

  it("validates custom fields: allowed kinds, labels, ids, counts", async () => {
    const f = (o: object) => rt({ type: "note", title: "x", fields: [{ id: "a", label: "L", kind: "text", value: "v", ...o }] as RecordBody["fields"] });
    await expect(f({ kind: "html" })).rejects.toThrow(/kind/);
    await expect(f({ label: "  " })).rejects.toThrow(/label/);
    await expect(f({ label: "x".repeat(101) })).rejects.toThrow(/label/);
    await expect(f({ id: "has space" })).rejects.toThrow(/id/);
    await expect(rt({ type: "note", title: "x", fields: [{ id: "a", label: "A", kind: "text", value: "1" }, { id: "a", label: "B", kind: "text", value: "2" }] })).rejects.toThrow(/id/);
    for (const kind of ["text", "secret", "multiline", "url", "email", "phone", "date", "totp", "hiddenMultiline"] as const) expect((await f({ kind })).fields![0]!.kind).toBe(kind);
    const many = Array.from({ length: MAX_CUSTOM_FIELDS }, (_, i) => ({ id: `f${i}`, label: `F${i}`, kind: "text" as const, value: "v" }));
    expect((await rt({ type: "note", title: "x", fields: many })).fields).toHaveLength(MAX_CUSTOM_FIELDS);
    await expect(rt({ type: "note", title: "x", fields: [...many, { id: "z", label: "Z", kind: "text", value: "v" }] })).rejects.toThrow(/at most 64/);
  });

  it("bounds the size of a value and of the whole body", async () => {
    await expect(rt({ type: "note", title: "x", fields: [{ id: "a", label: "Big", kind: "multiline", value: "x".repeat(64 * 1024 + 1) }] })).rejects.toThrow(/too long/);
    await expect(rt({ type: "note", title: "x", notes: "x".repeat(MAX_BODY_BYTES) })).rejects.toThrow(/too large/);
    const fits = await encryptNewRecord(crypto.randomUUID(), { type: "note", title: "x", notes: "é".repeat((MAX_BODY_BYTES - 100) / 2) }, userKey);
    // The API takes envelopes up to 65 536 characters.
    expect(fits.encBody.length).toBeLessThanOrEqual(65536);
  });

  it("keeps passwordChangedAt next to a v2 password", async () => {
    const at = "2026-01-02T03:04:05.000Z";
    expect((await rt({ type: "server", title: "s", password: "pw", passwordChangedAt: at })).passwordChangedAt).toBe(at);
    expect((await rt({ type: "card", title: "c", passwordChangedAt: at })).passwordChangedAt).toBeUndefined();
  });

  it("tells the server only login or item", () => {
    expect(serverRecordType({ type: "login" })).toBe("login");
    for (const t of RECORD_TYPES.filter((x) => x !== "login")) expect(serverRecordType({ type: t })).toBe("item");
  });

  it("normalises a v1-shaped login to v2", () => {
    expect(normalizeRecordBody({ type: "login", title: " T ", username: "u" })).toEqual({ v: 2, type: "login", title: "T", username: "u" });
  });

  it("only the core password is a password-like credential; card numbers, CVVs, PINs, licence keys and SSH keys are data", () => {
    const pw = (t: keyof typeof RECORD_TYPE_DEFS) => RECORD_TYPE_DEFS[t].fields.some((f) => f.core && f.key === "password");
    expect(RECORD_TYPES.filter(pw).sort()).toEqual(["bankAccount", "database", "login", "membership", "server", "wifi"]);
    for (const [t, k] of [["card", "number"], ["card", "cvv"], ["card", "pin"], ["softwareLicence", "licenceKey"], ["sshKey", "privateKey"], ["sshKey", "passphrase"]] as const) {
      const f = RECORD_TYPE_DEFS[t].fields.find((x) => x.key === k)!;
      expect(f.core).toBeUndefined();
      expect(isSecretKind(f.kind)).toBe(true);
    }
  });

  it("card helpers: Luhn, brand, expiry", () => {
    expect(luhnValid("4242 4242 4242 4242")).toBe(true);
    expect(luhnValid("4242 4242 4242 4241")).toBe(false);
    expect(luhnValid("12")).toBe(false);
    expect(cardBrand("4242")).toBe("Visa");
    expect(cardBrand("5555 5555")).toBe("Mastercard");
    expect(cardBrand("3782")).toBe("Amex");
    expect(expiryValid("12/29")).toBe(true);
    expect(expiryValid("13/29")).toBe(false);
    expect(expiryValid("1/29")).toBe(false);
  });
});
