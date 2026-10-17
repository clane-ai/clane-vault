import { describe, expect, it, vi } from "vitest";
import { assertNoInspector, createLogger, HeldSecrets, installCrashHandlers, safeError } from "../src/log.js";
import { variantsOf } from "../src/outbound/scrub.js";

const S = "sk_live_SECRET123";

describe("secret-aware logger", () => {
  it("redacts a held secret in raw and base64 form", () => {
    const held = new HeldSecrets();
    held.hold(S);
    const lines: string[] = [];
    createLogger(held, (l) => lines.push(l)).error({ msg: `boom ${S}`, b64: btoa(S) });
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain(S);
    expect(lines[0]).not.toContain(btoa(S));
    expect(lines[0]).toContain("[clane:redacted]");
    expect(JSON.parse(lines[0]!)).toEqual({ msg: "boom [clane:redacted]", b64: "[clane:redacted]" });
  });
  it("redacts strings nested in objects and arrays", () => {
    const held = new HeldSecrets();
    held.hold(S);
    const lines: string[] = [];
    createLogger(held, (l) => lines.push(l)).info({ a: { b: [`x${S}`] } });
    expect(lines[0]).toBe('{"a":{"b":["x[clane:redacted]"]}}');
  });
  it("stops redacting once released, and keeps a value held twice until both release", () => {
    const held = new HeldSecrets();
    const r1 = held.hold(S), r2 = held.hold(S);
    r1();
    r1();
    expect(held.redact(S)).toBe("[clane:redacted]");
    r2();
    expect(held.redact(S)).toBe(S);
  });
  it("redacts the basic-auth form", () => {
    const held = new HeldSecrets();
    held.hold(S, "bob");
    expect(held.redact(`Basic ${btoa(`bob:${S}`)}`)).toBe("Basic [clane:redacted]");
  });
  it("safeError has no secret and no stack", () => {
    const held = new HeldSecrets();
    held.hold(S);
    const e = safeError(new Error(`x ${S}`), held);
    expect(e).toEqual({ class: "Error", message: "x [clane:redacted]" });
    expect(JSON.stringify(e)).not.toContain(S);
    expect(e).not.toHaveProperty("stack");
  });
});

describe("variantsOf", () => {
  it("lists every encoded form", () => {
    expect(variantsOf("a b", "u")).toEqual(["a b", "YSBi", "a%20b", "612062", btoa("u:a b")]);
    expect(variantsOf("ÿ?")).toEqual(["ÿ?", "w78/", "w78_", "%C3%BF%3F", "c3bf3f", "C3BF3F"]);
    expect(variantsOf("")).toEqual([]);
  });
});

describe("crash handlers", () => {
  it("log the class only, then exit(1)", () => {
    const handlers = new Map<string, (e: unknown) => void>();
    const proc = { on: (ev: string, fn: (e: unknown) => void) => { handlers.set(ev, fn); return proc; } };
    const lines: string[] = [];
    const exit = vi.fn();
    installCrashHandlers(proc as never, createLogger(new HeldSecrets(), (l) => lines.push(l)), exit);
    handlers.get("uncaughtException")!(new TypeError(S));
    expect(lines).toEqual(['{"event":"crash","class":"TypeError"}']);
    expect(exit).toHaveBeenCalledWith(1);
    handlers.get("unhandledRejection")!(S);
    expect(lines[1]).toBe('{"event":"crash","class":"string"}');
    expect(exit).toHaveBeenCalledTimes(2);
  });
});

describe("assertNoInspector", () => {
  it("refuses inspector and heap/cpu dump flags", () => {
    expect(() => assertNoInspector(["--inspect"], undefined)).toThrow();
    expect(() => assertNoInspector(["--inspect-brk=0.0.0.0:9229"], undefined)).toThrow();
    expect(() => assertNoInspector([], "--heapsnapshot-signal=SIGUSR2")).toThrow();
    expect(() => assertNoInspector([], "--max-old-space-size=512 --cpu-prof")).toThrow();
    expect(() => assertNoInspector(["--heap-prof"], "")).toThrow();
    expect(() => assertNoInspector([], "")).not.toThrow();
    expect(() => assertNoInspector(["--disable-sigusr1"], "--max-old-space-size=512")).not.toThrow();
  });
});
