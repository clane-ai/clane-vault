import { describe, expect, it } from "vitest";
import {
  MAX_ENV_BYTES, checkEnvContent, diffEnv, envEntries, envFileName, envKeys, envValue, parseEnv, quoteEnvValue, setEnvEntry,
} from "../src/index.js";
import { FILE } from "./envFixture.js";

describe("env files (spec §10.3)", () => {
  const v = (k: string) => envValue(FILE, k);

  it("parses losslessly, with the last duplicate winning and invalid lines kept", () => {
    expect(parseEnv(FILE).map((l) => l.raw).join("")).toBe(FILE);
    expect(envKeys(FILE)).toEqual(["STRIPE_KEY", "PORT", "DB", "PW", "PW2", "A", "REF", "E", "T"]);
    expect([v("STRIPE_KEY"), v("PORT"), v("DB"), v("PW"), v("PW2"), v("A"), v("REF"), v("E"), v("T"), v("BAD")])
      .toEqual(["sk_live_1", "3000", "line1\nline2\tx", "abc#123", "abc", "2", "${A}", "", "tick", null]);
    expect(parseEnv(FILE).filter((l) => l.kind === "invalid").map((l) => l.raw)).toEqual(["not a line\r\n", 'BAD="open\r\n']);
    expect(envEntries("A=1\nA=2").map((e) => e.overridden)).toEqual([true, false]);
    expect(envValue("K='a\\nb'", "K")).toBe("a\\nb"); // single quotes are literal
    for (const bad of ['K="a"b', "=x", "K", "K: v", "a b=1"]) expect(parseEnv(bad)[0]!.kind).toBe("invalid");
    for (const any of ["", "\n", "\r", '"', "A='\n", "\u0000", "=".repeat(9)]) expect(parseEnv(any).map((l) => l.raw).join("")).toBe(any);
  });

  it("entries split into head + token + tail", () => {
    for (const l of parseEnv(FILE)) if (l.kind === "entry") expect(l.head + l.token + l.tail).toBe(l.raw);
  });

  it("quotes, sets and diffs entries", () => {
    expect(["abc", "x y", "it's", "l1\nl2", "", "a#b", "$x"].map(quoteEnvValue)).toEqual(["abc", "'x y'", '"it\'s"', '"l1\\nl2"', "", "'a#b'", "'$x'"]);
    expect(setEnvEntry(FILE, "STRIPE_KEY", "sk_live_2")).toBe(FILE.replace("'sk_live_1'", "sk_live_2")); // export, spacing, comment, CRLF and BOM stay
    expect(setEnvEntry("A=1\nA=2\n", "A", "3")).toBe("A=1\nA=3\n");
    expect(setEnvEntry("A=1", "B", "x y")).toBe("A=1\nB='x y'\n");
    expect(setEnvEntry("A=1\r\n", "B", "2")).toBe("A=1\r\nB=2\r\n");
    expect(setEnvEntry("", "B", "2")).toBe("B=2\n");
    expect(() => setEnvEntry("", "a b", "1")).toThrow();
    for (const val of ["", " lead", "tab\there", 'q"q\'q', "back\\slash", "multi\r\nline", "#hash", "üñí"]) expect(envValue(setEnvEntry("X=0\n", "X", val), "X")).toBe(val);
    expect(diffEnv("A=1\nB=2\nD=4\n", "A=1\nB=3\nC=4\n")).toEqual({ added: ["C"], changed: ["B"], removed: ["D"] });
  });

  it("checks limits and names downloads", () => {
    expect(() => checkEnvContent("A=" + "x".repeat(MAX_ENV_BYTES - 2))).not.toThrow();
    expect(() => checkEnvContent("A=" + "x".repeat(MAX_ENV_BYTES - 1))).toThrow("too large");
    expect(() => checkEnvContent("é".repeat(MAX_ENV_BYTES / 2 + 1))).toThrow("too large"); // bytes, not characters
    expect(() => checkEnvContent(Array.from({ length: 501 }, (_, i) => `K${i}=1`).join("\n"))).toThrow("too many");
    expect(() => checkEnvContent("A=1\u0000")).toThrow("text");
    expect([envFileName(".env.production"), envFileName("../x"), envFileName(".."), envFileName(undefined)]).toEqual([".env.production", ".env", ".env", ".env"]);
    // A dot name, or none, follows the title's slug (Chrome and Edge drop a leading dot); a plain name stays as it is.
    expect([envFileName(".env", "Billing API"), envFileName(undefined, "Billing API"), envFileName("../x", "Billing API"), envFileName(".env.production", "Web shop"), envFileName("prod.env", "Web shop")])
      .toEqual(["billing-api.env", "billing-api.env", "billing-api.env", "web-shop.env.production", "prod.env"]);
  });
});
