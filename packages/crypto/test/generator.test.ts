import { describe, expect, it } from "vitest";
import { generatePassword } from "../src/index.js";

describe("generatePassword", () => {
  it("defaults to 20 chars with every class", () => {
    const p = generatePassword();
    expect(p).toHaveLength(20);
    expect(p).toMatch(/[a-z]/); expect(p).toMatch(/[A-Z]/); expect(p).toMatch(/[0-9]/); expect(p).toMatch(/[^A-Za-z0-9]/);
  });
  it("honours options", () => {
    const p = generatePassword({ length: 32, symbols: false });
    expect(p).toHaveLength(32);
    expect(p).toMatch(/^[A-Za-z0-9]+$/);
  });
  it("avoids ambiguous characters", () => {
    for (let i = 0; i < 50; i++) expect(generatePassword({ length: 64 })).not.toMatch(/[Il1O0]/);
  });
  it("rejects impossible options", () => {
    expect(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false })).toThrow();
    expect(() => generatePassword({ length: 3 })).toThrow();
  });
  it("rejects NaN length", () => {
    expect(() => generatePassword({ length: NaN })).toThrow(/length must be 8–128/);
  });
  it("rejects float length", () => {
    expect(() => generatePassword({ length: 20.5 })).toThrow(/length must be 8–128/);
  });
  it("treats undefined length as default", () => {
    expect(generatePassword({ length: undefined })).toHaveLength(20);
  });
  it("accepts boundary lengths 8 and 128", () => {
    expect(generatePassword({ length: 8 })).toHaveLength(8);
    expect(generatePassword({ length: 128 })).toHaveLength(128);
  });
});
