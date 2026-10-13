import { describe, expect, it } from "vitest";
import { totpCode, totpSecondsLeft, base32Decode } from "../src/index.js";

// RFC 6238 Appendix B, SHA-1 seed "12345678901234567890" = base32 below
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp", () => {
  it("decodes base32 with spaces and lowercase", () => {
    expect(new TextDecoder().decode(base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"))).toBe("12345678901234567890");
  });
  it("matches RFC 6238 vectors (8 digits)", async () => {
    expect(await totpCode(SEED, 59_000, 8)).toBe("94287082");
    expect(await totpCode(SEED, 1111111109_000, 8)).toBe("07081804");
    expect(await totpCode(SEED, 1234567890_000, 8)).toBe("89005924");
  });
  it("gives 6 digits by default", async () => {
    expect(await totpCode(SEED, 59_000)).toBe("287082");
  });
  it("counts down within the period", () => {
    expect(totpSecondsLeft(59_000)).toBe(1);
    expect(totpSecondsLeft(60_000)).toBe(30);
  });
});
