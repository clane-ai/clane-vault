import { describe, expect, it } from "vitest";
import { REDACTED, scrub, variantsOf } from "../src/outbound/scrub.js";

const S = "sk_live/ab+c d\"é!*'";
const forms = (s: string, user: string) => {
  const b = Buffer.from(s, "utf8");
  return [s, b.toString("base64"), b.toString("base64url"), encodeURIComponent(s), b.toString("hex"), b.toString("hex").toUpperCase(),
    Buffer.from(`${user}:${s}`).toString("base64")];
};

describe("variantsOf", () => {
  it("covers raw, base64, base64url, URL-encoded, hex and Basic forms", () => {
    const vs = variantsOf(S, "bob");
    for (const f of forms(S, "bob")) expect(vs).toContain(f);
    expect(variantsOf(S)).not.toContain(Buffer.from(`bob:${S}`).toString("base64"));
  });
  it("covers the form-urlencoded form searchParams.set sends", () => {
    const u = new URL("https://api.test/");
    u.searchParams.set("key", S);
    expect(variantsOf(S)).toContain(u.search.slice("?key=".length));
  });
  it("covers JSON echoes: escaped quote, ASCII-only (Python) and escaped slash (PHP)", () => {
    const vs = variantsOf(S);
    expect(vs).toContain(JSON.stringify(S).slice(1, -1));
    expect(vs).toContain('sk_live/ab+c d\\"\\u00e9!*\'');
    expect(vs).toContain('sk_live\\/ab+c d\\"é!*\'');
  });
  it("covers PHP-escaped base64, base64url, Basic and URL-encoded forms", () => {
    const sec = "????ü";
    const b64 = Buffer.from(sec).toString("base64"), b64u = Buffer.from(sec).toString("base64url"), basic = Buffer.from(`bob:${sec}`).toString("base64");
    expect(b64).toBe("Pz8/P8O8");
    expect(basic).toBe("Ym9iOj8/Pz/DvA==");
    // PHP json_encode defaults: "/" → "\/", non-ASCII → \uXXXX (lower-case hex)
    const php = (x: string) => JSON.stringify(x).slice(1, -1).replaceAll("/", "\\/").replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
    expect(php(b64)).toBe("Pz8\\/P8O8");
    expect(php(sec)).toBe("????\\u00fc");
    const body = `{"a":"${php(b64)}","b":"${php(basic)}","c":"${php(sec)}","d":"${php(b64u)}","e":"${php(encodeURIComponent(sec))}"}`;
    const out = scrub(body, variantsOf(sec, "bob"));
    expect(out.hits).toBe(5);
    expect(out.text).toBe(`{"a":"${REDACTED}","b":"${REDACTED}","c":"${REDACTED}","d":"${REDACTED}","e":"${REDACTED}"}`);
  });
  it("covers Go's <>& escapes, upper-case \\uXXXX and lower-case %xx", () => {
    const sec = "a<b>&c/é";
    const vs = variantsOf(sec);
    expect(vs).toContain("a\\u003cb\\u003e\\u0026c/é");
    expect(vs).toContain("a<b>&c/\\u00E9");
    expect(vs).toContain("a<b>&c\\/\\u00e9");
    expect(vs).toContain("a%3cb%3e%26c%2f%c3%a9");
  });
  it("dedupes and returns nothing for an empty secret", () => {
    expect(variantsOf("abc")).toEqual(["abc", "YWJj", "616263"]);
    expect(new Set(variantsOf("ab/c")).size).toBe(variantsOf("ab/c").length);
    expect(variantsOf("")).toEqual([]);
  });
});

describe("scrub", () => {
  it("redacts every form of the secret in a body and counts hits", () => {
    const body = JSON.stringify({ echo: S, url: `https://api.test/?key=${new URLSearchParams({ k: S }).toString().slice(2)}`, more: forms(S, "bob") });
    const out = scrub(body, variantsOf(S, "bob"));
    for (const f of [...forms(S, "bob"), JSON.stringify(S).slice(1, -1), "sk_live"]) expect(out.text).not.toContain(f);
    expect(out.text).toContain(REDACTED);
    expect(out.hits).toBe(9);
    expect(() => JSON.parse(out.text)).not.toThrow();
  });
  it("replaces the longest variant first, so a longer form is never left half-redacted", () => {
    expect(scrub("a-abcdef-b", ["abc", "abcdef"])).toEqual({ text: `a-${REDACTED}-b`, hits: 1 });
    expect(scrub("abcdef abc", ["abc", "abcdef"])).toEqual({ text: `${REDACTED} ${REDACTED}`, hits: 2 });
  });
  it("leaves clean text alone and ignores empty variants", () => {
    expect(scrub("nothing here", ["", ...variantsOf("s3cr3t-value")])).toEqual({ text: "nothing here", hits: 0 });
    expect(scrub("", variantsOf("x1"))).toEqual({ text: "", hits: 0 });
  });
  it("scrubs a secret split across chunks once the chunks are joined", () => {
    const chunks = [`{"a":"${S.slice(0, 5)}`, `${S.slice(5)}"}`];
    expect(scrub(chunks.join(""), variantsOf(S)).hits).toBe(1);
  });
});
