import dns from "node:dns";
import { describe, expect, it, vi } from "vitest";
import type { AgentPolicy } from "@clane-vault/crypto";
import {
  checkMethodPath, defaultResolver, inAllow, isBlockedAddress, isPrivateAddress, matchHost, parseCidrs, Refused, resolveChecked, type Resolver,
} from "../src/outbound/ssrf.js";

// Vectors for the copy of apps/api/src/lib/netGuard.ts isPrivateAddress: keep in step with that function.
const NETGUARD_VECTORS: [string, boolean][] = [
  ["0.0.0.0", true], ["10.0.0.5", true], ["127.0.0.1", true], ["169.254.169.254", true], ["172.16.0.1", true], ["172.31.255.255", true],
  ["172.32.0.1", false], ["192.168.1.1", true], ["100.64.0.1", true], ["100.127.255.255", true], ["100.128.0.1", false], ["224.0.0.1", true],
  ["255.255.255.255", true], ["8.8.8.8", false], ["1.1.1.1", false], ["::1", true], ["::", true], ["::ffff:10.0.0.1", true], ["::ffff:8.8.8.8", false],
  ["fc00::1", true], ["fd00::1", true], ["fe80::1", true], ["febf::1", true], ["ff02::1", true], ["2606:4700::1111", false], ["not-an-ip", true],
];

// Everything the gateway must refuse with no allow list, beyond the netGuard vectors.
const BLOCKED = [
  "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:a9fe:a9fe", "::ffff:127.0.0.1", "::ffff:7f00:1", "[::ffff:10.0.0.1]",
  "0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "::7f00:1", "::127.0.0.1",
  "fd00:ec2::254", "FD00:EC2::254", "fd12:3456::1", "fe80::1%eth0", "fec0::1", "ff05::2",
  "64:ff9b::a9fe:a9fe", "64:ff9b::10.0.0.1", "2002:a9fe:a9fe::1", "2002:7f00:1::", "2001:0:4136:e378::1", "2001:db8::1", "100::1", "64:ff9b:1::1",
  "::ffff:0:a9fe:a9fe", "0:0:0:0:ffff:0:7f00:1", "::ffff:0:127.0.0.1", "::ffff:0:10.0.0.1", "2001:2::1", "3fff::1", "5f00::1",
  "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
  // Not IP literals at all (decimal, octal, hex IPv4 forms and junk): fail closed.
  "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.0.0.1", "127.1", "", "1.2.3.4.5", "999.1.1.1",
];
const PUBLIC = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "::ffff:0:808:808", "2002:808:808::1", "172.32.0.1", "100.128.0.1"];

const stub = (map: Record<string, string[]>): Resolver & { calls: string[] } => {
  const calls: string[] = [];
  const fn = async (host: string) => {
    calls.push(host);
    const a = map[host];
    if (!a) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return a.map((address) => ({ address, family: (address.includes(":") ? 6 : 4) as 4 | 6 }));
  };
  return Object.assign(fn, { calls });
};
const refusedWith = async (p: Promise<unknown>, reason: string) => {
  const e = await p.then(() => null, (x: unknown) => x);
  expect(e).toBeInstanceOf(Refused);
  expect((e as Refused).reason).toBe(reason);
};

describe("isPrivateAddress (copied from netGuard)", () => {
  it.each(NETGUARD_VECTORS)("%s → %s", (ip, want) => expect(isPrivateAddress(ip)).toBe(want));
});

describe("isBlockedAddress", () => {
  it("blocks every netGuard private vector and passes its public ones", () => {
    for (const [ip, priv] of NETGUARD_VECTORS) expect(isBlockedAddress(ip, []), ip).toBe(priv);
  });
  it.each(BLOCKED)("blocks %s", (ip) => expect(isBlockedAddress(ip, [])).toBe(true));
  it.each(PUBLIC)("passes %s", (ip) => expect(isBlockedAddress(ip, [])).toBe(false));

  it("lets an allow range lift a private range, including its IPv4-mapped form", () => {
    const allow = parseCidrs(["127.0.0.0/8", "fd00::/8"]);
    expect(isBlockedAddress("127.0.0.1", allow)).toBe(false);
    expect(isBlockedAddress("::ffff:127.0.0.1", allow)).toBe(false);
    expect(isBlockedAddress("fd12::1", allow)).toBe(false);
    expect(isBlockedAddress("10.0.0.1", allow)).toBe(true);
  });
  it("never lifts the metadata addresses, in any form", () => {
    const allow = parseCidrs(["169.254.0.0/16", "fd00::/8", "0.0.0.0/0", "::/0"]);
    for (const ip of ["169.254.169.254", "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "fd00:ec2::254", "169.254.170.2"])
      expect(isBlockedAddress(ip, allow), ip).toBe(true);
    expect(isBlockedAddress("169.254.1.1", allow)).toBe(false);
  });
});

describe("parseCidrs", () => {
  it("parses v4 and v6 ranges", () => {
    expect(parseCidrs(["10.0.0.0/8", " fd00::/8 "])).toEqual([{ family: 4, bits: 0x0a000000n, prefix: 8 }, { family: 6, bits: 0xfd00n << 112n, prefix: 8 }]);
    expect(inAllow("10.9.9.9", parseCidrs(["10.0.0.0/8"]))).toBe(true);
    expect(inAllow("11.0.0.1", parseCidrs(["10.0.0.0/8"]))).toBe(false);
  });
  it.each(["10.0.0.0", "10.0.0.0/33", "fd00::/129", "10.0.0.0/-1", "10.0.0.0/8/8", "10.0.0/8", "example.com/8", "10.0.0.0/ 8", "10.0.0.0/08x", ""])("refuses %j", (c) =>
    expect(() => parseCidrs([c])).toThrow(/CIDR/));
});

describe("matchHost", () => {
  it("matches exactly one label under a wildcard", () => {
    expect(matchHost(["*.github.com"], new URL("https://api.github.com/x"))).toBe("*.github.com");
    expect(matchHost(["*.github.com"], new URL("https://a.b.github.com/x"))).toBeNull();
    expect(matchHost(["*.github.com"], new URL("https://github.com/x"))).toBeNull();
    expect(matchHost(["*.github.com"], new URL("https://evilgithub.com/x"))).toBeNull();
  });
  it("never lets a wildcard over a public suffix match the bare suffix", () => {
    expect(matchHost(["*.co.uk"], new URL("https://co.uk/"))).toBeNull();
    expect(matchHost(["*.co.uk"], new URL("https://shop.co.uk/"))).toBe("*.co.uk");
  });
  it("uses the default port when the policy names none", () => {
    expect(matchHost(["api.test"], new URL("https://api.test:8443/"))).toBeNull();
    expect(matchHost(["api.test:8443"], new URL("https://api.test:8443/"))).toBe("api.test:8443");
    expect(matchHost(["api.test"], new URL("https://api.test:443/"))).toBe("api.test");
    expect(matchHost(["api.test:443"], new URL("https://api.test/"))).toBe("api.test:443");
    expect(matchHost(["api.test:8443"], new URL("https://api.test/"))).toBeNull();
    expect(matchHost(["api.test"], new URL("http://api.test/"))).toBe("api.test");
    expect(matchHost(["api.test"], new URL("http://api.test:443/"))).toBeNull();
  });
  it("returns the first matching entry and null for an unlisted host", () => {
    expect(matchHost(["x.test", "api.test", "*.test"], new URL("https://api.test/"))).toBe("api.test");
    expect(matchHost(["api.test"], new URL("https://other.test/"))).toBeNull();
    expect(matchHost(["api.test"], new URL("https://api.test.evil.com/"))).toBeNull();
  });
  it("never matches an IP literal, even through a wildcard", () => {
    for (const u of ["https://127.0.0.1/", "https://2130706433/", "https://0x7f.0.0.1/", "https://[::1]/", "https://1.2.3.4/"])
      expect(matchHost(["*.0.1", "*.0.0.1", "*.3.4", "*.2.3.4", "127.0.0.1"], new URL(u)), u).toBeNull();
  });
  it("refuses other schemes and a trailing-dot host", () => {
    expect(matchHost(["api.test"], new URL("ftp://api.test/"))).toBeNull();
    expect(matchHost(["api.test"], new URL("https://api.test./"))).toBeNull();
  });
});

describe("checkMethodPath", () => {
  const p = (x: Partial<AgentPolicy>): AgentPolicy => ({ v: 1, hosts: ["api.test"], inject: { kind: "bearer" }, ...x });
  const u = (path: string) => new URL(`https://api.test${path}`);
  it("allows anything when methods and paths are absent", () => expect(checkMethodPath(p({}), "DELETE", u("/any/thing"))).toBeNull());
  it("treats empty methods and paths as deny-all", () => {
    expect(checkMethodPath(p({ methods: [] }), "GET", u("/"))).toBe("method");
    expect(checkMethodPath(p({ paths: [] }), "GET", u("/"))).toBe("path");
  });
  it("requires a listed method", () => {
    expect(checkMethodPath(p({ methods: ["GET"] }), "GET", u("/"))).toBeNull();
    expect(checkMethodPath(p({ methods: ["GET"] }), "POST", u("/"))).toBe("method");
  });
  it("matches paths by whole segments", () => {
    const pol = p({ paths: ["/v1/charges", "/files/"] });
    for (const ok of ["/v1/charges", "/v1/charges/ch_1", "/files/a", "/v1/charges?x=1"]) expect(checkMethodPath(pol, "GET", u(ok)), ok).toBeNull();
    for (const bad of ["/v1/chargesX", "/v1", "/files", "/v1/x/../../admin", "/v1/charges/%2e%2e/%2e%2e/admin", "/V1/charges"])
      expect(checkMethodPath(pol, "GET", u(bad)), bad).toBe("path");
    expect(checkMethodPath(p({ paths: ["/"] }), "GET", u("/anything"))).toBeNull();
  });
  it.each(["/v1/charges/%2e%2e%2fadmin", "/v1/charges/..%2f..%2fadmin", "/v1/charges/%2E%2E%2Fadmin", "/v1/charges/..%5cadmin", "/v1/charges/..%5Cadmin",
    "/v1/charges/x%2Ey", "/v1/charges/a%2Fb"])("refuses an encoded slash, backslash or dot: %s", (path) => {
    expect(checkMethodPath(p({ paths: ["/v1/charges"] }), "GET", u(path))).toBe("path");
    expect(checkMethodPath(p({}), "GET", u(path))).toBe("path");
  });
  it("refuses a path with control characters, raw or encoded", () => {
    const pol = p({ paths: ["/"] });
    for (const bad of ["/a%00b", "/a%0d%0aX-Injected:1", "/a%1F", "/a%7f"]) expect(checkMethodPath(pol, "GET", u(bad)), bad).toBe("path");
    expect(checkMethodPath(p({}), "GET", u("/a%0Ab"))).toBe("path");
  });
});

describe("resolveChecked", () => {
  it.each(["127.0.0.1", "10.0.0.5", "169.254.169.254", "fd00::1", "::ffff:10.0.0.1", "fd00:ec2::254", "0.0.0.0", "::"])("refuses a host resolving to %s", async (ip) => {
    const r = stub({ "evil.test": [ip] });
    await refusedWith(resolveChecked("evil.test", { resolve: r, allow: [] }), "ssrf");
  });
  it("refuses metadata.google.internal by name without resolving it", async () => {
    const r = stub({ "metadata.google.internal": ["8.8.8.8"], metadata: ["8.8.8.8"] });
    for (const h of ["metadata.google.internal", "METADATA.Google.Internal.", "metadata"]) await refusedWith(resolveChecked(h, { resolve: r, allow: [] }), "ssrf");
    expect(r.calls).toEqual([]);
  });
  it("refuses when any address in a mixed answer is private", async () => {
    for (const mix of [["8.8.8.8", "10.0.0.1"], ["10.0.0.1", "8.8.8.8"], ["2606:4700::1", "::ffff:a9fe:a9fe"]])
      await refusedWith(resolveChecked("mix.test", { resolve: stub({ "mix.test": mix }), allow: [] }), "ssrf");
  });
  it("refuses an empty answer and maps a resolver failure to upstream_error", async () => {
    await refusedWith(resolveChecked("none.test", { resolve: async () => [], allow: [] }), "ssrf");
    await refusedWith(resolveChecked("nx.test", { resolve: stub({}), allow: [] }), "upstream_error");
  });
  it("refuses 169.254.169.254 even with 169.254.0.0/16 allowed", async () => {
    await refusedWith(resolveChecked("meta.test", { resolve: stub({ "meta.test": ["169.254.169.254"] }), allow: parseCidrs(["169.254.0.0/16"]) }), "ssrf");
  });
  it("returns the first address, with viaAllow when an allow range covers it", async () => {
    const r = stub({ "api.test": ["127.0.0.1"], "pub.test": ["8.8.8.8", "2606:4700::1"] });
    expect(await resolveChecked("api.test", { resolve: r, allow: parseCidrs(["127.0.0.0/8"]) })).toEqual({ address: "127.0.0.1", family: 4, viaAllow: true });
    expect(await resolveChecked("pub.test", { resolve: r, allow: parseCidrs(["127.0.0.0/8"]) })).toEqual({ address: "8.8.8.8", family: 4, viaAllow: false });
  });
  it("checks IP literals (any form) directly, without the resolver", async () => {
    const r = stub({});
    for (const h of ["127.0.0.1", "2130706433", "0x7f.1", "0177.0.0.1", "[::1]", "[::ffff:169.254.169.254]", "[::]", "0.0.0.0"])
      await refusedWith(resolveChecked(h, { resolve: r, allow: [] }), "ssrf");
    expect(await resolveChecked("[2606:4700::1]", { resolve: r, allow: [] })).toEqual({ address: "2606:4700::1", family: 6, viaAllow: false });
    expect(r.calls).toEqual([]);
  });
  it("calls the resolver once per check (no cached answer survives a rebinding)", async () => {
    let n = 0;
    const r: Resolver = async () => [{ address: n++ === 0 ? "127.0.0.1" : "10.9.9.9", family: 4 }];
    const allow = parseCidrs(["127.0.0.0/8"]);
    expect((await resolveChecked("api.test", { resolve: r, allow })).address).toBe("127.0.0.1");
    await refusedWith(resolveChecked("api.test", { resolve: r, allow }), "ssrf");
    expect(n).toBe(2);
  });
  it("Refused carries the reason only, never the host", async () => {
    const e = await resolveChecked("secret-host.test", { resolve: stub({ "secret-host.test": ["10.0.0.1"] }), allow: [] }).catch((x: Error) => x);
    expect(String((e as Error).message)).not.toContain("secret-host");
  });
});

describe("defaultResolver", () => {
  it("calls dns.promises.lookup through the namespace at call time", async () => {
    const spy = vi.spyOn(dns.promises, "lookup").mockResolvedValue([{ address: "8.8.8.8", family: 4 }] as never);
    try {
      expect(await defaultResolver("x.test")).toEqual([{ address: "8.8.8.8", family: 4 }]);
      expect(spy).toHaveBeenCalledWith("x.test", { all: true, verbatim: true });
    } finally { spy.mockRestore(); }
  });
});
