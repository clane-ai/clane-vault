import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { isPrivateAddress, publicOnlyFetch } from "../src/lib/netGuard.js";

// The real undici fetch with the public-only dispatcher dropped, so a redirect test can use a local server. The URL's own
// literal check still runs in publicOnlyFetch first.
const fetchCalls = vi.hoisted(() => [] as { redirect?: string }[]);
vi.mock("undici", async (orig) => {
  const u = await orig<typeof import("undici")>();
  return { ...u, fetch: (url: string, init: { redirect?: string; dispatcher?: unknown }) => {
    fetchCalls.push({ redirect: init.redirect });
    const { dispatcher: _d, ...rest } = init;
    return u.fetch(url.replace("://public.test", "://127.0.0.1"), rest as never);
  } };
});

// The gateway's vectors (apps/gateway/test/ssrf.test.ts NETGUARD_VECTORS, BLOCKED, PUBLIC), plus forms the WHATWG URL
// parser produces from bracketed hosts.
const VECTORS: [string, boolean][] = [
  ["0.0.0.0", true], ["10.0.0.5", true], ["127.0.0.1", true], ["169.254.169.254", true], ["172.16.0.1", true], ["172.31.255.255", true],
  ["172.32.0.1", false], ["192.168.1.1", true], ["100.64.0.1", true], ["100.127.255.255", true], ["100.128.0.1", false], ["224.0.0.1", true],
  ["255.255.255.255", true], ["8.8.8.8", false], ["1.1.1.1", false], ["::1", true], ["::", true], ["::ffff:10.0.0.1", true], ["::ffff:8.8.8.8", false],
  ["fc00::1", true], ["fd00::1", true], ["fe80::1", true], ["febf::1", true], ["ff02::1", true], ["2606:4700::1111", false], ["not-an-ip", true],
];

const BLOCKED = [
  // IPv4-mapped, in dotted and hex forms (new URL("http://[::ffff:169.254.169.254]/").hostname is "[::ffff:a9fe:a9fe]").
  "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:a9fe:a9fe", "::FFFF:A9FE:A9FE", "::ffff:127.0.0.1", "::ffff:7f00:1",
  // Unspecified and loopback, compressed or not; deprecated IPv4-compatible.
  "::", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::7f00:1", "::127.0.0.1",
  "::169.254.169.254", "::a9fe:a9fe",
  // Metadata, unique-local, link-local with a zone, site-local, multicast.
  "fd00:ec2::254", "FD00:EC2::254", "fd12:3456::1", "fe80::1%eth0", "fec0::1", "ff05::2",
  // NAT64, 6to4, Teredo, documentation, discard, local-use NAT64.
  "64:ff9b::a9fe:a9fe", "64:ff9b::169.254.169.254", "64:ff9b::10.0.0.1", "2002:a9fe:a9fe::", "2002:a9fe:a9fe::1", "2002:7f00:1::",
  "2001:0:4136:e378::1", "2001:db8::1", "100::1", "64:ff9b:1::1",
  // SIIT (::ffff:0:0:0/96).
  "::ffff:0:a9fe:a9fe", "0:0:0:0:ffff:0:7f00:1", "::ffff:0:127.0.0.1", "::ffff:0:10.0.0.1",
  "2001:2::1", "3fff::1", "5f00::1",
  // IPv4 special ranges: IETF protocol, documentation, benchmarking, reserved, broadcast, Azure wireserver, ECS, Alibaba.
  "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255",
  "168.63.129.16", "169.254.170.2", "100.100.100.200",
  // Not clean IP literals (decimal, octal, hex IPv4 forms, brackets, junk): fail closed.
  "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.0.0.1", "127.1", "", "1.2.3.4.5", "999.1.1.1", "[::1]", "[::ffff:10.0.0.1]", "localhost", " 8.8.8.8",
];
const PUBLIC = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "::ffff:808:808", "64:ff9b::808:808", "::ffff:0:808:808",
  "2002:808:808::1", "172.32.0.1", "100.128.0.1", "198.20.0.1", "2a00:1450:4001:80b::200e"];

describe("isPrivateAddress", () => {
  it.each(VECTORS)("%s → %s", (ip, want) => expect(isPrivateAddress(ip)).toBe(want));
  it.each(BLOCKED)("blocks %j", (ip) => expect(isPrivateAddress(ip)).toBe(true));
  it.each(PUBLIC)("passes %s", (ip) => expect(isPrivateAddress(ip)).toBe(false));
  it("judges the hostname the URL parser gives for a bracketed metadata address", () => {
    const h = new URL("http://[::ffff:169.254.169.254]/").hostname.replace(/^\[|\]$/g, "");
    expect(h).toBe("::ffff:a9fe:a9fe");
    expect(isPrivateAddress(h)).toBe(true);
  });
});

describe("publicOnlyFetch", () => {
  it("refuses an IP-literal URL on a private address without connecting (no lookup happens for literals)", async () => {
    for (const u of ["http://[::ffff:169.254.169.254]/latest/meta-data/", "http://127.0.0.1:1/", "http://[64:ff9b::a9fe:a9fe]/"]) {
      const e = await publicOnlyFetch(u, {}).then(() => null, (x: Error & { cause?: { code?: string } }) => x);
      expect(e?.cause?.code, u).toBe("EPRIVATE");
    }
  });
  it("never follows a redirect, even when the caller asks to", async () => {
    let hits = 0;
    const srv = createServer((req, res) => { hits++; res.writeHead(302, { location: "http://[::ffff:169.254.169.254]/latest/meta-data/" }).end(); });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const { port } = srv.address() as AddressInfo;
      fetchCalls.length = 0;
      const res = await publicOnlyFetch(`http://public.test:${port}/`, { redirect: "follow" });
      expect(res.status).toBe(302);
      expect(hits).toBe(1);
      expect(fetchCalls).toEqual([{ redirect: "manual" }]);
    } finally { srv.close(); }
  });
});
