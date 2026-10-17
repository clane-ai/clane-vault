import dns from "node:dns";
import { isIP } from "node:net";
import type { AgentMethod, AgentPolicy } from "@clane-vault/crypto";

export type RefuseReason = "host" | "scheme" | "ssrf" | "method" | "path" | "timeout" | "request_too_large" | "upstream_error";
/** Carries the reason only: never a host, URL, header or value. */
export class Refused extends Error {
  constructor(public reason: RefuseReason) { super(reason); this.name = "Refused"; }
}

export type Resolver = (host: string) => Promise<{ address: string; family: 4 | 6 }[]>;
// Read through the namespace at call time, so a patched dns.promises.lookup (e2e hosts.mjs) is the one used.
export const defaultResolver: Resolver = (host) => dns.promises.lookup(host, { all: true, verbatim: true }) as ReturnType<Resolver>;

export interface Cidr { family: 4 | 6; bits: bigint; prefix: number }
type Addr = { family: 4 | 6; bits: bigint };

// copied from apps/api/src/lib/netGuard.ts (the gateway can't depend on apps/api); isBlockedAddress extends it.
/** Loopback, private, link-local, CGNAT, unique-local and other non-public ranges. */
export function isPrivateAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (v === 6) {
    const x = ip.toLowerCase();
    if (x === "::1" || x === "::") return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x);
    if (mapped) return isPrivateAddress(mapped[1]!);
    return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(x);
  }
  return true;
}

const v4bits = (s: string) => s.split(".").reduce((a, p) => (a << 8n) | BigInt(p), 0n);
const v4str = (b: bigint) => [24n, 16n, 8n, 0n].map((s) => Number((b >> s) & 255n)).join(".");

/** A strict IP literal (brackets and an IPv6 zone allowed) as bits; null for anything else, including 2130706433-style forms. */
function parseIp(ip: string): Addr | null {
  let s = ip.replace(/^\[(.*)\]$/, "$1").split("%")[0]!;
  const v = isIP(s);
  if (v === 4) return { family: 4, bits: v4bits(s) };
  if (v !== 6) return null;
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) { const b = v4bits(tail[2]!); s = `${tail[1]}${(b >> 16n).toString(16)}:${(b & 0xffffn).toString(16)}`; }
  const [head, rest] = s.split("::") as [string, string | undefined];
  const h = head ? head.split(":") : [];
  const r = rest ? rest.split(":") : [];
  const groups = rest === undefined ? h : [...h, ...Array<string>(8 - h.length - r.length).fill("0"), ...r];
  return { family: 6, bits: groups.reduce((a, g) => (a << 16n) | BigInt(`0x${g}`), 0n) };
}

const inCidr = (a: Addr, c: Cidr) => {
  const w = BigInt(a.family === 4 ? 32 : 128) - BigInt(c.prefix);
  return a.family === c.family && a.bits >> w === c.bits >> w;
};

/** Throws on a bad entry. Entries are "address/prefix"; the message names the entry (config, not a secret). */
export function parseCidrs(list: string[]): Cidr[] {
  return list.map((raw) => {
    const e = raw.trim();
    const m = /^([^/]+)\/(\d{1,3})$/.exec(e);
    const a = m && isIP(m[1]!) ? parseIp(m[1]!) : null;
    const prefix = m ? Number(m[2]) : NaN;
    if (!a || prefix > (a.family === 4 ? 32 : 128)) throw new Error(`not a CIDR: "${e}"`);
    return { family: a.family, bits: a.bits, prefix };
  });
}

const [MAPPED, SIIT, NAT64, SIX_TO_FOUR] = parseCidrs(["::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96", "2002::/16"]) as [Cidr, Cidr, Cidr, Cidr];
const MASK32 = 0xffffffffn;
/** IPv6 forms that carry an IPv4 address (mapped, SIIT IPv4-translated per RFC 2765, NAT64, 6to4) become that IPv4 address. */
function embedded(a: Addr): Addr {
  if (a.family === 6 && (inCidr(a, MAPPED) || inCidr(a, SIIT) || inCidr(a, NAT64))) return { family: 4, bits: a.bits & MASK32 };
  if (a.family === 6 && inCidr(a, SIX_TO_FOUR)) return { family: 4, bits: (a.bits >> 80n) & MASK32 };
  return a;
}

// Cloud metadata endpoints (AWS/GCP/Azure, AWS IPv6, ECS task metadata, Azure wireserver, Alibaba): never lifted by `allow`.
const METADATA = parseCidrs(["169.254.169.254/32", "fd00:ec2::254/128", "169.254.170.2/32", "168.63.129.16/32", "100.100.100.200/32"]);
// Ranges isPrivateAddress misses: IPv4-compatible/unspecified/loopback ::/96, site-local, Teredo, documentation, discard,
// local NAT64, v6 benchmarking (2001:2::/48), v6 documentation (3fff::/20), SRv6 SIDs (5f00::/16), IETF protocol
// assignments, IPv4 documentation and benchmarking nets.
const EXTRA = parseCidrs(["::/96", "fec0::/10", "2001::/32", "2001:db8::/32", "100::/64", "64:ff9b:1::/48", "2001:2::/48", "3fff::/20", "5f00::/16",
  "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"]);

const fmt = (a: Addr) => a.family === 4 ? v4str(a.bits) : Array.from({ length: 8 }, (_, i) => ((a.bits >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(":");

/** True when an `allow` range covers the address (IPv4-embedding IPv6 forms are judged as their IPv4 address). */
export function inAllow(ip: string, allow: Cidr[]): boolean {
  const a = parseIp(ip);
  return !!a && allow.some((c) => inCidr(embedded(a), c));
}

/** Loopback, link-local, private, CGNAT, multicast, unspecified, IPv4-mapped forms of these, 169.254.169.254, fd00:ec2::254. `allow` lifts a range except the metadata addresses. */
export function isBlockedAddress(ip: string, allow: Cidr[]): boolean {
  const raw = parseIp(ip);
  if (!raw) return true;
  const a = embedded(raw);
  if (METADATA.some((c) => inCidr(a, c) || inCidr(raw, c))) return true;
  if (allow.some((c) => inCidr(a, c))) return false;
  // fmt() writes uncompressed v6 ("0:0:0:0:0:0:0:1"), so isPrivateAddress misses ::1 and ::; EXTRA's ::/96 catches them.
  return isPrivateAddress(fmt(a)) || EXTRA.some((c) => inCidr(a, c) || inCidr(raw, c));
}

/** The matching policy entry, or null. No port in policy = the scheme's default port only; "*.a.com" = exactly one label; never an IP literal. */
export function matchHost(policyHosts: string[], url: URL): string | null {
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  const host = url.hostname;
  if (host.startsWith("[") || isIP(host)) return null;
  for (const entry of policyHosts) {
    const [name = "", port = ""] = entry.toLowerCase().split(":");
    if (port !== url.port && !(url.port === "" && port === (url.protocol === "https:" ? "443" : "80"))) continue;
    const sfx = name.slice(1); // "*.a.com" → ".a.com"; the label in front must be non-empty and dot-free
    if (name.startsWith("*.") ? host.endsWith(sfx) && host.length > sfx.length && !host.slice(0, -sfx.length).includes(".") : host === name) return entry;
  }
  return null;
}

// Raw C0/DEL (the URL parser already encodes most) or their percent-encoded forms; also an encoded "/", "\" or ".", which
// url.pathname keeps encoded but an upstream proxy may decode into another path (/v1/x/..%2f..%2fadmin).
const REFUSED_PATH = /[\x00-\x1f\x7f]|%(?:[01][0-9a-f]|7f|2f|5c|2e)/i;

/**
 * Rule 2 after matchHost. A present-but-empty `methods` or `paths` denies every call (fail closed). Paths match by whole
 * segments ("/v1" covers "/v1" and "/v1/x", not "/v1x"; "/files/" covers "/files/a"). A path with control characters or an encoded
 * "/", "\" or "." is refused, with or without `paths`.
 */
export function checkMethodPath(policy: Pick<AgentPolicy, "methods" | "paths">, method: AgentMethod, url: URL): "method" | "path" | null {
  if (policy.methods && !policy.methods.includes(method)) return "method";
  const path = url.pathname;
  if (REFUSED_PATH.test(path)) return "path";
  if (policy.paths && !policy.paths.some((p) => path === p || path.startsWith(p.endsWith("/") ? p : `${p}/`))) return "path";
  return null;
}

const BLOCKED_NAMES = new Set(["metadata.google.internal", "metadata"]);

/** IP literals in any form the URL parser accepts (2130706433, 0x7f.1, [::1]) as a canonical address; null for a name. */
function literalOf(h: string): string | null {
  if (isIP(h)) return h;
  const host = new URL(`http://${h.includes(":") ? `[${h}]` : h}/`).hostname; // throws on junk
  const bare = host.replace(/^\[(.*)\]$/, "$1");
  return isIP(bare) ? bare : null;
}

/**
 * Resolves once and refuses (Refused "ssrf") unless EVERY address is allowed; metadata names are refused without resolving.
 * The caller connects to the returned address, so the checked address is the one used.
 */
export async function resolveChecked(host: string, o: { resolve: Resolver; allow: Cidr[] }): Promise<{ address: string; family: 4 | 6; viaAllow: boolean }> {
  const h = host.toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.+$/, "");
  if (!h || BLOCKED_NAMES.has(h)) throw new Refused("ssrf");
  let lit: string | null;
  try { lit = literalOf(h); } catch { throw new Refused("ssrf"); }
  let addrs: { address: string }[];
  if (lit) addrs = [{ address: lit }];
  else {
    try { addrs = await o.resolve(h); } catch { throw new Refused("upstream_error"); }
  }
  if (!addrs.length || addrs.some((a) => isBlockedAddress(a.address, o.allow))) throw new Refused("ssrf");
  const address = addrs[0]!.address.split("%")[0]!;
  return { address, family: isIP(address) as 4 | 6, viaAllow: inAllow(address, o.allow) };
}
