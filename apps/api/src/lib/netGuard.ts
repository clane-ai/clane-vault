import { lookup } from "node:dns/promises";
import { lookup as dnsLookup } from "node:dns/promises";
import { Agent, fetch as undiciFetch } from "undici";
import { isIP } from "node:net";

type Addr = { v6: boolean; bits: bigint };
const v4bits = (s: string) => s.split(".").reduce((a, p) => (a << 8n) | BigInt(p), 0n);

/** A strict IP literal (an IPv6 zone allowed) as bits; null for anything else (names, 2130706433-style forms, brackets). */
function parseIp(ip: string): Addr | null {
  const v = isIP(ip);
  if (v === 4) return { v6: false, bits: v4bits(ip) };
  if (v !== 6) return null;
  let s = ip.split("%")[0]!;
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) { const b = v4bits(tail[2]!); s = `${tail[1]}${(b >> 16n).toString(16)}:${(b & 0xffffn).toString(16)}`; }
  const [head, rest] = s.split("::") as [string, string | undefined];
  const h = head ? head.split(":") : [];
  const r = rest ? rest.split(":") : [];
  const groups = rest === undefined ? h : [...h, ...Array<string>(8 - h.length - r.length).fill("0"), ...r];
  if (groups.length !== 8) return null;
  return { v6: true, bits: groups.reduce((a, g) => (a << 16n) | BigInt(`0x${g}`), 0n) };
}

const cidr = (c: string) => { const [ip, p] = c.split("/") as [string, string]; return { ...parseIp(ip)!, prefix: Number(p) }; };
const inCidr = (a: Addr, c: ReturnType<typeof cidr>) => {
  const w = BigInt((a.v6 ? 128 : 32) - c.prefix);
  return a.v6 === c.v6 && a.bits >> w === c.bits >> w;
};
const MASK32 = 0xffffffffn;
// IPv4 carried in IPv6: mapped, SIIT (RFC 2765), NAT64 well-known prefix (low 32 bits); 6to4 (bits 16-48).
const EMBED_LOW = ["::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96"].map(cidr);
const SIX_TO_FOUR = cidr("2002::/16");
const embedded = (a: Addr): Addr =>
  EMBED_LOW.some((c) => inCidr(a, c)) ? { v6: false, bits: a.bits & MASK32 }
    : inCidr(a, SIX_TO_FOUR) ? { v6: false, bits: (a.bits >> 80n) & MASK32 } : a;

const BLOCKED = [
  // IPv4: this network, RFC1918, CGNAT, loopback, link-local (169.254.169.254 metadata), IETF protocol, documentation,
  // benchmarking, multicast, reserved and broadcast; Azure wireserver metadata.
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
  "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
  // IPv6: ::/96 (unspecified, loopback and the deprecated IPv4-compatible form), discard, Teredo, benchmarking, documentation,
  // local-use NAT64 (its IPv4 can sit anywhere), 3fff::/20 documentation, SRv6 SIDs, unique-local (fd00:ec2::254 metadata),
  // link-local, site-local, multicast.
  "::/96", "100::/64", "2001::/32", "2001:2::/48", "2001:db8::/32", "64:ff9b:1::/48", "3fff::/20", "5f00::/16",
  "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
].map(cidr);

/**
 * Loopback, private, link-local, CGNAT, unique-local, metadata, documentation and other non-public ranges, with IPv6
 * forms that carry an IPv4 address judged as that address. Anything that isn't a plain IP literal counts as private.
 */
export function isPrivateAddress(ip: string): boolean {
  const raw = parseIp(ip);
  if (!raw) return true;
  const a = embedded(raw);
  return BLOCKED.some((c) => inCidr(a, c) || inCidr(raw, c));
}

export class PrivateHostError extends Error {
  constructor(public host: string) { super(`${host} resolves to a private address`); this.name = "PrivateHostError"; }
}

/**
 * HOSTED_MODE: organisation admins are not trusted with the server's network, so hosts they configure (an SSO issuer
 * and its endpoints, an SMTP server) must resolve only to public addresses. Self-hosted servers skip this (an internal
 * identity provider or relay is normal there). DNS rebinding between this check and the connection remains possible;
 * it narrows the attack, it doesn't remove it.
 */
export async function assertPublicHost(host: string): Promise<void> {
  const h = host.replace(/^\[|\]$/g, "");
  const addrs = isIP(h) ? [h] : (await lookup(h, { all: true, verbatim: true })).map((a) => a.address);
  if (!addrs.length || addrs.some(isPrivateAddress)) throw new PrivateHostError(host);
}

type LookupCb = (err: NodeJS.ErrnoException | null, address?: string | { address: string; family: number }[], family?: number) => void;
/**
 * A `lookup` for sockets that resolves the name once and refuses private addresses: the address that is checked is the
 * one connected to (no DNS-rebinding gap between a check and the connection).
 */
export function publicOnlyLookup(hostname: string, options: { all?: boolean; family?: number } | number, cb: LookupCb): void {
  const opts = typeof options === "number" ? { family: options } : options ?? {};
  dnsLookup(hostname, { all: true, verbatim: true }).then((addrs) => {
    const list = addrs.filter((a) => !opts.family || a.family === opts.family);
    if (!list.length || list.some((a) => isPrivateAddress(a.address))) { cb(Object.assign(new PrivateHostError(hostname), { code: "EPRIVATE" })); return; }
    if (opts.all) cb(null, list);
    else cb(null, list[0]!.address, list[0]!.family);
  }, (e: NodeJS.ErrnoException) => cb(e));
}

let publicAgent: Agent | null = null;
/** fetch whose connections only ever go to public addresses (HOSTED_MODE: SSO discovery, token and JWKS requests). */
export const publicOnlyFetch = async (url: string, init: RequestInit): Promise<Response> => {
  // A URL with an IP literal (say a token_endpoint or jwks_uri from discovery) connects without a lookup: check it here.
  const h = new URL(String(url)).hostname.replace(/^\[|\]$/g, "");
  if (isIP(h) && isPrivateAddress(h)) throw new TypeError("fetch failed", { cause: Object.assign(new PrivateHostError(h), { code: "EPRIVATE" }) });
  publicAgent ??= new Agent({ connect: { lookup: publicOnlyLookup as never } });
  return undiciFetch(url, { ...(init as object), dispatcher: publicAgent } as never) as unknown as Promise<Response>;
};

/** Resolves once to a public address (SMTP in HOSTED_MODE then connects to that IP, with TLS checked against the name). */
export async function resolvePublic(host: string): Promise<string> {
  const h = host.replace(/^\[|\]$/g, "");
  if (isIP(h)) { if (isPrivateAddress(h)) throw new PrivateHostError(host); return h; }
  const addrs = await dnsLookup(h, { all: true, verbatim: true });
  if (!addrs.length || addrs.some((a) => isPrivateAddress(a.address))) throw new PrivateHostError(host);
  return addrs[0]!.address;
}
