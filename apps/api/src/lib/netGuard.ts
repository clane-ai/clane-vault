import { lookup } from "node:dns/promises";
import { lookup as dnsLookup } from "node:dns/promises";
import { Agent, fetch as undiciFetch } from "undici";
import { isIP } from "node:net";

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
export const publicOnlyFetch = (url: string, init: RequestInit): Promise<Response> => {
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
