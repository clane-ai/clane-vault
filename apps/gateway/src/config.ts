import { z } from "zod";

export interface GatewayConfig {
  apiUrl: string; apiToken: string; publicUrl: string; kek: string; identityKeyFile: string; cacheTtlSeconds: number; agentRatePerMinute: number;
  maxResponseBytes: number; upstreamTimeoutMs: number; allowPrivateCidrs: string[]; port: number; internalPort: number; trustProxy: number;
}

const blank = (v: unknown) => (v === "" ? undefined : v);
const int = (def: number, min = 0) => z.preprocess(blank, z.coerce.number().int().min(min).default(def));
const schema = z.object({
  API_URL: z.string().url(),
  GATEWAY_API_TOKEN: z.string().min(32, "GATEWAY_API_TOKEN must be at least 32 characters"),
  PUBLIC_URL: z.string().url(),
  GATEWAY_KEK: z.string().min(1, "GATEWAY_KEK is required"),
  GATEWAY_IDENTITY_KEY_FILE: z.string().min(1, "GATEWAY_IDENTITY_KEY_FILE is required"),
  GATEWAY_CACHE_TTL_SECONDS: int(60),
  GATEWAY_AGENT_RATE_PER_MINUTE: int(60, 1),
  GATEWAY_MAX_RESPONSE_BYTES: int(4194304, 1),
  GATEWAY_UPSTREAM_TIMEOUT_MS: int(30000, 1),
  GATEWAY_ALLOW_PRIVATE_CIDRS: z.string().default(""),
  PORT: int(3002, 1),
  INTERNAL_PORT: int(3003, 1),
  TRUST_PROXY: int(0),
});

const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const r = schema.safeParse(env);
  // Name the variable and the rule only; zod issues never carry the input value here.
  if (!r.success) throw new Error(r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  const e = r.data;
  const pub = new URL(e.PUBLIC_URL);
  if (pub.protocol !== "https:" && !(pub.protocol === "http:" && LOCAL.has(pub.hostname)))
    throw new Error("PUBLIC_URL must be https (http only for localhost)");
  return {
    apiUrl: e.API_URL, apiToken: e.GATEWAY_API_TOKEN, publicUrl: e.PUBLIC_URL, kek: e.GATEWAY_KEK, identityKeyFile: e.GATEWAY_IDENTITY_KEY_FILE,
    cacheTtlSeconds: e.GATEWAY_CACHE_TTL_SECONDS, agentRatePerMinute: e.GATEWAY_AGENT_RATE_PER_MINUTE, maxResponseBytes: e.GATEWAY_MAX_RESPONSE_BYTES,
    upstreamTimeoutMs: e.GATEWAY_UPSTREAM_TIMEOUT_MS, allowPrivateCidrs: e.GATEWAY_ALLOW_PRIVATE_CIDRS.split(",").map((s) => s.trim()).filter(Boolean),
    port: e.PORT, internalPort: e.INTERNAL_PORT, trustProxy: e.TRUST_PROXY,
  };
}
