import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { z } from "zod";
import { b64url, generateKeyPair } from "@clane-vault/crypto";
import type { GatewayConfig } from "./config.js";
import { wrapAgentKey } from "./envelope.js";
import type { Identity } from "./identity.js";
import type { Kek } from "./kek.js";
import { safeError, type HeldSecrets, type Logger } from "./log.js";

export interface GatewayDeps { kek: Kek; identity: Identity; log: Logger; held: HeldSecrets; fetch?: typeof fetch; now?: () => number }
/** Task 11 replaces this stub with the real AgentKeyCache (Task 9). */
export interface DroppableKeys { drop(id: string): void }

const MAX_BODY = 16 * 1024;
const enrolBody = z.object({ agentId: z.string().uuid(), orgId: z.string().uuid() });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class HttpError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

const send = (res: ServerResponse, status: number, body?: unknown) => {
  if (body === undefined) { res.writeHead(status).end(); return; }
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
};

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req as AsyncIterable<Buffer>) {
    size += c.length;
    if (size > MAX_BODY) throw new HttpError(413, "request_too_large");
    chunks.push(c);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new HttpError(400, "invalid_request"); }
}

export async function createGateway(cfg: GatewayConfig, deps: GatewayDeps): Promise<{ publicServer: Server; internalServer: Server; close(): Promise<void>; keys: DroppableKeys }> {
  const { kek, identity, log, held } = deps;
  const keys: DroppableKeys = { drop: () => {} };
  // Hashing first gives equal lengths, so the compare is timing-safe whatever the caller sends.
  const digest = (s: string) => createHash("sha256").update(s).digest();
  const tokenHash = digest(cfg.apiToken);
  const authorised = (req: IncomingMessage) => {
    const t = req.headers["x-gateway-token"];
    return typeof t === "string" && timingSafeEqual(digest(t), tokenHash);
  };

  async function internal(req: IncomingMessage, res: ServerResponse) {
    const path = new URL(req.url ?? "/", "http://internal").pathname;
    if (!path.startsWith("/internal/")) return send(res, 404, { error: "not_found" });
    if (!authorised(req)) return send(res, 401, { error: "unauthorized" });
    if (req.method === "GET" && path === "/internal/health")
      return send(res, 200, { ok: true, identity: { keyId: identity.keyId, publicKey: identity.publicKey } });
    if (req.method === "POST" && path === "/internal/agents") {
      const p = enrolBody.safeParse(await readJson(req));
      if (!p.success) return send(res, 400, { error: "invalid_request" });
      const { agentId, orgId } = p.data;
      const kp = await generateKeyPair();
      try {
        const ids = { orgId, agentId, publicKey: b64url.encode(kp.publicKey) };
        const wrappedPrivateKey = await wrapAgentKey(kek, ids, kp.privateKey);
        const attestation = await identity.sign(ids);
        return send(res, 200, { publicKey: ids.publicKey, wrappedPrivateKey, kekId: kek.id, attestation });
      } finally {
        kp.privateKey.fill(0);
      }
    }
    const m = /^\/internal\/agents\/([^/]+)$/.exec(path);
    if (req.method === "DELETE" && m) {
      const id = m[1]!; // a UUID needs no percent-decoding
      if (!UUID.test(id)) return send(res, 400, { error: "invalid_request" });
      keys.drop(id);
      return send(res, 204);
    }
    return send(res, 404, { error: "not_found" });
  }

  const handle = (fn: (req: IncomingMessage, res: ServerResponse) => Promise<void>) => (req: IncomingMessage, res: ServerResponse) => {
    fn(req, res).catch((e: unknown) => {
      if (e instanceof HttpError) return send(res, e.status, { error: e.code });
      log.error({ event: "request_error", ...safeError(e, held) });
      if (!res.headersSent) send(res, 500, { error: "internal_error" });
      else res.destroy();
    });
  };

  // Task 11 adds /mcp and Task 12 the OAuth metadata; /internal/* is never served here.
  const publicServer = createServer(handle(async (_req, res) => send(res, 404, { error: "not_found" })));
  const internalServer = createServer(handle(internal));
  const stop = (s: Server) => new Promise<void>((r) => { if (!s.listening) return r(); s.close(() => r()); s.closeAllConnections(); });
  return { publicServer, internalServer, keys, close: async () => { await Promise.all([stop(publicServer), stop(internalServer)]); } };
}
