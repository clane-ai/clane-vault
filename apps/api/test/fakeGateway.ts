import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";
import { b64url, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, signAgentKey } from "@clane-vault/crypto";
import type { GatewayIdentityInfo } from "../src/lib/gateway.js";

/** A stand-in for apps/gateway's internal port: real key pairs and real attestations, an opaque envelope. */
export async function startFakeGateway(o: { down?: boolean } = {}) {
  const token = randomBytes(24).toString("base64url");
  let down = !!o.down;
  let signWrongAgent = false;
  let priv: Uint8Array = new Uint8Array();
  const identity: GatewayIdentityInfo = { keyId: "", publicKey: "" };
  const rotateIdentity = async () => {
    const kp = await generateIdentityKeyPair();
    priv = kp.privateKey;
    identity.keyId = await gatewayKeyId(kp.publicKey);
    identity.publicKey = b64url.encode(kp.publicKey);
  };
  await rotateIdentity();
  const created: { agentId: string; orgId: string }[] = [];
  const dropped: string[] = [];

  const server = createServer(async (req, res) => {
    const send = (code: number, body?: unknown) => { res.writeHead(code, body ? { "content-type": "application/json" } : {}); res.end(body ? JSON.stringify(body) : undefined); };
    if (down) return send(503, { error: "down" });
    if (req.headers["x-gateway-token"] !== token) return send(401, { error: "unauthorized" });
    const url = req.url ?? "";
    if (req.method === "GET" && url === "/internal/health") return send(200, { ok: true, identity: { ...identity } });
    if (req.method === "POST" && url === "/internal/agents") {
      let raw = "";
      for await (const c of req) raw += c;
      const ids = JSON.parse(raw) as { agentId: string; orgId: string };
      created.push({ agentId: ids.agentId, orgId: ids.orgId });
      const publicKey = b64url.encode((await generateKeyPair()).publicKey);
      const attestation = await signAgentKey(priv, identity.keyId, { orgId: ids.orgId, agentId: signWrongAgent ? crypto.randomUUID() : ids.agentId, publicKey });
      return send(200, { publicKey, wrappedPrivateKey: `k1.file-test.${randomBytes(8).toString("base64url")}.v1.${randomBytes(16).toString("base64url")}`, kekId: "file-test", attestation });
    }
    const del = /^\/internal\/agents\/([^/]+)$/.exec(url);
    if (req.method === "DELETE" && del) { dropped.push(del[1]!); return send(204); }
    send(404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, token, identity, created, dropped, rotateIdentity,
    setDown(d: boolean) { down = d; },
    /** Tests: attest a different agent id than the one asked for. */
    setSignWrongAgent(b: boolean) { signWrongAgent = b; },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
