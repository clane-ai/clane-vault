import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { b64url, gatewayKeyId, generateIdentityKeyPair, generateKeyPair, signPersonalAgentKey } from "@clane-vault/crypto";
import { resetBasePath } from "./base";
import {
  AgentAttestationError, allGatewayPins, ensureGatewayPinned, PERSONAL_SLOT, personalGatewayPinStatus, pinGateway, pinnedGateway, verifyPersonalAgentKey,
  type GatewayIdentity,
} from "./orgKeys";

const ME = "u1", ORG = "aaaaaaaa-0000-4000-8000-000000000001", AGENT = "bbbbbbbb-0000-4000-8000-000000000002";

async function newGateway() {
  const kp = await generateIdentityKeyPair();
  const identity: GatewayIdentity = { keyId: await gatewayKeyId(kp.publicKey), publicKey: b64url.encode(kp.publicKey) };
  return { identity, privateKey: kp.privateKey };
}
const reason = (p: Promise<unknown>) => p.then(() => "passed", (e: unknown) => (e instanceof AgentAttestationError ? e.reason : String(e)));

beforeEach(() => { localStorage.clear(); resetBasePath(); });
afterEach(() => { document.head.querySelector('meta[name="clane-base"]')?.remove(); resetBasePath(); });

describe("personal gateway pin", () => {
  it("no pins → new; an organisation pin equal to it → same; one that differs → changed with previous", async () => {
    const a = await newGateway(), b = await newGateway();
    expect(personalGatewayPinStatus(ME, a.identity)).toEqual({ status: "new" });
    await pinGateway(ME, ORG, a.identity);
    expect(personalGatewayPinStatus(ME, a.identity)).toEqual({ status: "same" });
    expect(personalGatewayPinStatus(ME, b.identity)).toEqual({ status: "changed", previous: a.identity });
  });

  it("a first personal pin refuses when an organisation pin differs, unless repin", async () => {
    const a = await newGateway(), b = await newGateway();
    await pinGateway(ME, ORG, a.identity);
    expect(await reason(pinGateway(ME, PERSONAL_SLOT, b.identity))).toBe("gateway_changed");
    expect(pinnedGateway(ME, PERSONAL_SLOT)).toBeNull();
    expect(await pinGateway(ME, PERSONAL_SLOT, b.identity, { repin: true })).toBe(true);
    expect(pinnedGateway(ME, PERSONAL_SLOT)).toEqual(b.identity);
  });

  it("an organisation pin is unaffected by a differing personal pin", async () => {
    const a = await newGateway(), b = await newGateway();
    await pinGateway(ME, PERSONAL_SLOT, a.identity);
    expect(await pinGateway(ME, ORG, b.identity)).toBe(true);
    const r = await ensureGatewayPinned({ get: async () => { throw new Error("not asked"); } }, ME, ORG);
    expect(r.identity).toEqual(b.identity);
  });

  it("ensureGatewayPinned for the personal slot fetches /me/agents/gateway and refuses a gateway that differs from an organisation pin", async () => {
    const a = await newGateway(), b = await newGateway();
    let asked = "";
    const oapi = { get: async <T,>(p: string) => { asked = p; return { identityKeyId: b.identity.keyId, identityPublicKey: b.identity.publicKey } as T; } };
    await pinGateway(ME, ORG, a.identity);
    expect(await reason(ensureGatewayPinned(oapi, ME, PERSONAL_SLOT, "/me/agents/gateway"))).toBe("gateway_changed");
    expect(asked).toBe("/me/agents/gateway");
    localStorage.clear();
    expect((await ensureGatewayPinned(oapi, ME, PERSONAL_SLOT, "/me/agents/gateway")).pinnedNow).toBe(true);
  });

  it("allGatewayPins reads this instance's pins under a base path, not another instance's or user's", async () => {
    const a = await newGateway(), b = await newGateway(), c = await newGateway();
    await pinGateway(ME, ORG, a.identity); // root instance
    await pinGateway("u2", ORG, c.identity);
    const meta = document.createElement("meta");
    meta.name = "clane-base"; meta.content = "/vault";
    document.head.appendChild(meta);
    resetBasePath();
    expect(allGatewayPins(ME)).toEqual([]);
    await pinGateway(ME, PERSONAL_SLOT, b.identity);
    expect(Object.keys(localStorage)).toContain(`cv.gateway.${ME}.${PERSONAL_SLOT}@/vault`);
    expect(allGatewayPins(ME)).toEqual([b.identity]);
    meta.remove(); resetBasePath();
    expect(allGatewayPins(ME)).toEqual([a.identity]);
  });
});

describe("verifyPersonalAgentKey", () => {
  async function setup() {
    const gw = await newGateway();
    const owner = await generateKeyPair();
    const ownerPublicKey = b64url.encode(owner.publicKey);
    const publicKey = b64url.encode((await generateKeyPair()).publicKey);
    await pinGateway(ME, PERSONAL_SLOT, gw.identity);
    const sign = (agentId: string, ownerKey = ownerPublicKey) => signPersonalAgentKey(gw.privateKey, gw.identity.keyId, { ownerUserId: ME, ownerPublicKey: ownerKey, agentId, publicKey });
    return { owner, ownerPublicKey, publicKey, sign };
  }

  it("passes for a real attestation", async () => {
    const s = await setup();
    await expect(verifyPersonalAgentKey(ME, { id: AGENT, publicKey: s.publicKey, attestation: await s.sign(AGENT) }, { userId: ME, publicKey: s.ownerPublicKey }, s.owner.privateKey)).resolves.toBeUndefined();
  });

  it("an owner key that isn't mine → owner", async () => {
    const s = await setup();
    const other = b64url.encode((await generateKeyPair()).publicKey);
    expect(await reason(verifyPersonalAgentKey(ME, { id: AGENT, publicKey: s.publicKey, attestation: await s.sign(AGENT, other) }, { userId: ME, publicKey: other }, s.owner.privateKey))).toBe("owner");
    expect(new AgentAttestationError("owner").message).toBe("This agent's key is bound to a different account key than yours, so nothing was shared. Revoke the agent and create it again.");
  });

  it("an attestation signed for another agent id → invalid", async () => {
    const s = await setup();
    expect(await reason(verifyPersonalAgentKey(ME, { id: AGENT, publicKey: s.publicKey, attestation: await s.sign("cccccccc-0000-4000-8000-000000000003") }, { userId: ME, publicKey: s.ownerPublicKey }, s.owner.privateKey))).toBe("invalid");
  });

  it("nothing pinned → unpinned", async () => {
    const s = await setup();
    const att = await s.sign(AGENT);
    localStorage.clear();
    expect(await reason(verifyPersonalAgentKey(ME, { id: AGENT, publicKey: s.publicKey, attestation: att }, { userId: ME, publicKey: s.ownerPublicKey }, s.owner.privateKey))).toBe("unpinned");
  });
});
