import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router";
import { Button } from "@/components/ui/button";
import { api, ApiError, forOrg } from "@/lib/api";
import { useSession } from "@/lib/session";
import { AGENTS_OFF, agentsOff } from "@/features/admin/agents";
import { AuthLayout } from "./AuthLayout";
import Unlock from "./Unlock";
import { oauthNav } from "./oauthNav";

const PARAMS = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "resource"];

interface Info { issuer?: string; client: { name: string }; agents: { id: string; name: string; orgId: string; orgName: string }[] }


const INVALID = "This connection request isn't valid. Start again from your AI app.";
const MESSAGES: Record<string, string> = {
  rate_limited: "Too many attempts. Wait a minute and try again.",
  agent_expired: "That agent has expired. Pick another or renew it on the Agents page.",
  agent_unverified: "That agent isn't verified yet. Verify it on the Agents page first.",
  forbidden: "Only owners and admins can connect agents.",
};

/** http(s) only, so a crafted redirect_uri can't become a javascript: or data: navigation. */
function parse(u: string | null): URL | null {
  try { const x = new URL(u ?? ""); return x.protocol === "https:" || x.protocol === "http:" ? x : null; } catch { return null; }
}

/** OAuth consent (docs: spec §4.7): an owner or admin picks the agent a connecting MCP client acts as. Never approves by itself. */
export default function OAuthAuthorize() {
  const { state, orgs } = useSession();
  const location = useLocation();
  const q = new URLSearchParams(location.search);
  // A repeated parameter could pass validation on one value and redirect to another: refuse the request.
  const repeated = PARAMS.some((k) => q.getAll(k).length > 1);
  const redirect = repeated ? null : parse(q.get("redirect_uri"));
  const infoQuery = new URLSearchParams(PARAMS.flatMap((k) => (q.get(k) === null ? [] : [[k, q.get(k)!]]))).toString();
  const [info, setInfo] = useState<Info | null>(null);
  const [failure, setFailure] = useState<"invalid" | "off" | null>(null);
  const [agentId, setAgentId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setInfo(null); setFailure(null); setAgentId(""); setError(null);
    if (state !== "unlocked") return;
    if (!redirect) { setFailure("invalid"); return; }
    let live = true;
    // Plain state, not the query cache: nothing from this flow is kept after the page.
    api.get<Info>(`/oauth/authorize/info?${infoQuery}`)
      .then((r) => { if (live) setInfo(r); })
      .catch((e) => { if (live) setFailure(agentsOff(e) ? "off" : "invalid"); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, location.search]);

  if (state === "loading") return <AuthLayout title="Connect an agent"><span /></AuthLayout>;
  if (state === "signed_out") return <Navigate to="/sign-in" replace state={{ from: { pathname: location.pathname, search: location.search } }} />;
  if (state === "locked") return <Unlock />;
  if (failure) return <AuthLayout title="Connect an agent"><p role="alert" className="text-[14px] text-text-primary">{failure === "off" ? AGENTS_OFF : INVALID}</p></AuthLayout>;
  if (!info || !redirect) return <AuthLayout title="Connect an agent" subtitle="Checking the request…"><span /></AuthLayout>;

  const agent = info.agents.find((a) => a.id === agentId);
  const isAdmin = orgs.some((o) => o.role === "owner" || o.role === "admin");
  const back = (extra: Record<string, string>) => {
    const u = new URL(redirect.href);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
    return u.href;
  };

  async function allow() {
    if (!agent) return;
    setBusy(true); setError(null);
    try {
      const { redirectTo } = await forOrg(agent.orgId).post<{ redirectTo: string }>("/oauth/authorize", {
        clientId: q.get("client_id"), redirectUri: q.get("redirect_uri"), codeChallenge: q.get("code_challenge"),
        codeChallengeMethod: q.get("code_challenge_method"), ...(q.get("state") ? { state: q.get("state") } : {}),
        ...(q.get("resource") ? { resource: q.get("resource") } : {}), agentId: agent.id,
      });
      // The server's answer must go back to the client we showed, nowhere else.
      if (parse(redirectTo)?.origin !== redirect!.origin) throw new Error("mismatch");
      oauthNav.go(redirectTo);
    } catch (e) {
      setError(e instanceof ApiError ? (MESSAGES[e.code] ?? "Couldn't connect the agent. Try again.") : "Couldn't connect the agent. Try again.");
      setBusy(false);
    }
  }
  const deny = () => { const s = q.get("state"); oauthNav.go(back({ error: "access_denied", ...(s ? { state: s } : {}), ...(info.issuer ? { iss: info.issuer } : {}) })); };

  const host = redirect.host;
  return (
    <AuthLayout title="Connect an agent" subtitle={`${info.client.name} wants to use vault credentials as an agent you choose.`}>
      <p className="rounded-[10px] border border-border px-3 py-2.5 text-[13px] text-text-primary">
        Approving sends you back to <strong className="font-mono text-[15px]" data-testid="redirect-host">{host}</strong>. Only continue if you started this from <strong>{info.client.name}</strong> and recognise that address.
      </p>
      {info.agents.length === 0 ? (
        <>
          <p role="status" className="text-[14px] text-text-primary">
            {isAdmin ? "You have no verified agents yet. Create and verify one on the Agents page, then start again from your AI app."
              : "Only owners and admins can connect agents. Ask an admin of your organisation to connect it."}
          </p>
          <Button variant="outline" onClick={deny}>Cancel</Button>
        </>
      ) : (
        <>
          <fieldset className="flex flex-col gap-2">
            <legend className="mb-1 text-[13px] font-medium text-text-primary">Act as agent</legend>
            {info.agents.map((a) => (
              <label key={a.id} className="flex cursor-pointer items-center gap-2 rounded-[10px] border border-border px-3 py-2 text-[14px]">
                <input type="radio" name="agent" value={a.id} checked={agentId === a.id} onChange={() => setAgentId(a.id)} />
                <span>{a.name} <span className="text-text-muted">· {a.orgName}</span></span>
              </label>
            ))}
          </fieldset>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex gap-3">
            <Button variant="cta" size="lg" className="h-11 flex-1" disabled={!agent || busy} onClick={() => void allow()}>{busy ? "Connecting…" : "Allow"}</Button>
            <Button variant="outline" size="lg" className="h-11 flex-1" disabled={busy} onClick={deny}>Deny</Button>
          </div>
        </>
      )}
    </AuthLayout>
  );
}
