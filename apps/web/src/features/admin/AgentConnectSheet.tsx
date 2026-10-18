import { useState } from "react";
import { Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { copySecret } from "@/lib/clipboard";
import { relativeTime } from "@/lib/time";
import { AGENT_PROMPT, agentErrorText, connectSnippets, useCreateToken, useRevokeGrant, useRevokeToken, type Agent } from "./agents";

const h3 = "font-display text-[14px] font-semibold text-text-primary";
const pre = "overflow-x-auto rounded-[10px] border border-border-default bg-well px-3 py-2 font-mono text-[12px] whitespace-pre-wrap break-all text-text-primary";

function CopyButton({ text, label }: { text: string; label: string }) {
  return <Button type="button" variant="ghost" size="sm" aria-label={label} onClick={async () => { await copySecret(text); toast.success("Copied"); }}><Copy className="size-3.5" />Copy</Button>;
}

/**
 * Connect an agent (spec §7): the gateway URL, per-client snippets, API tokens and OAuth grants. A new token is shown
 * once, in this sheet's state only: closing the sheet forgets it (the server keeps only its hash).
 */
export function AgentConnectSheet({ agent, url, onClose }: { agent: Agent; url: string; onClose: () => void }) {
  const [label, setLabel] = useState("API token");
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const create = useCreateToken();
  const revokeToken = useRevokeToken();
  const revokeGrant = useRevokeGrant();
  const run = async (f: () => Promise<unknown>) => { setError(null); try { await f(); } catch (e) { setError(agentErrorText(e)); } };
  const tokens = agent.tokens.filter((t) => !t.revokedAt);
  const grants = agent.grants.filter((g) => !g.revokedAt);

  return (
    <Sheet open onOpenChange={(o) => { if (!o) onClose(); }}>
      <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="data-[side=right]:w-full data-[side=right]:sm:max-w-[560px]">
        <SheetHeader><SheetTitle className="font-display text-[18px] font-semibold tracking-[-0.02em]">Connect {agent.name}</SheetTitle><SheetCloseButton /></SheetHeader>
        <SheetBody className="gap-5 overflow-y-auto pt-5">
          <section aria-label="Connector URL" className="flex flex-col gap-1.5">
            <h3 className={h3}>Connector URL</h3>
            <div className="flex items-center gap-2"><code className={`${pre} flex-1`}>{url}</code><CopyButton text={url} label="Copy URL" /></div>
            <p className="text-[12.5px] text-text-secondary">OAuth clients end on a consent page where an owner or admin picks this agent. API clients use a token.</p>
          </section>

          <section aria-label="API tokens" className="flex flex-col gap-2">
            <h3 className={h3}>API tokens</h3>
            {token ? (
              <div className="flex flex-col gap-1.5 rounded-[10px] border border-[var(--orange-tint-border)] bg-orange-tint px-3 py-2.5">
                <p className="text-[12.5px] text-orange-ink">Copy it now: it won't be shown again. It's already in the snippets below.</p>
                <div className="flex items-center gap-2"><code className={`${pre} flex-1`}>{token}</code><CopyButton text={token} label="Copy token" /></div>
              </div>
            ) : (
              <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); void run(async () => setToken((await create.mutateAsync({ agentId: agent.id, label: label.trim() })).token)); }}>
                <div className="flex flex-1 flex-col gap-1"><Label htmlFor="agent-token-label">Token name</Label><Input id="agent-token-label" value={label} maxLength={60} onChange={(e) => setLabel(e.target.value)} /></div>
                <Button type="submit" disabled={create.isPending || !label.trim()}>Create API token</Button>
              </form>
            )}
            {tokens.length > 0 && (
              <ul className="divide-y divide-border-subtle rounded-[10px] border border-border-default">
                {tokens.map((t) => (
                  <li key={t.id} aria-label={t.label} className="flex items-center gap-2 px-3 py-2 text-[13px]">
                    <span className="min-w-0 flex-1 truncate">{t.label}</span>
                    <span className="text-[12px] text-text-tertiary">{t.lastUsedAt ? `used ${relativeTime(t.lastUsedAt)}` : "never used"}</span>
                    <Button variant="ghost" size="sm" aria-label={`Revoke token ${t.label}`} disabled={revokeToken.isPending} onClick={() => void run(() => revokeToken.mutateAsync({ agentId: agent.id, tokenId: t.id }))}>Revoke</Button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section aria-label="Connected apps" className="flex flex-col gap-2">
            <h3 className={h3}>Connected apps</h3>
            {grants.length === 0 ? <p className="text-[12.5px] text-text-secondary">No app has connected through OAuth yet.</p> : (
              <ul className="divide-y divide-border-subtle rounded-[10px] border border-border-default">
                {grants.map((g) => (
                  <li key={g.id} aria-label={g.clientName} className="flex items-center gap-2 px-3 py-2 text-[13px]">
                    <span className="min-w-0 flex-1 truncate">{g.clientName}</span>
                    <span className="text-[12px] text-text-tertiary">{g.grantedBy ? `${g.grantedBy}, ` : ""}{relativeTime(g.createdAt)}</span>
                    <Button variant="ghost" size="sm" aria-label={`Revoke ${g.clientName}`} disabled={revokeGrant.isPending} onClick={() => void run(() => revokeGrant.mutateAsync({ agentId: agent.id, grantId: g.id }))}>Revoke</Button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}

          <section aria-label="Prompt" className="flex flex-col gap-1.5">
            <h3 className={h3}>Tell the model</h3>
            <div className="flex items-start gap-2"><p className={`${pre} flex-1`}>{AGENT_PROMPT}</p><CopyButton text={AGENT_PROMPT} label="Copy prompt" /></div>
          </section>
          {connectSnippets(url, token ?? undefined).map((s) => (
            <section key={s.id} aria-label={`${s.label} snippet`} className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between"><h3 className={h3}>{s.label}</h3><CopyButton text={s.text} label={`Copy ${s.label}`} /></div>
              <pre className={pre}>{s.text}</pre>
            </section>
          ))}
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}
