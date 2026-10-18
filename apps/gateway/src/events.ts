import { ApiRefused, type ApiClient, type UseEvent } from "./apiClient.js";
import type { AgentPrincipal } from "./auth.js";
import type { Logger } from "./log.js";

const MAX_PER_AGENT = 200;

/** Use events per agent, sent to /agent/events with that agent's own token. At most 200 kept per agent; the oldest go first. */
export class EventQueue {
  private queues = new Map<string, UseEvent[]>();
  constructor(private api: ApiClient, private log: Logger) {}

  push(p: AgentPrincipal, e: UseEvent): void {
    const q = this.queues.get(p.agentId) ?? [];
    q.push(e);
    if (q.length > MAX_PER_AGENT) q.splice(0, q.length - MAX_PER_AGENT);
    this.queues.set(p.agentId, q);
  }

  /** Never throws. A failed send is kept for the next flush, unless the API refused the token (revoked or expired). */
  async flush(p: AgentPrincipal): Promise<void> {
    const batch = this.queues.get(p.agentId);
    if (!batch?.length) return;
    this.queues.delete(p.agentId);
    try {
      await this.api.events(p.accessToken, batch);
    } catch (e) {
      this.log.error({ event: "events_failed", class: e instanceof Error ? e.name : typeof e, count: batch.length });
      if (e instanceof ApiRefused) return;
      const q = [...batch, ...(this.queues.get(p.agentId) ?? [])];
      this.queues.set(p.agentId, q.slice(-MAX_PER_AGENT));
    }
  }
}
