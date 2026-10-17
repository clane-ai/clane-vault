/** Fixed windows per key. shortcut: allows up to 2× the limit across a window edge; move to a sliding window if that matters. */
export class RateLimiter {
  private windows = new Map<string, { until: number; n: number }>();
  private swept = -Infinity;
  constructor(private now: () => number = Date.now) {}

  take(key: string, limit: number, windowMs: number): { ok: true } | { ok: false; retryAfterSeconds: number } {
    const t = this.now();
    // Client addresses are unbounded: sweep finished windows once the map is large, at most once per window.
    if (this.windows.size > 10_000 && t - this.swept >= windowMs) {
      this.swept = t;
      for (const [k, w] of this.windows) if (t >= w.until) this.windows.delete(k);
    }
    let w = this.windows.get(key);
    if (!w || t >= w.until) { w = { until: t + windowMs, n: 0 }; this.windows.set(key, w); }
    if (w.n >= limit) return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((w.until - t) / 1000)) };
    w.n++;
    return { ok: true };
  }
}
