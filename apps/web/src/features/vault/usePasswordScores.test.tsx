import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { passwordStrength } from "@/lib/strength";
import type { ScoreBatch, ScoreRequest } from "@/lib/strength.worker";
import { usePasswordScores } from "./usePasswordScores";
import type { VaultRecord } from "./types";

const rec = (id: string, password: string, o: Partial<VaultRecord> = {}): VaultRecord => ({
  id, folderId: null, type: "login", body: { type: "login", title: id, password }, revision: 1,
  updatedAt: "2026-09-01T00:00:00Z", deleted: false, permission: "owner", recordKey: null, ...o,
});
const STRONG = "Tg7#qL2v!Rm9zW4x", ALSO_STRONG = "Zq8$wP3n!Lk7xV2m";

/** A worker that scores on a timer, in two batches, like the real one. */
class FakeWorker {
  static made: FakeWorker[] = [];
  onmessage: ((e: MessageEvent<ScoreBatch>) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  posted: ScoreRequest[] = [];
  terminated = false;
  constructor(public url: URL | string) { FakeWorker.made.push(this); }
  postMessage(m: ScoreRequest) {
    this.posted.push(m);
    const scores = m.passwords.map((p) => passwordStrength(p).score);
    const half = Math.ceil(scores.length / 2);
    setTimeout(() => this.onmessage?.({ data: { id: m.id, from: 0, scores: scores.slice(0, half) } } as MessageEvent<ScoreBatch>), 5);
    setTimeout(() => this.onmessage?.({ data: { id: m.id, from: half, scores: scores.slice(half) } } as MessageEvent<ScoreBatch>), 10);
  }
  terminate() { this.terminated = true; }
}

afterEach(() => { vi.unstubAllGlobals(); FakeWorker.made = []; });

describe("usePasswordScores", () => {
  it("scores in the worker, off the render path, and never scores a password twice", async () => {
    vi.stubGlobal("Worker", FakeWorker);
    const records = [rec("a", "figma123"), rec("b", STRONG), rec("c", STRONG), rec("d", ALSO_STRONG), rec("e", "password12345", { deleted: true })];
    const { result, rerender, unmount } = renderHook(({ rs }) => usePasswordScores(rs), { initialProps: { rs: records } });
    // Before the worker answers: pending, and only the obvious rule applies.
    expect(result.current.pending).toBe(true);
    expect(result.current.scoreOf(STRONG)).toBeUndefined();
    expect(result.current.isWeak("figma123")).toBe(true);
    expect(result.current.isWeak(STRONG)).toBe(false);
    await waitFor(() => expect(result.current.pending).toBe(false), { timeout: 5000 });
    expect(result.current.scoreOf(STRONG)).toBe(4);
    expect(result.current.isWeak("figma123")).toBe(true);
    // Unique passwords of live records only (trash left out).
    expect(FakeWorker.made).toHaveLength(1);
    expect(FakeWorker.made[0]!.posted.map((p) => p.passwords)).toEqual([["figma123", STRONG, ALSO_STRONG]]);

    // A refetch (new objects, same passwords) scores nothing; a new password is scored on its own.
    rerender({ rs: records.map((r) => ({ ...r, body: { ...r.body! } })) });
    expect(result.current.pending).toBe(false);
    rerender({ rs: [...records, rec("f", "password12345")] });
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false), { timeout: 5000 });
    expect(FakeWorker.made[0]!.posted.map((p) => p.passwords)).toEqual([["figma123", STRONG, ALSO_STRONG], ["password12345"]]);
    expect(result.current.isWeak("password12345")).toBe(true);

    // Locking (unmount) ends the worker.
    unmount();
    expect(FakeWorker.made[0]!.terminated).toBe(true);
  });

  it("scores on the main thread, in slices, when the worker can't start", async () => {
    vi.stubGlobal("Worker", class { constructor() { throw new Error("blocked"); } });
    const { result } = renderHook(() => usePasswordScores([rec("a", STRONG), rec("b", "figma123")]));
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false), { timeout: 5000 });
    expect(result.current.scoreOf(STRONG)).toBe(4);
  });
});
