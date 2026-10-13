import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { passwordStrength, type StrengthScore } from "@/lib/strength";
import type { ScoreBatch, ScoreRequest } from "@/lib/strength.worker";
import { obviouslyWeak, weakForScore } from "./attention";
import type { VaultRecord } from "./types";

export interface PasswordScores {
  /** The zxcvbn score of a password of these records; undefined while it is still being scored. */
  scoreOf: (pw: string) => StrengthScore | undefined;
  /** The weak rule (attention, health); a password still being scored counts only if it is obviously weak. */
  isWeak: (pw: string) => boolean;
  /** Some password has no score yet. */
  pending: boolean;
}

type Done = (passwords: string[], scores: StrengthScore[]) => void;
interface Scorer { score(passwords: string[], done: Done): void; dispose(): void }

/** Main thread, a slice at a time: when there is no worker (it failed to load). */
function scoreInSlices(passwords: string[], done: Done, alive: () => boolean) {
  let i = 0;
  const step = () => {
    if (!alive()) return;
    const start = performance.now(), from = i, scores: StrengthScore[] = [];
    while (i < passwords.length && performance.now() - start < 8) scores.push(passwordStrength(passwords[i++]!).score);
    done(passwords.slice(from, i), scores);
    if (i < passwords.length) setTimeout(step, 0);
  };
  setTimeout(step, 0);
}

function createScorer(): Scorer {
  let disposed = false, seq = 0;
  const jobs = new Map<number, { passwords: string[]; next: number; done: Done }>();
  let worker: Worker | null = null;
  try { worker = new Worker(new URL("../../lib/strength.worker.ts", import.meta.url), { type: "module" }); } catch { worker = null; }
  const fallBack = () => {
    worker?.terminate(); worker = null;
    for (const j of jobs.values()) scoreInSlices(j.passwords.slice(j.next), j.done, () => !disposed);
    jobs.clear();
  };
  if (worker) {
    worker.onmessage = (e: MessageEvent<ScoreBatch>) => {
      const job = jobs.get(e.data.id);
      if (!job || disposed) return;
      const { from, scores } = e.data;
      job.next = from + scores.length;
      if (job.next >= job.passwords.length) jobs.delete(e.data.id);
      job.done(job.passwords.slice(from, job.next), scores);
    };
    worker.onerror = (e) => { e.preventDefault(); fallBack(); };
  }
  return {
    score(passwords, done) {
      if (!worker) return scoreInSlices(passwords, done, () => !disposed);
      const id = ++seq;
      jobs.set(id, { passwords, next: 0, done });
      worker.postMessage({ id, passwords } satisfies ScoreRequest);
    },
    dispose() { disposed = true; worker?.terminate(); worker = null; jobs.clear(); },
  };
}

/**
 * zxcvbn scores for the passwords in `records`, worked out in a worker (scoring a vault of a few hundred random
 * passwords takes many seconds of CPU) and kept for as long as the component is mounted, so a vault refetch (after
 * every change, on window focus) never scores the same password twice and nothing scores on the render path.
 *
 * The kept scores and the worker go when the component unmounts (the vault locks or signs out). Without Worker support
 * (tests) it scores synchronously, as before.
 */
export function usePasswordScores(records: VaultRecord[]): PasswordScores {
  const cache = useRef(new Map<string, StrengthScore>());
  const [version, setVersion] = useState(0);
  const passwords = useMemo(() => [...new Set(records.flatMap((r) => (!r.deleted && r.body?.password ? [r.body.password] : [])))], [records]);
  const sync = typeof Worker === "undefined";
  if (sync) for (const pw of passwords) if (!cache.current.has(pw)) cache.current.set(pw, passwordStrength(pw).score);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- `version`: the cache gained scores
  const missing = useMemo(() => passwords.filter((pw) => !cache.current.has(pw)), [passwords, version]);

  const scorer = useRef<Scorer | null>(null);
  const inflight = useRef(new Set<string>());
  useEffect(() => () => { scorer.current?.dispose(); scorer.current = null; inflight.current.clear(); }, []);
  useEffect(() => {
    const todo = missing.filter((pw) => !inflight.current.has(pw));
    if (todo.length === 0) return;
    for (const pw of todo) inflight.current.add(pw);
    const s = (scorer.current ??= createScorer());
    s.score(todo, (pws, scores) => {
      if (scorer.current !== s) return;
      pws.forEach((pw, i) => { cache.current.set(pw, scores[i]!); inflight.current.delete(pw); });
      setVersion((v) => v + 1);
    });
  }, [missing]);

  // eslint-disable-next-line react-hooks/exhaustive-deps -- new identities when scores arrive, so memos over them recompute
  const scoreOf = useCallback((pw: string) => cache.current.get(pw), [version]);
  const isWeak = useCallback((pw: string) => { const s = scoreOf(pw); return s === undefined ? obviouslyWeak(pw) : weakForScore(pw, s); }, [scoreOf]);
  return { scoreOf, isWeak, pending: missing.length > 0 };
}
