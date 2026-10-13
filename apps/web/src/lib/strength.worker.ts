/**
 * Scores passwords with zxcvbn off the main thread (usePasswordScores). Scoring a vault takes seconds; results go back
 * in batches about every 200 ms so the vault fills in its counts as they come. The worker keeps nothing: it is ended
 * when the vault closes (lock, sign-out).
 */
import { passwordStrength, type StrengthScore } from "./strength";

export interface ScoreRequest { id: number; passwords: string[] }
export interface ScoreBatch { id: number; from: number; scores: StrengthScore[] }

const post = (m: ScoreBatch) => (self as unknown as { postMessage(m: ScoreBatch): void }).postMessage(m);

self.onmessage = (e: MessageEvent<ScoreRequest>) => {
  const { id, passwords } = e.data;
  let from = 0, scores: StrengthScore[] = [], last = performance.now();
  for (const pw of passwords) {
    scores.push(passwordStrength(pw).score);
    if (performance.now() - last > 200) { post({ id, from, scores }); from += scores.length; scores = []; last = performance.now(); }
  }
  post({ id, from, scores });
};
