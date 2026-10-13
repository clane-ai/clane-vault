import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";

const zxcvbn = new ZxcvbnFactory({ dictionary: { ...common.dictionary, ...en.dictionary }, graphs: common.adjacencyGraphs, translations: en.translations });
const LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"] as const;
export type StrengthScore = 0 | 1 | 2 | 3 | 4;
export const strengthLabel = (score: StrengthScore) => LABELS[score];

/**
 * zxcvbn score and label. Slow: a random 16–30 character password with symbols takes 30–100 ms (its l33t matching),
 * so code that scores many passwords (the vault's attention and health checks) uses usePasswordScores, which scores
 * them in a worker and keeps the results, never on the render path.
 */
export function passwordStrength(pw: string) {
  const score = zxcvbn.check(pw.slice(0, 100)).score as StrengthScore;
  return { score, label: LABELS[score] };
}
