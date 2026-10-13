export interface GeneratorOptions { length: number; lower: boolean; upper: boolean; digits: boolean; symbols: boolean; avoidAmbiguous: boolean }
export const DEFAULT_GENERATOR: GeneratorOptions = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true };

const SETS = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!#$%&*+-=?@^_~" };
const AMBIGUOUS = /[Il1O0]/g;

function randomIndex(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n; // rejection sampling, no modulo bias
  const buf = new Uint32Array(1);
  for (;;) { crypto.getRandomValues(buf); if (buf[0]! < limit) return buf[0]! % n; }
}

export function generatePassword(opts: Partial<GeneratorOptions> = {}): string {
  const o = { ...DEFAULT_GENERATOR, ...opts };
  const length = opts.length ?? DEFAULT_GENERATOR.length;
  if (!Number.isInteger(length) || length < 8 || length > 128) throw new Error("length must be 8–128");
  const sets = (Object.keys(SETS) as (keyof typeof SETS)[]).filter((k) => o[k])
    .map((k) => (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, "") : SETS[k]));
  if (sets.length === 0) throw new Error("choose at least one character type");
  const chars = sets.map((s) => s[randomIndex(s.length)]!); // one from each chosen set
  const all = sets.join("");
  while (chars.length < length) chars.push(all[randomIndex(all.length)]!);
  for (let i = chars.length - 1; i > 0; i--) { const j = randomIndex(i + 1); [chars[i], chars[j]] = [chars[j]!, chars[i]!]; }
  return chars.join("");
}
