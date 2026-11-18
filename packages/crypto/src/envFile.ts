/**
 * `.env` file items (spec §10). The file's text is the only stored form (`data.content`); everything here reads it, and
 * `setEnvEntry` rewrites one value in place. The parser is lossless: the lines it returns, joined, are the input.
 */
import { utf8 } from "./encoding.js";

export const MAX_ENV_BYTES = 32_768; // UTF-8 bytes of the text
export const MAX_ENV_ENTRIES = 500;
export const ENV_KEY = /^[A-Za-z0-9_.-]{1,128}$/;

/** One logical line with its terminator. For an entry, raw === head + token + tail: `token` is the value as written (quotes included, "" when empty), `tail` is spaces, a comment and the terminator. A quoted value may make one line span several physical lines. */
export type EnvLine =
  | { kind: "entry"; raw: string; key: string; value: string; head: string; token: string; tail: string }
  | { kind: "blank" | "comment" | "invalid"; raw: string };

const isSpace = (c: string | undefined) => c === " " || c === "\t";
const isKeyChar = (c: string) => /[A-Za-z0-9_.-]/.test(c);
const DECODE: Record<string, string> = { n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" };

/** End of the physical line's content (before "\r\n" or "\n") and the index after its terminator. */
function lineAt(t: string, from: number): { end: number; next: number } {
  const nl = t.indexOf("\n", from);
  if (nl < 0) return { end: t.length, next: t.length };
  return { end: nl > from && t[nl - 1] === "\r" ? nl - 1 : nl, next: nl + 1 };
}

/** Spec §10.3. Never throws. parseEnv(t).map((l) => l.raw).join("") === t for every string. */
export function parseEnv(text: string): EnvLine[] {
  const out: EnvLine[] = [];
  let pos = 0;
  while (pos < text.length) {
    const start = pos;
    const { end, next } = lineAt(text, pos);
    const invalid = () => { out.push({ kind: "invalid", raw: text.slice(start, next) }); pos = next; };
    let i = start === 0 && text.charCodeAt(0) === 0xfeff ? 1 : start;
    while (i < end && isSpace(text[i])) i++;
    if (i === end) { out.push({ kind: "blank", raw: text.slice(start, next) }); pos = next; continue; }
    if (text[i] === "#") { out.push({ kind: "comment", raw: text.slice(start, next) }); pos = next; continue; }
    if (text.startsWith("export", i) && isSpace(text[i + 6])) { i += 6; while (i < end && isSpace(text[i])) i++; }
    const k0 = i;
    while (i < end && isKeyChar(text[i]!)) i++;
    const key = text.slice(k0, i);
    while (i < end && isSpace(text[i])) i++;
    if (!ENV_KEY.test(key) || text[i] !== "=") { invalid(); continue; }
    const afterEq = ++i;
    while (i < end && isSpace(text[i])) i++;
    const q = text[i];
    let value: string, tokenEnd: number, lineNext = next;
    if (q === '"' || q === "'" || q === "`") {
      let c = i + 1;
      value = "";
      if (q === '"') {
        for (; c < text.length && text[c] !== '"'; c++) {
          if (text[c] === "\\" && c + 1 < text.length) { const d = DECODE[text[c + 1]!]; value += d ?? text.slice(c, c + 2); c++; } else value += text[c];
        }
      } else {
        c = text.indexOf(q, c);
        if (c < 0) c = text.length;
        value = text.slice(i + 1, c);
      }
      if (c >= text.length) { invalid(); continue; } // unterminated quote
      tokenEnd = c + 1;
      const l = lineAt(text, tokenEnd);
      let r = tokenEnd;
      while (r < l.end && isSpace(text[r])) r++;
      if (r < l.end && text[r] !== "#") { invalid(); continue; }
      lineNext = l.next;
    } else {
      // Unquoted: a "#" after whitespace starts a comment; the value is trimmed.
      let e = i;
      while (e < end && !(text[e] === "#" && isSpace(text[e - 1]))) e++;
      while (e > i && isSpace(text[e - 1])) e--;
      if (e === i) i = afterEq; // empty: the spaces belong to the tail, so a later value can't run into a comment
      value = text.slice(i, e);
      tokenEnd = e;
    }
    out.push({ kind: "entry", raw: text.slice(start, lineNext), key, value, head: text.slice(start, i), token: text.slice(i, tokenEnd), tail: text.slice(tokenEnd, lineNext) });
    pos = lineNext;
  }
  return out;
}

type Entry = Extract<EnvLine, { kind: "entry" }>;
const entriesOf = (text: string) => parseEnv(text).filter((l): l is Entry => l.kind === "entry");

/** Entries in file order; `overridden` when a later line sets the same key. */
export function envEntries(text: string): { key: string; value: string; overridden: boolean }[] {
  const es = entriesOf(text);
  const last = new Map(es.map((e, i) => [e.key, i]));
  return es.map((e, i) => ({ key: e.key, value: e.value, overridden: last.get(e.key) !== i }));
}

/** Unique, in order of first appearance. */
export const envKeys = (text: string): string[] => [...new Set(entriesOf(text).map((e) => e.key))];

/** The last entry with that key; null when there is none. */
export function envValue(text: string, key: string): string | null {
  const e = entriesOf(text).filter((x) => x.key === key).pop();
  return e ? e.value : null;
}

/** Spec §10.3: bare, else '…', else "…" with \\ \" \n \r \t. */
export function quoteEnvValue(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]*$/.test(value)) return value;
  if (!/['\r\n]/.test(value)) return `'${value}'`;
  return `"${value.replace(/[\\"\n\r\t]/g, (c) => ({ "\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t" })[c]!)}"`;
}

/** Replaces the token of the last entry with that key; without one, appends `KEY=<quoted>` plus the file's first line terminator (default "\n"), after terminating an unterminated last line. Throws on a key that fails ENV_KEY. */
export function setEnvEntry(text: string, key: string, value: string): string {
  if (!ENV_KEY.test(key)) throw new Error("env key is invalid");
  const lines = parseEnv(text);
  let idx = -1;
  lines.forEach((l, i) => { if (l.kind === "entry" && l.key === key) idx = i; });
  let out: string;
  if (idx >= 0) {
    const l = lines[idx] as Entry;
    let token = quoteEnvValue(value);
    // A bare token right before "#" would swallow the comment (`K="a"#c`); quote it instead.
    if (l.tail.startsWith("#") && !/^['"]/.test(token)) token = `'${value}'`;
    lines[idx] = { ...l, token, raw: l.head + token + l.tail };
    out = lines.map((x) => x.raw).join("");
  } else {
    const nl = text.indexOf("\n");
    const eol = nl > 0 && text[nl - 1] === "\r" ? "\r\n" : "\n";
    out = text + (text === "" || text.endsWith("\n") ? "" : eol) + `${key}=${quoteEnvValue(value)}${eol}`;
  }
  // An unterminated quote earlier in the file could absorb the new line; refuse rather than save a file that reads otherwise.
  if (envValue(out, key) !== value) throw new Error("env entry couldn't be set");
  return out;
}

/** By envValue, each list in `after`'s (removed: `before`'s) key order. */
export function diffEnv(before: string, after: string): { added: string[]; changed: string[]; removed: string[] } {
  const b = new Map(entriesOf(before).map((e) => [e.key, e.value])), a = new Map(entriesOf(after).map((e) => [e.key, e.value]));
  const ak = envKeys(after);
  return {
    added: ak.filter((k) => !b.has(k)),
    changed: ak.filter((k) => b.has(k) && b.get(k) !== a.get(k)),
    removed: envKeys(before).filter((k) => !a.has(k)),
  };
}

/** Throws "env file is too large", "env file has too many entries" or "env file isn't text" (a NUL). */
export function checkEnvContent(text: string): void {
  if (utf8.encode(text).length > MAX_ENV_BYTES) throw new Error("env file is too large");
  if (text.includes("\u0000")) throw new Error("env file isn't text");
  if (entriesOf(text).length > MAX_ENV_ENTRIES) throw new Error("env file has too many entries");
}

/** The name a download gets: `name` when it matches /^[A-Za-z0-9._-]{1,100}$/ and is not only dots, else ".env". (`safeFilename` strips the leading dot, so it is not used here.) */
export const envFileName = (name?: string): string => (name && /^[A-Za-z0-9._-]{1,100}$/.test(name) && !/^\.+$/.test(name) ? name : ".env");
