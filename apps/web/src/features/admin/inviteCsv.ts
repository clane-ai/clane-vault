/**
 * Turns what an admin pastes or uploads into invitation rows (docs/provisioning.md). The server validates every row
 * again; this only splits the input. Pasted text: addresses separated by commas, semicolons, spaces or new lines
 * ("Ann <ann@acme.com>" works too). A CSV: columns email, name, role, groups (groups separated by ";"), with an
 * optional header row naming them in any order.
 */
export interface InviteRowInput { email: string; name?: string; role?: string; groups?: string }

export const MAX_INVITE_ROWS = 500;

/** RFC 4180-style CSV: quoted fields, doubled quotes, CRLF or LF. Blank lines are skipped. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], cell = "", quoted = false;
  const s = text.replace(/^﻿/, "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (quoted) {
      if (c === '"' && s[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
      continue;
    }
    if (c === '"' && cell.trim() === "") { quoted = true; cell = ""; }
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      if (row.some((x) => x.trim())) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x.trim())) rows.push(row);
  return rows.map((r) => r.map((x) => x.trim()));
}

const HEADERS: Record<string, keyof InviteRowInput> = {
  email: "email", "e-mail": "email", "email address": "email", mail: "email",
  name: "name", "full name": "name", "display name": "name",
  role: "role",
  groups: "groups", group: "groups", teams: "groups",
};

/** Rows from a CSV file: a header row (any order) or, without one, email, name, role, groups. */
export function rowsFromCsv(text: string): InviteRowInput[] {
  const table = parseCsv(text);
  if (!table.length) return [];
  const head = table[0]!.map((h) => HEADERS[h.toLowerCase()]);
  const hasHeader = head.includes("email");
  const cols: (keyof InviteRowInput | undefined)[] = hasHeader ? head : ["email", "name", "role", "groups"];
  return (hasHeader ? table.slice(1) : table).map((r) => {
    const out: InviteRowInput = { email: "" };
    cols.forEach((k, i) => { const v = r[i]?.trim(); if (k && v) out[k] = v; });
    return out;
  }).filter((r) => r.email || r.name);
}

/** Rows from pasted text: one per address. */
export function rowsFromPaste(text: string): InviteRowInput[] {
  return text.split(/[\n\r,;]+/).flatMap((part) => {
    const p = part.trim();
    if (!p) return [];
    // "Ann Example <ann@acme.com>"
    const angle = /^(.*?)<([^<>\s]+)>\s*$/.exec(p);
    if (angle) return [{ email: angle[2]!.trim(), ...(angle[1]!.trim().replace(/^"|"$/g, "") ? { name: angle[1]!.trim().replace(/^"|"$/g, "") } : {}) }];
    return p.split(/\s+/).filter(Boolean).map((email) => ({ email }));
  });
}
