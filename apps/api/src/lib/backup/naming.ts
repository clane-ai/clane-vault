const pad = (n: number) => String(n).padStart(2, "0");
const STAMP = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/;

/** `clane-vault-<schema>-<UTC yyyyMMdd-HHmmss>.dump.age` */
export function backupName(schema: string, at: Date): string {
  const d = at;
  const stamp = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
  return `clane-vault-${schema}-${stamp}.dump.age`;
}

/** The UTC time a backup name encodes, or null when the name is not one of this schema's backups. */
export function backupTime(name: string, schema: string): Date | null {
  const base = name.slice(name.lastIndexOf("/") + 1);
  const head = `clane-vault-${schema}-`;
  if (!base.startsWith(head) || !base.endsWith(".dump.age")) return null;
  const m = STAMP.exec(base.slice(head.length, -".dump.age".length));
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m.map(Number) as [number, number, number, number, number, number, number];
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return Number.isNaN(t.getTime()) ? null : t;
}

/**
 * Names to delete under the retention policy: this schema's backups older than `days`. Anything else in the
 * bucket/dir (other schemas, other files) is never touched, and `keep` (the backup just written) always stays.
 */
export function selectExpired(names: string[], opts: { schema: string; days: number; now: Date; keep?: string }): string[] {
  const cutoff = opts.now.getTime() - opts.days * 864e5;
  return names.filter((n) => {
    if (n === opts.keep) return false;
    const t = backupTime(n, opts.schema);
    return t !== null && t.getTime() < cutoff;
  });
}
