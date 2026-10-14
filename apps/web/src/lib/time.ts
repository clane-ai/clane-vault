const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];

/** "just now", "5 minutes ago", "yesterday"… */
/** A time of day as the rest of the app shows it (the browser's locale, hours and minutes). */
export const clockTime = (d: Date | string): string => new Date(d).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

export function relativeTime(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const secs = Math.round((t - now) / 1000);
  if (Math.abs(secs) < 45) return "just now";
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of UNITS) if (Math.abs(secs) >= size || unit === "minute") return rtf.format(Math.round(secs / size), unit);
  return "just now";
}
