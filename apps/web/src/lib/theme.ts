export type Theme = "light" | "dark" | "system";
const KEY = "cv-theme";

export function getTheme(): Theme {
  try { const v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : "system"; } catch { return "system"; }
}

export function applyTheme(t: Theme) {
  const dark = t === "dark" || (t === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function setTheme(t: Theme) {
  try { t === "system" ? localStorage.removeItem(KEY) : localStorage.setItem(KEY, t); } catch { /* storage blocked */ }
  applyTheme(t);
}
