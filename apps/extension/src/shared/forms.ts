/**
 * Login form detection and filling. Runs in pages (content script and the fill script), so it touches only the DOM.
 * Nothing here talks to the extension: callers pass values in and get plain results out.
 */

const TEXTY = new Set(["text", "email", "tel", ""]);
const USERNAME_HINT = /user|email|e-mail|login|account|identifier|phone/i;

/** Hidden, disabled or zero-opacity fields are never filled or read (a classic credential-harvesting trick). */
export function isUsable(el: HTMLInputElement): boolean {
  if (el.disabled || el.readOnly || el.type === "hidden" || el.hidden) return false;
  for (let n: Element | null = el; n; n = n.parentElement) {
    if (n.getAttribute("aria-hidden") === "true" || (n as HTMLElement).hidden) return false;
    const s = n.ownerDocument.defaultView?.getComputedStyle(n);
    if (s && (s.display === "none" || s.visibility === "hidden" || s.opacity === "0")) return false;
  }
  return true;
}

const inputs = (root: ParentNode) => Array.from(root.querySelectorAll("input")).filter(isUsable);

export interface LoginFields { username: HTMLInputElement | null; password: HTMLInputElement | null }

/**
 * The login fields of a page or form: the first usable password field (a current-password one before a new-password
 * one) and the username field before it in the same form (autocomplete="username" or a user/email-like name first).
 * Without a password field, a lone username field (two-step sign-ins) is returned.
 */
export function findLoginFields(root: ParentNode): LoginFields {
  const all = inputs(root);
  const passwords = all.filter((i) => i.type === "password");
  const password = passwords.find((p) => p.autocomplete !== "new-password") ?? passwords[0] ?? null;
  const scope = password?.form ?? null;
  const before = all.filter((i) => TEXTY.has(i.type) && (!scope || i.form === scope) &&
    (!password || (i.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0));
  const hinted = (i: HTMLInputElement) => i.autocomplete === "username" || i.type === "email" || USERNAME_HINT.test(`${i.name} ${i.id} ${i.placeholder} ${i.getAttribute("aria-label") ?? ""}`);
  const username = before.find((i) => i.autocomplete === "username") ?? [...before].reverse().find(hinted) ?? before[before.length - 1] ?? null;
  return { username, password };
}

/** Sets a value the way typing does, so React/Vue/Angular forms see it. */
export function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el) as object, "value")?.set;
  if (setter) setter.call(el, value); else el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

export type FillResult = { ok: true; filled: ("username" | "password")[] } | { ok: false; reason: "frame" | "navigated" | "no_fields" };

/**
 * Fills the top-level page. `expectedOrigin` is the origin the extension checked before injecting: if the tab has
 * navigated since, nothing is filled.
 */
export function fillPage(doc: Document, expectedOrigin: string, username: string | null, password: string | null): FillResult {
  const win = doc.defaultView;
  if (!win || win.top !== win) return { ok: false, reason: "frame" };
  if (win.location.origin !== expectedOrigin) return { ok: false, reason: "navigated" };
  const f = findLoginFields(doc);
  const filled: ("username" | "password")[] = [];
  if (f.username && username) { setValue(f.username, username); filled.push("username"); }
  if (f.password && password) { setValue(f.password, password); filled.push("password"); }
  return filled.length ? { ok: true, filled } : { ok: false, reason: "no_fields" };
}

/** What a submitted login form held: a non-empty password and the username next to it (or remembered from step one). */
export function readSubmission(root: ParentNode, rememberedUsername = ""): { username: string; password: string } | null {
  const f = findLoginFields(root);
  const password = f.password?.value ?? "";
  if (!password) return null;
  return { username: (f.username?.value ?? "").trim() || rememberedUsername, password };
}
