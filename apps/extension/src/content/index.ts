import { readSubmission } from "../shared/forms";
import { send } from "../shared/ext";
import type { PromptView } from "../shared/messages";
import { showBanner, type Answer } from "./banner";

/**
 * Save offers (opt-in, top frame only). Watches for a login being submitted and hands the username and password to
 * the background, which decides whether to offer "Save" or "Update". Nothing secret ever comes back to the page.
 */
if (window.top === window && !(window as unknown as { __claneSave?: boolean }).__claneSave) {
  (window as unknown as { __claneSave: boolean }).__claneSave = true;
  let last = "";
  let closeBanner: (() => void) | null = null;
  let username = "";

  const show = (v: PromptView | null) => {
    if (!v) return;
    closeBanner?.();
    closeBanner = showBanner(v, (a: Answer) => send<{ ok: boolean }>({ type: "prompt.answer", action: a }).catch(() => null));
  };

  /** Reads the form (or page) around `el` and reports a login once per distinct value pair. */
  const capture = (el: Element | null) => {
    const root: ParentNode = (el instanceof HTMLFormElement ? el : el?.closest("form")) ?? document;
    const s = readSubmission(root, username);
    if (!s) return;
    const key = `${s.username}\n${s.password}`;
    if (key === last) return;
    last = key;
    void send<PromptView | null>({ type: "login.submitted", username: s.username, password: s.password }).then(show, () => undefined);
  };

  // Remember the username of a two-step sign-in (email first, password on the next step of the same page).
  document.addEventListener("change", (e) => {
    const t = e.target;
    if (t instanceof HTMLInputElement && (t.type === "email" || t.autocomplete === "username" || /user|email|login/i.test(t.name + t.id))) username = t.value.trim();
  }, true);
  // Only what the user does counts: page script can't make the extension compare made-up logins (isTrusted).
  document.addEventListener("submit", (e) => { if (e.isTrusted) capture(e.target as Element); }, true);
  // Sign-ins driven by script (no submit event): a click on a submit-like button or Enter in a password field.
  document.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    const b = (e.target as Element | null)?.closest?.("button, input[type=submit], [role=button]");
    const submitLike = b && (b.matches("input[type=submit], button[type=submit], form button:not([type])") || /log\s?in|sign\s?in|continue|submit/i.test(b.textContent ?? ""));
    if (submitLike && (b.closest("form") ?? document).querySelector("input[type=password]")) capture(b);
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.isTrusted && e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password") capture(e.target);
  }, true);

  // After a sign-in redirect, the next page of the same site shows the offer.
  void send<PromptView | null>({ type: "prompt.pending" }).then(show, () => undefined);
}
