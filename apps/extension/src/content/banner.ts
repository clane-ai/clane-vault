import type { PromptView } from "../shared/messages";

export type Answer = "save" | "update" | "never" | "dismiss";

const CSS = `
:host { all: initial; }
.b { position: fixed; top: 16px; right: 16px; z-index: 2147483647; width: 320px; box-sizing: border-box; padding: 14px 14px 12px;
  background: #0A1224; color: #F7F9FC; border: 1px solid rgba(222,230,242,.12); border-radius: 14px; box-shadow: 0 12px 32px rgba(7,14,28,.35);
  font: 13px/1.4 "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif; }
.h { display: flex; align-items: center; gap: 8px; font: 600 14px/1.2 "Space Grotesk", ui-sans-serif, system-ui, sans-serif; letter-spacing: -.01em; }
.m { width: 18px; height: 18px; flex: none; }
.s { margin: 6px 0 12px; color: #A9B6CE; word-break: break-word; }
.r { display: flex; gap: 8px; align-items: center; }
button { font: 500 13px/1 "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif; border-radius: 9px; padding: 8px 12px; cursor: pointer; border: 1px solid rgba(222,230,242,.18); background: transparent; color: #F7F9FC; }
button.p { background: #FF6A3D; border-color: #FF6A3D; color: #0A1224; }
button.l { margin-left: auto; border: 0; color: #A9B6CE; padding: 8px 4px; }
button.x { position: absolute; top: 8px; right: 8px; border: 0; padding: 4px 6px; color: #8A9BB8; font-size: 16px; }
button:focus-visible { outline: 2px solid #3E7BFA; outline-offset: 2px; }
`;
const MARK = `<svg class="m" viewBox="0 0 9 9" shape-rendering="crispEdges" aria-hidden="true" fill="#FF6A3D"><path d="M3 0h3v2H3zM2 1h2v2H2zM5 1h2v2H5zM1 2h2v2H1zM6 2h2v2H6zM0 3h2v3H0zM7 3h2v3H7zM1 5h2v2H1zM6 5h2v2H6zM2 6h2v2H2zM5 6h2v2H5zM3 7h3v2H3zM4 4h1v1H4z"/></svg>`;

/** A click counts only once the banner has been on screen, unchanged, for this long (no pop-under or flash clicks). */
export const ARM_MS = 700;
const CHECK_MS = 100;
const COVERED = "This page is covering or restyling the offer, so it can't be answered here.";

/**
 * Whether the page is hiding or restyling the banner (clickjacking: a see-through banner under a decoy, or one moved
 * under the cursor). The host element lives in the page's DOM, so page CSS and script can reach it even though they
 * can't see inside the closed shadow root.
 */
export function tampered(host: HTMLElement, box: HTMLElement, rect: DOMRect | null, doc: Document): boolean {
  const win = doc.defaultView;
  if (!win || !host.isConnected) return true;
  for (let n: Element | null = host; n; n = n.parentElement) {
    const s = win.getComputedStyle(n);
    if (s.display === "none" || parseFloat(s.opacity) < 1 || (s.filter && s.filter !== "none")) return true;
    if (n === host && ((s.visibility && s.visibility !== "visible") || (s.clipPath && s.clipPath !== "none") ||
      (s.transform && s.transform !== "none") || (s.mixBlendMode && s.mixBlendMode !== "normal"))) return true;
  }
  const r = box.getBoundingClientRect();
  return !!rect && (r.top !== rect.top || r.left !== rect.left || r.width !== rect.width || r.height !== rect.height);
}

/**
 * The save/update offer, in a closed shadow root so the page can neither style its inside nor read it. Only trusted
 * clicks (a real user, not page script) answer it, and only when the banner has been visible, unmoved and on top for
 * ARM_MS. Known limit: an overlay with pointer-events:none on top of it can't be detected from a page.
 */
export function showBanner(view: PromptView, answer: (a: Answer) => Promise<{ ok: boolean } | null>, doc: Document = document): () => void {
  const host = doc.createElement("clane-vault-prompt");
  const root = host.attachShadow({ mode: "closed" });
  const style = doc.createElement("style");
  style.textContent = CSS;
  const box = doc.createElement("div");
  box.className = "b";
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-label", view.kind === "save" ? "Save login" : "Update password");
  const title = doc.createElement("div");
  title.className = "h";
  title.innerHTML = MARK;
  title.append(view.kind === "save" ? "Save this login?" : "Update the saved password?");
  const sub = doc.createElement("div");
  sub.className = "s";
  sub.textContent = view.kind === "save" ? `${view.username || "No username"} on ${view.host}, to your private vault.` : `${view.username || "No username"} on ${view.host}.`;
  const row = doc.createElement("div");
  row.className = "r";
  const btn = (label: string, cls: string, a: Answer) => {
    const b = doc.createElement("button");
    b.type = "button"; b.className = cls; b.textContent = label;
    b.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      if (a !== "dismiss") { // closing is always fine; saving, updating and "never" need an unobscured banner
        // A pointer click must land on the banner itself (nothing of the page's on top); keyboard clicks have detail 0.
        const onTop = e.detail === 0 || typeof doc.elementsFromPoint !== "function" || doc.elementsFromPoint(e.clientX, e.clientY)[0] === host;
        if (!onTop || tampered(host, box, rect, doc)) { rearm(); sub.textContent = COVERED; return; }
        if (Date.now() < armedAt) return;
      }
      row.querySelectorAll("button").forEach((x) => { x.disabled = true; });
      void answer(a).then((r) => {
        if (a === "save" || a === "update") { sub.textContent = r?.ok ? (a === "save" ? "Saved." : "Updated.") : "That didn't work. Try again from the extension."; setTimeout(close, r?.ok ? 1500 : 4000); }
        else close();
      });
    });
    return b;
  };
  row.append(btn(view.kind === "save" ? "Save" : "Update", "p", view.kind), btn("Not now", "", "dismiss"), btn("Never for this site", "l", "never"));
  const x = btn("×", "x", "dismiss");
  x.setAttribute("aria-label", "Close");
  box.append(x, title, sub, row);
  root.append(style, box);
  (doc.body ?? doc.documentElement).append(host);
  let armedAt = Date.now() + ARM_MS;
  let rect: DOMRect | null = box.getBoundingClientRect();
  function rearm() { armedAt = Date.now() + ARM_MS; rect = box.isConnected ? box.getBoundingClientRect() : null; }
  // Any change to the host element, or a hidden/moved banner seen by the periodic check, restarts the arming delay.
  const watch = new MutationObserver(rearm);
  watch.observe(host, { attributes: true });
  const check = setInterval(() => { if (tampered(host, box, rect, doc)) rearm(); }, CHECK_MS);
  const timer = setTimeout(close, 60_000);
  function close() { clearTimeout(timer); clearInterval(check); watch.disconnect(); host.remove(); }
  return close;
}
