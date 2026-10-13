// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { showBanner, tampered } from "../src/content/banner";

const view = { kind: "update" as const, host: "accounts.example.com", username: "ana" };
afterEach(() => { document.body.innerHTML = ""; document.documentElement.removeAttribute("style"); document.body.removeAttribute("style"); vi.useRealTimers(); });

function mount() {
  const answer = vi.fn(async () => ({ ok: true }));
  const close = showBanner(view, answer);
  const host = document.querySelector("clane-vault-prompt") as HTMLElement;
  const box = document.createElement("div");
  host.parentElement!.append(box);
  return { answer, close, host, box };
}

describe("save banner", () => {
  it("lives in a closed shadow root and ignores clicks from page script", () => {
    const { answer, host } = mount();
    expect(host.shadowRoot).toBeNull();
    host.click();
    host.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
    expect(answer).not.toHaveBeenCalled();
  });

  it("detects a banner the page made see-through, filtered, hidden, transformed or moved", () => {
    const { host, box } = mount();
    const rect = box.getBoundingClientRect();
    expect(tampered(host, box, rect, document)).toBe(false);
    for (const style of ["opacity: 0", "opacity: 0.1", "visibility: hidden", "display: none", "transform: scale(0.01)", "clip-path: inset(50%)", "filter: opacity(0)", "mix-blend-mode: multiply"]) {
      host.setAttribute("style", style);
      expect(tampered(host, box, rect, document), style).toBe(true);
    }
    host.removeAttribute("style");
    document.body.setAttribute("style", "opacity: 0.02");
    expect(tampered(host, box, rect, document)).toBe(true);
    document.body.removeAttribute("style");
    document.documentElement.setAttribute("style", "filter: opacity(0)");
    expect(tampered(host, box, rect, document)).toBe(true);
    document.documentElement.removeAttribute("style");
    expect(tampered(host, box, { top: 400, left: rect.left, width: rect.width, height: rect.height } as DOMRect, document)).toBe(true);
    host.remove();
    expect(tampered(host, box, rect, document)).toBe(true);
  });

  it("closes itself after a minute", () => {
    vi.useFakeTimers();
    mount();
    vi.advanceTimersByTime(60_001);
    expect(document.querySelector("clane-vault-prompt")).toBeNull();
  });
});
