import { useSyncExternalStore } from "react";

/** Chrome and Edge's install offer (not in the DOM typings). */
interface BeforeInstallPromptEvent extends Event { prompt(): Promise<void>; userChoice: Promise<{ outcome: "accepted" | "dismissed" }> }

let offer: BeforeInstallPromptEvent | null = null;
const listeners = new Set<() => void>();
const notify = () => { for (const l of listeners) l(); };

if (typeof window !== "undefined") {
  // Kept for the account menu's "Install app" (docs/install-app.md); the browser's own install icon still works.
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); offer = e as BeforeInstallPromptEvent; notify(); });
  window.addEventListener("appinstalled", () => { offer = null; notify(); });
}

/** Opens the browser's install dialog; null when the browser hasn't offered one (installed already, Safari, Firefox). */
export function useInstallPrompt(): (() => Promise<void>) | null {
  const o = useSyncExternalStore((l) => { listeners.add(l); return () => { listeners.delete(l); }; }, () => offer, () => null);
  if (!o) return null;
  return async () => { await o.prompt(); await o.userChoice.catch(() => undefined); offer = null; notify(); };
}
