import { withBase } from "@/lib/base";
/** Installs the service worker in production builds (app shell cache for the installable app; docs/install-app.md). */
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD || !("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => { navigator.serviceWorker.register(withBase("/sw.js"), { scope: withBase("/") }).catch(() => undefined); });
}
