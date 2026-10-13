import { clearClipboardHere, ext } from "../shared/ext";
import type { FillResult } from "../shared/forms";
import type { ContentMessage, PopupMessage } from "../shared/messages";
import { createCore, type KV } from "./core";

const kv = (area: chrome.storage.StorageArea): KV => ({
  get: async <T,>(key: string) => (await area.get(key))[key] as T | undefined,
  set: (key, value) => area.set({ [key]: value }),
  remove: (key) => area.remove(key),
});

const SAVE_SCRIPT = "save-offers";
const OFFSCREEN = "offscreen.html";

/** Chrome: the offscreen document clears the clipboard. Firefox: the background page has a document of its own. */
async function clearClipboard() {
  if (!ext.offscreen) { clearClipboardHere(); return; }
  const url = ext.runtime.getURL(OFFSCREEN);
  const open = await ext.runtime.getContexts({ contextTypes: [ext.runtime.ContextType.OFFSCREEN_DOCUMENT], documentUrls: [url] });
  if (!open.length) await ext.offscreen.createDocument({ url: OFFSCREEN, reasons: [ext.offscreen.Reason.CLIPBOARD], justification: "Clear a copied password from the clipboard after 30 seconds" });
  await ext.runtime.sendMessage({ target: "offscreen", type: "clear-clipboard" });
}

const core = createCore({
  session: kv(ext.storage.session),
  local: kv(ext.storage.local),
  tabUrl: async (tabId) => (await ext.tabs.get(tabId)).url,
  async fill(tabId, origin, username, password): Promise<FillResult> {
    // Top frame only: never into iframes, whatever their origin. The fill script re-checks the origin itself.
    const target = { tabId, frameIds: [0] };
    await ext.scripting.executeScript({ target, files: ["fill.js"] });
    const [r] = await ext.scripting.executeScript({
      target, args: [origin, username, password],
      func: (o: string, u: string | null, p: string | null) => (globalThis as unknown as { __claneFill: (o: string, u: string | null, p: string | null) => unknown }).__claneFill(o, u, p),
    });
    return (r?.result as FillResult | undefined) ?? { ok: false, reason: "no_fields" };
  },
  armAutoLock: (minutes) => {
    void ext.alarms.create("autolock", { delayInMinutes: minutes });
    // The machine idle for the whole auto-lock time means no popup use either: lock then too (see onStateChanged).
    ext.idle?.setDetectionInterval(Math.max(15, Math.round(minutes * 60)));
  },
  scheduleClipboardClear: () => { void ext.alarms.create("clipboard", { delayInMinutes: 0.5 }); },
});

/** The save-offer content script runs only while the user has it on and has granted access to all sites. */
async function syncContentScripts() {
  await core.hydrate();
  const { saveOffers } = core.state();
  const allowed = await ext.permissions.contains({ origins: ["<all_urls>"] });
  const registered = (await ext.scripting.getRegisteredContentScripts({ ids: [SAVE_SCRIPT] })).length > 0;
  if (saveOffers && allowed && !registered)
    await ext.scripting.registerContentScripts([{ id: SAVE_SCRIPT, js: ["content.js"], matches: ["https://*/*", "http://*/*"], runAt: "document_idle", allFrames: false }]);
  else if ((!saveOffers || !allowed) && registered) await ext.scripting.unregisterContentScripts({ ids: [SAVE_SCRIPT] });
}

ext.runtime.onMessage.addListener((msg: { type?: string; target?: string }, sender, sendResponse) => {
  if (msg?.target === "offscreen") return false;
  const fromExtensionPage = sender.id === ext.runtime.id && !!sender.url?.startsWith(ext.runtime.getURL(""));
  let work: Promise<unknown>;
  if (fromExtensionPage) {
    work = core.onPopup(msg as PopupMessage).then(async (r) => { if (msg.type === "settings") await syncContentScripts(); return r; });
  } else if (sender.id === ext.runtime.id && sender.tab?.id !== undefined && sender.url) {
    work = core.onContent(msg as ContentMessage, { tabId: sender.tab.id, frameId: sender.frameId ?? -1, url: sender.url });
  } else return false;
  work.then(sendResponse, (e: unknown) => sendResponse({ error: e instanceof Error ? e.message : "error" }));
  return true;
});

ext.alarms.onAlarm.addListener((a) => {
  if (a.name === "autolock") void core.onAlarm();
  if (a.name === "clipboard") void clearClipboard().catch(() => undefined);
});
// Screen locked, or the machine idle for the auto-lock time: lock the vault too. Firefox does not report "locked"
// everywhere, so the idle state is what locks there.
ext.idle?.onStateChanged.addListener((s) => { if (s === "locked" || s === "idle") void core.onSystemLocked(); });
ext.permissions.onRemoved.addListener(() => { void syncContentScripts(); });
ext.runtime.onStartup.addListener(() => { void syncContentScripts(); });
ext.runtime.onInstalled.addListener(() => { void syncContentScripts(); });
void core.hydrate();
