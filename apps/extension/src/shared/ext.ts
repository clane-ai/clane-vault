/** The WebExtension API: Firefox's promise-based `browser`, else Chrome's `chrome` (promise-based in MV3). */
export const ext: typeof chrome = (globalThis as unknown as { browser?: typeof chrome }).browser ?? chrome;

/** Message to the background; resolves with its answer. */
export const send = <T,>(msg: unknown): Promise<T> => ext.runtime.sendMessage(msg) as Promise<T>;

/** Clears the clipboard from a document (offscreen page or Firefox background page): a copy event with empty text. */
export function clearClipboardHere(doc: Document = document): boolean {
  const onCopy = (e: ClipboardEvent) => { e.clipboardData?.setData("text/plain", ""); e.preventDefault(); };
  doc.addEventListener("copy", onCopy, { once: true });
  try { return doc.execCommand("copy"); } finally { doc.removeEventListener("copy", onCopy); }
}
