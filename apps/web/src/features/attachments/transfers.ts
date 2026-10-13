import { cancelAllUploads } from "./uploader";

/** Downloads in flight, so locking the vault can stop them (their keys are zeroed by their own finally blocks). */
const downloads = new Set<AbortController>();

export function trackDownload(): { signal: AbortSignal; done: () => void } {
  const c = new AbortController();
  downloads.add(c);
  return { signal: c.signal, done: () => { downloads.delete(c); } };
}

/** The vault locked (or the session ended): every upload and download stops and forgets its keys. */
export function cancelAllTransfers(): void {
  cancelAllUploads();
  for (const c of downloads) c.abort();
  downloads.clear();
}
