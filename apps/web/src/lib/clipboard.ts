async function clearIfSame(text: string) {
  try { if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText(""); }
  catch { /* reading the clipboard needs permission; skip if refused */ }
}

export async function copySecret(text: string, clearAfterMs = 30_000): Promise<void> {
  await navigator.clipboard.writeText(text);
  setTimeout(() => {
    if (document.hasFocus()) { void clearIfSame(text); return; }
    // The browser refuses clipboard reads while the page is unfocused; wait until it is visible again.
    const retry = () => {
      if (!document.hasFocus()) return;
      window.removeEventListener("focus", retry); document.removeEventListener("visibilitychange", retry);
      void clearIfSame(text);
    };
    window.addEventListener("focus", retry); document.addEventListener("visibilitychange", retry);
  }, clearAfterMs);
}
