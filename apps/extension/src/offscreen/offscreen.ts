import { clearClipboardHere, ext } from "../shared/ext";

// Chrome's offscreen document: the only place an MV3 extension can write the clipboard without a visible page.
ext.runtime.onMessage.addListener((msg: { target?: string; type?: string }) => {
  if (msg?.target === "offscreen" && msg.type === "clear-clipboard") clearClipboardHere();
  return false;
});
