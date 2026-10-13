import { fillPage } from "../shared/forms";

// Injected on demand by the background (chrome.scripting, top frame only) right before a user-requested fill.
(globalThis as unknown as { __claneFill: unknown }).__claneFill = (origin: string, username: string | null, password: string | null) =>
  fillPage(document, origin, username, password);
