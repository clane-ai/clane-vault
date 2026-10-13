import "@testing-library/jest-dom/vitest";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, "crypto", { value: webcrypto });

// jsdom lacks the pointer-capture and scroll APIs Radix Select calls.
if (typeof Element !== "undefined") {
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => undefined;
  Element.prototype.scrollIntoView ??= () => undefined;
}

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
afterEach(() => cleanup());

import { afterAll, beforeAll } from "vitest";
import { server } from "./server";
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
