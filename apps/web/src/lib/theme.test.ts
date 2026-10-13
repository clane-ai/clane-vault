import { beforeEach, describe, expect, it } from "vitest";
import { applyTheme, getTheme, setTheme } from "./theme";

describe("theme", () => {
  beforeEach(() => { localStorage.clear(); document.documentElement.removeAttribute("data-theme"); });
  it("defaults to system", () => expect(getTheme()).toBe("system"));
  it("stores and applies dark", () => {
    setTheme("dark");
    expect(getTheme()).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });
  it("applies system by following prefers-color-scheme", () => {
    window.matchMedia = ((q: string) => ({ matches: q.includes("dark"), media: q, addEventListener() {}, removeEventListener() {} })) as never;
    applyTheme("system");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });
});
