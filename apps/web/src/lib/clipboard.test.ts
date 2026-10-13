import { afterEach, describe, expect, it, vi } from "vitest";
import { copySecret } from "./clipboard";

const focus = (v: boolean) => vi.spyOn(document, "hasFocus").mockReturnValue(v);
afterEach(() => vi.restoreAllMocks());

describe("copySecret", () => {
  it("defers the clear until the window regains focus", async () => {
    vi.useFakeTimers();
    let content = "";
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async (t: string) => { content = t; }), readText: vi.fn(async () => content) } });
    const spy = focus(false);
    await copySecret("hunter2", 1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(content).toBe("hunter2");
    spy.mockReturnValue(true);
    window.dispatchEvent(new Event("focus"));
    await vi.advanceTimersByTimeAsync(0);
    expect(content).toBe("");
    vi.useRealTimers();
  });
  it("clears the clipboard after the delay if it still holds the secret", async () => {
    vi.useFakeTimers(); focus(true);
    let content = "";
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async (t: string) => { content = t; }), readText: vi.fn(async () => content) } });
    await copySecret("hunter2", 1000);
    expect(content).toBe("hunter2");
    await vi.advanceTimersByTimeAsync(1000);
    expect(content).toBe("");
    vi.useRealTimers();
  });
  it("does not clear something else the user copied later", async () => {
    vi.useFakeTimers(); focus(true);
    let content = "";
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async (t: string) => { content = t; }), readText: vi.fn(async () => content) } });
    await copySecret("hunter2", 1000);
    content = "user copied this";
    await vi.advanceTimersByTimeAsync(1000);
    expect(content).toBe("user copied this");
    vi.useRealTimers();
  });
});
