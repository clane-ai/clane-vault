import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Showcase, SLIDE_MS, SLIDES } from "./Showcase";

const current = () => screen.getAllByRole("group", { hidden: true }).find((g) => g.getAttribute("aria-hidden") !== "true")!;
function mockReducedMotion(reduce: boolean) {
  window.matchMedia = vi.fn().mockImplementation((q: string) => ({ matches: reduce && q.includes("reduce"), media: q, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
}

describe("Showcase", () => {
  beforeEach(() => { vi.useFakeTimers(); mockReducedMotion(false); });
  afterEach(() => vi.useRealTimers());

  it("rotates every 6 seconds and pauses while hovered", () => {
    render(<Showcase />);
    expect(current()).toHaveAccessibleName(`1 of 3: ${SLIDES[0].title}`);
    act(() => { vi.advanceTimersByTime(SLIDE_MS); });
    expect(current()).toHaveAccessibleName(`2 of 3: ${SLIDES[1].title}`);
    fireEvent.mouseEnter(screen.getByRole("region", { name: "What's in Clane Vault" }));
    act(() => { vi.advanceTimersByTime(SLIDE_MS * 3); });
    expect(current()).toHaveAccessibleName(`2 of 3: ${SLIDES[1].title}`);
  });

  it("dots jump to a slide and the pause button stops autoplay", () => {
    render(<Showcase />);
    fireEvent.click(screen.getByRole("button", { name: `Show slide 3 of 3: ${SLIDES[2].title}` }));
    expect(current()).toHaveAccessibleName(`3 of 3: ${SLIDES[2].title}`);
    expect(screen.getByRole("button", { name: /Show slide 3/ })).toHaveAttribute("aria-current", "true");
    fireEvent.click(screen.getByRole("button", { name: "Pause slideshow" }));
    fireEvent.blur(screen.getByRole("button", { name: "Play slideshow" }));
    act(() => { vi.advanceTimersByTime(SLIDE_MS * 2); });
    expect(current()).toHaveAccessibleName(`3 of 3: ${SLIDES[2].title}`);
  });

  it("does not autoplay when reduced motion is preferred", () => {
    mockReducedMotion(true);
    render(<Showcase />);
    expect(screen.getByRole("button", { name: "Play slideshow" })).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(SLIDE_MS * 2); });
    expect(current()).toHaveAccessibleName(`1 of 3: ${SLIDES[0].title}`);
  });
});
