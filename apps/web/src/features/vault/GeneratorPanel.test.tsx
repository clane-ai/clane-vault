import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GeneratorPanel } from "./GeneratorPanel";

describe("GeneratorPanel", () => {
  it("generates on open, regenerates, and hands the password over", async () => {
    const onUse = vi.fn();
    render(<GeneratorPanel onUse={onUse} />);
    const first = screen.getByTestId("generated").textContent!;
    expect(first).toHaveLength(20);
    await userEvent.click(screen.getByRole("button", { name: "Regenerate" }));
    expect(screen.getByTestId("generated").textContent).not.toBe(first);
    await userEvent.click(screen.getByRole("switch", { name: "Symbols" }));
    expect(screen.getByTestId("generated").textContent).toMatch(/^[A-Za-z0-9]+$/);
    await userEvent.click(screen.getByRole("button", { name: "Use password" }));
    expect(onUse).toHaveBeenCalledWith(screen.getByTestId("generated").textContent);
  });
});
