import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Switch } from "./switch";

describe("Switch (Radix)", () => {
  it("exposes data-state=checked on the root", () => {
    render(<Switch defaultChecked aria-label="x" />);
    expect(screen.getByRole("switch", { name: "x" })).toHaveAttribute("data-state", "checked");
  });
});
