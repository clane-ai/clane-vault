import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Logo } from "./Logo";

describe("Logo", () => {
  it("shows the Clane mark and the product name", () => {
    render(<Logo />);
    const logo = screen.getByRole("img", { name: "Clane Vault" });
    expect(logo.querySelector(".vault-mark__word")).not.toBeNull();
    expect(screen.getByText("Vault")).toBeInTheDocument();
  });
  it("can show the mark alone", () => {
    render(<Logo showProduct={false} />);
    expect(screen.queryByText("Vault")).not.toBeInTheDocument();
  });
  it("uses the dark theme on dark grounds and follows the app theme elsewhere", () => {
    const { rerender } = render(<Logo onDark />);
    expect(screen.getByRole("img")).toHaveAttribute("data-variant", "dark");
    rerender(<Logo />);
    expect(screen.getByRole("img")).toHaveAttribute("data-variant", "auto");
  });
  it("passes the working state through", () => {
    render(<Logo state="working" />);
    expect(screen.getByRole("img")).toHaveAttribute("data-state", "working");
  });
});
