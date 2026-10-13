import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RecordAvatar, tileFor } from "./RecordAvatar";

describe("RecordAvatar", () => {
  it("shows the title's first letter on a stable tile", () => {
    render(<RecordAvatar title="aws root" />);
    const a = screen.getByTestId("record-avatar");
    expect(a).toHaveTextContent("A");
    expect(a).toHaveAttribute("aria-hidden", "true");
    expect(a.className).toContain(tileFor("aws root").split(" ")[0]);
    expect(tileFor("aws root")).toBe(tileFor("aws root"));
  });

  it("22 px in list rows (6 px radius, 11 px letter)", () => {
    render(<RecordAvatar title="AWS" size={22} />);
    expect(screen.getByTestId("record-avatar")).toHaveClass("size-[22px]", "rounded-[6px]", "text-[11px]");
  });

  it("a secure note gets the note glyph on the well, not a letter", () => {
    render(<RecordAvatar title="VPN runbook" kind="note" size={22} />);
    const a = screen.getByTestId("record-avatar");
    expect(a).toHaveAttribute("data-kind", "note");
    expect(a).toHaveClass("bg-well");
    expect(a).not.toHaveTextContent("V");
    expect(a.querySelector("svg")).not.toBeNull();
  });

  it("a record that can't be opened shows ?", () => {
    render(<RecordAvatar title={null} />);
    expect(screen.getByTestId("record-avatar")).toHaveTextContent("?");
  });

  it("the navy tile is lifted in the dark theme", () => {
    const navy = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"].map(tileFor).find((t) => t.includes("navy"));
    expect(navy).toBe("bg-navy-700 dark:bg-[#2A4A8A]");
  });
});
