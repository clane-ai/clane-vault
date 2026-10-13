import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FolderGlyph } from "./FolderGlyph";
import { glyphFor } from "./types";

describe("FolderGlyph", () => {
  it("private: blue folder, open or closed, no badge", () => {
    const { rerender } = render(<FolderGlyph kind="private" />);
    const g = screen.getByTestId("folder-glyph");
    expect(g).toHaveAttribute("data-kind", "private");
    expect(g).toHaveClass("size-5", "fill-blue-tint", "stroke-blue-500");
    expect(g).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByTestId("people-badge")).not.toBeInTheDocument();
    const closed = g.querySelector("path")!.getAttribute("d");
    rerender(<FolderGlyph kind="private" open />);
    expect(screen.getByTestId("folder-glyph").querySelector("path")!.getAttribute("d")).not.toBe(closed);
  });

  it("shared: purple folder with the people badge, its ring from --badge-ring", () => {
    render(<FolderGlyph kind="team" size={16} />);
    const g = screen.getByTestId("folder-glyph");
    expect(g).toHaveClass("size-4", "fill-purple-tint", "stroke-purple-ink");
    const ring = screen.getByTestId("people-badge").querySelector("circle")!;
    expect(ring.getAttribute("fill")).toBe("var(--badge-ring, var(--surface-card))");
  });

  it("shared without its key yet: a lock, no badge", () => {
    render(<FolderGlyph kind="team" locked />);
    expect(screen.getByTestId("folder-glyph")).toHaveAttribute("data-locked", "true");
    expect(screen.queryByTestId("people-badge")).not.toBeInTheDocument();
  });

  it("No folder: the inbox", () => {
    render(<FolderGlyph kind="none" />);
    expect(screen.getByTestId("folder-glyph")).toHaveAttribute("data-kind", "none");
  });

  it("glyphFor: a team folder with no key is locked; one still loading (undefined) is not", () => {
    expect(glyphFor(null)).toEqual({ kind: "none", locked: false });
    expect(glyphFor({ kind: "private" })).toEqual({ kind: "private", locked: false });
    expect(glyphFor({ kind: "team", folderKey: null })).toEqual({ kind: "team", locked: true });
    expect(glyphFor({ kind: "team", folderKey: new Uint8Array(1) })).toEqual({ kind: "team", locked: false });
  });
});
