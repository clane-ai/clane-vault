import { readFileSync } from "node:fs";
import path from "node:path";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NEURON_RING } from "./glyphs";
import { RING_ORDER, VaultMark, cellAngle } from "./VaultMark";

const css = readFileSync(path.join(import.meta.dirname, "vault-mark.css"), "utf8");
/** The stylesheet without comments, so prose about rotation does not count. */
const rules = css.replace(/\/\*[\s\S]*?\*\//g, "");

const root = () => document.querySelector(".vault-mark") as HTMLElement;

function mockReducedMotion(matches: boolean) {
  vi.stubGlobal("matchMedia", vi.fn((q: string) => ({ matches: q.includes("reduce") && matches, media: q, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
}

describe("VaultMark", () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.resetModules(); });

  it("draws the 12-cell ring and the live centre cell, named after the product", () => {
    render(<VaultMark size={36} />);
    expect(screen.getByRole("img", { name: "Clane Vault" })).toBe(root());
    expect(root().querySelectorAll(".vault-mark__ring rect")).toHaveLength(12);
    expect(root().querySelector(".vault-mark__core")).not.toBeNull();
    expect(screen.getByTestId("vault-mark-svg")).toHaveAttribute("viewBox", "0 0 9 9");
  });

  it("drops the centre cell below 24 px", () => {
    render(<VaultMark size={18} />);
    expect(root().querySelector(".vault-mark__core")).toBeNull();
  });

  it.each(["idle", "working", "unlocked"] as const)("exposes the %s state for its animation", (state) => {
    mockReducedMotion(false);
    render(<VaultMark state={state} variant="dark" />);
    expect(root()).toHaveAttribute("data-state", state);
    expect(root()).toHaveAttribute("data-variant", "dark");
    expect(root()).toHaveAttribute("data-motion", "full");
    expect(root()).not.toHaveClass("vault-mark--static");
  });

  it("is a still mark when the system asks for reduced motion", () => {
    mockReducedMotion(true);
    render(<VaultMark state="working" />);
    expect(root()).toHaveClass("vault-mark--static");
    expect(root()).toHaveAttribute("data-motion", "reduce");
    expect(root()).toHaveAttribute("data-state", "working");
    expect(screen.queryByTestId("vault-mark-lights")).toBeNull();
  });

  it("draws the moving lights over the ring, one per ring cell in clockwise order, when motion is on", () => {
    mockReducedMotion(false);
    render(<VaultMark state="idle" size={36} />);
    const lights = [...screen.getByTestId("vault-mark-lights").querySelectorAll("rect")];
    expect(lights.map((r) => ["x", "y", "width", "height"].map((a) => Number(r.getAttribute(a))))).toEqual(RING_ORDER.map((c) => [...c]));
    expect(lights.map((r) => r.style.getPropertyValue("--i"))).toEqual(RING_ORDER.map((_, i) => String(i)));
  });

  it("is a still mark when animated is off", () => {
    mockReducedMotion(false);
    render(<VaultMark animated={false} />);
    expect(root()).toHaveClass("vault-mark--static");
  });

  it("hides itself from assistive tech when decorative", () => {
    render(<VaultMark decorative />);
    expect(screen.queryByRole("img")).toBeNull();
    expect(root()).toHaveAttribute("aria-hidden", "true");
  });

  it("shows the CLANE wordmark plus the rest of a Clane name", () => {
    render(<VaultMark wordmark />);
    expect(root().querySelector(".vault-mark__word")).not.toBeNull();
    expect(screen.getByText("Vault")).toBeInTheDocument();
    expect(root()).toHaveAttribute("data-name", "clane");
  });

  it("sets any other product name as text, without the wordmark", async () => {
    vi.resetModules();
    vi.stubEnv("VITE_PRODUCT_NAME", "Acme Keys");
    const { VaultMark: Fresh } = await import("./VaultMark");
    render(<Fresh wordmark />);
    expect(screen.getByRole("img", { name: "Acme Keys" })).toBeInTheDocument();
    expect(root().querySelector(".vault-mark__word")).toBeNull();
    expect(screen.getByText("Acme Keys")).toBeInTheDocument();
    expect(root()).toHaveAttribute("data-name", "text");
  });
});

describe("VaultMark ring order", () => {
  const centre = ([x, y, w, h]: readonly number[]) => [x! + w! / 2 - 4.5, y! + h! / 2 - 4.5] as const;

  it("covers every ring cell exactly once", () => {
    const key = (c: readonly number[]) => c.join(",");
    expect(RING_ORDER).toHaveLength(NEURON_RING.length);
    expect(RING_ORDER.map(key).sort()).toEqual(NEURON_RING.map(key).sort());
  });

  it("starts at 12 o'clock and goes clockwise, each step a small turn", () => {
    expect(centre(RING_ORDER[0]!)).toEqual([0, -3.5]);
    const angles = RING_ORDER.map(cellAngle);
    for (let i = 1; i < angles.length; i++) expect(angles[i]!).toBeGreaterThan(angles[i - 1]!);
    for (let i = 0; i < RING_ORDER.length; i++) {
      const [ax, ay] = centre(RING_ORDER[i]!);
      const [bx, by] = centre(RING_ORDER[(i + 1) % RING_ORDER.length]!);
      // Screen y points down, so a positive cross product is a clockwise turn; under 90° keeps the sweep smooth.
      expect(ax * by - ay * bx).toBeGreaterThan(0);
      expect(ax * bx + ay * by).toBeGreaterThan(0);
    }
  });
});

describe("VaultMark styles are pixel-step only", () => {
  it("never rotates, scales or transforms the glyph", () => {
    expect(rules).not.toMatch(/(^|[\s;{])(transform|transform-origin|transform-box|rotate|scale|translate|filter)\s*:/);
    expect(rules).not.toMatch(/\b(rotate|scale|translate|matrix|blur)[XYZ3d]*\(/);
    expect(css).not.toMatch(/\.vault-mark[^{]*\{[^}]*(rotate|transform|scale)/);
  });

  it("steps every mark animation instead of easing it", () => {
    const marks = [...rules.matchAll(/animation:\s*(vm-[\w-]+)[^;]*;/g)].filter((m) => m[1] !== "vm-overlay");
    expect(marks.length).toBeGreaterThan(0);
    for (const m of marks) expect(m[0]).toMatch(/step-end|steps\(/);
    expect(rules).not.toMatch(/\.vault-mark[^{]*\{[^}]*transition/);
  });

  it("switches the motion off for reduced motion", () => {
    const media = rules.slice(rules.indexOf("@media (prefers-reduced-motion: reduce)"));
    expect(media).toMatch(/\.vault-mark__light[^{]*\{\s*animation:\s*none !important/);
    expect(media).toMatch(/\.vault-mark__lights\s*\{\s*display:\s*none/);
    expect(rules).toMatch(/\.vault-mark--static \.vault-mark__lights\s*\{\s*display:\s*none/);
  });
});
