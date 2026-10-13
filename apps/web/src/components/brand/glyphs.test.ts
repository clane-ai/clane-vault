import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { NEURON_CORE, NEURON_RING, WORDMARK } from "./glyphs";

const pub = path.resolve(import.meta.dirname, "../../../public/brand");
const cells = (file: string) => [...readFileSync(path.join(pub, file), "utf8").matchAll(/<rect x="(\d+)" y="(\d+)" width="(\d+)" height="(\d+)"\/>/g)].map((m) => m.slice(1, 5).map(Number));
const sort = (a: readonly (readonly number[])[]) => a.map((c) => c.join(",")).sort();

describe("glyphs come from the icon kit, not redrawn", () => {
  it("the neuron matches 2b bare (dark and light) cell for cell", () => {
    for (const f of ["2b-bare-dark.svg", "2b-bare-light.svg"]) expect(sort([...NEURON_RING, NEURON_CORE])).toEqual(sort(cells(f)));
  });
  it("the small favicon drops only the centre cell", () => {
    expect(sort(NEURON_RING)).toEqual(sort(cells("favicon.svg")));
  });
  it("the wordmark matches the kit's wordmark", () => {
    expect(sort(WORDMARK)).toEqual(sort(cells("wordmark-paper.svg")));
    expect(sort(WORDMARK)).toEqual(sort(cells("wordmark-light-clean.svg")));
  });
  it("the ring is 4-fold symmetric, so 90° rest positions draw identical pixels", () => {
    const rot = ([x, y, w, h]: readonly number[]) => [9 - y! - h!, x!, h!, w!];
    expect(sort(NEURON_RING.map(rot))).toEqual(sort(NEURON_RING));
  });
});
