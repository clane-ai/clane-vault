// Generated from the CLANE icon kit (clane-brand dist/svg/2b/2b-bare-dark.svg and dist/wordmark/wordmark-paper.svg,
// copied to public/brand/). Do not edit by hand: brand.glyphs.test.ts checks these against the SVG files.
/** [x, y, width, height] in design units. */
export type Cell = readonly [number, number, number, number];

/** 2b "Pixel neuron", 9×9 units: the stepped ring (12 cells). */
export const NEURON_RING: readonly Cell[] = [
  [3, 0, 3, 2],
  [2, 1, 2, 2],
  [5, 1, 2, 2],
  [1, 2, 2, 2],
  [6, 2, 2, 2],
  [0, 3, 2, 3],
  [7, 3, 2, 3],
  [1, 5, 2, 2],
  [6, 5, 2, 2],
  [2, 6, 2, 2],
  [5, 6, 2, 2],
  [3, 7, 3, 2],
];

/** The neuron's single centre cell. Dropped below 24 px. */
export const NEURON_CORE: Cell = [4, 4, 1, 1];

/** CLANE master wordmark, 50×9 units. */
export const WORDMARK: readonly Cell[] = [
  [1, 0, 7, 2],
  [0, 1, 2, 7],
  [1, 7, 7, 2],
  [10, 0, 2, 7],
  [10, 7, 8, 2],
  [22, 0, 5, 2],
  [21, 1, 2, 2],
  [20, 2, 2, 7],
  [26, 1, 2, 2],
  [27, 2, 2, 7],
  [22, 4, 5, 2],
  [31, 0, 2, 9],
  [38, 0, 2, 9],
  [33, 1, 2, 2],
  [34, 3, 2, 2],
  [35, 5, 2, 2],
  [36, 7, 2, 2],
  [42, 0, 8, 2],
  [42, 0, 2, 9],
  [44, 4, 5, 2],
  [42, 7, 8, 2],
];
