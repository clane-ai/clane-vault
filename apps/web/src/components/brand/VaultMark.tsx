import { useEffect, useState, type CSSProperties } from "react";
import { cn } from "@/lib/utils";
import { useBrand } from "@/brand";
import { NEURON_CORE, NEURON_RING, WORDMARK, type Cell } from "./glyphs";
import "./vault-mark.css";

export type VaultMarkState = "idle" | "working" | "unlocked";
export type VaultMarkVariant = "dark" | "light" | "auto";

const REDUCE = "(prefers-reduced-motion: reduce)";
const mql = () => (typeof window !== "undefined" && typeof window.matchMedia === "function" ? window.matchMedia(REDUCE) : null);

/** True when the person asked the system for less motion; follows changes live. */
export function useReducedMotion(): boolean {
  const [reduce, setReduce] = useState(() => mql()?.matches ?? false);
  useEffect(() => {
    const m = mql();
    if (!m) return;
    const on = () => setReduce(m.matches);
    on();
    m.addEventListener?.("change", on);
    return () => m.removeEventListener?.("change", on);
  }, []);
  return reduce;
}

/** Centre of the 9×9 neuron, in design units. */
const CENTRE = 4.5;
/** Clockwise angle of a cell's centre around the neuron's centre, 0 at 12 o'clock (screen y points down). */
export const cellAngle = ([x, y, w, h]: Cell) => {
  const a = Math.atan2(x + w / 2 - CENTRE, -(y + h / 2 - CENTRE));
  return a < 0 ? a + 2 * Math.PI : a;
};
/** The ring cells in clockwise order from 12 o'clock: the path the pointer, the chase and the sweep follow. */
export const RING_ORDER: readonly Cell[] = [...NEURON_RING].sort((a, b) => cellAngle(a) - cellAngle(b));

const rects = (cells: readonly Cell[]) => cells.map(([x, y, width, height]) => <rect key={`${x},${y},${width},${height}`} x={x} y={y} width={width} height={height} />);

/** The CLANE pixel wordmark at a whole number of pixels per unit (50×9 units). */
export function Wordmark({ unit = 2, className }: { unit?: number; className?: string }) {
  return (
    <svg aria-hidden="true" focusable="false" className={cn("vault-mark__word", className)} width={50 * unit} height={9 * unit} viewBox="0 0 50 9" shapeRendering="crispEdges">
      {rects(WORDMARK)}
    </svg>
  );
}

export interface VaultMarkProps {
  /** Pixel size of the 9×9 mark; a multiple of 9 keeps every cell on whole pixels. Below 24 px the centre cell is dropped. */
  size?: number;
  /** Colour theme: "dark" for dark grounds, "light" for light ones, "auto" follows the app theme. */
  variant?: VaultMarkVariant;
  /** False draws a still mark (reduced motion always does). */
  animated?: boolean;
  state?: VaultMarkState;
  /** Also show the product name: the CLANE wordmark plus the rest as text for "Clane …" names, else the name as text. */
  wordmark?: boolean;
  /** Pixels per wordmark unit (whole numbers only). */
  wordmarkUnit?: number;
  /** Font size of the name text next to the mark. */
  textSize?: number;
  /** Accessible name; defaults to the product name. */
  label?: string;
  /** Hide from assistive tech when nearby text already says it. */
  decorative?: boolean;
  className?: string;
}

/**
 * The 2b "Pixel neuron" drawn inline so its cells can light up: an idle dial pointer, a working chase and an unlocked
 * sweep. Pixel-step motion only: cells change fill/opacity on stepped timing; nothing rotates or scales.
 */
export function VaultMark({ size = 27, variant = "auto", animated = true, state = "idle", wordmark = false, wordmarkUnit = 2, textSize, label, decorative = false, className }: VaultMarkProps) {
  const { nameParts, productName } = useBrand();
  label ??= productName;
  const reduce = useReducedMotion();
  const still = reduce || !animated;
  const a11y = decorative ? { "aria-hidden": true as const } : { role: "img" as const, "aria-label": label };
  const mark = (
    <svg className="vault-mark__svg" width={size} height={size} viewBox="0 0 9 9" shapeRendering="crispEdges" aria-hidden="true" focusable="false" data-testid="vault-mark-svg">
      <g className="vault-mark__ring">{rects(NEURON_RING)}</g>
      {!still && (
        <g className="vault-mark__lights" data-testid="vault-mark-lights">
          {RING_ORDER.map(([x, y, width, height], i) => <rect key={i} className="vault-mark__light" x={x} y={y} width={width} height={height} style={{ "--i": i } as CSSProperties} />)}
        </g>
      )}
      {size >= 24 && <rect className="vault-mark__core" x={NEURON_CORE[0]} y={NEURON_CORE[1]} width={NEURON_CORE[2]} height={NEURON_CORE[3]} />}
    </svg>
  );
  return (
    <span {...a11y} data-variant={variant} data-state={state} data-name={wordmark ? (nameParts.clane ? "clane" : "text") : undefined} data-motion={still ? "reduce" : "full"}
      className={cn("vault-mark", still && "vault-mark--static", wordmark && "gap-[0.4em]", className)}
      style={wordmark ? { fontSize: textSize ?? Math.round(wordmarkUnit * 9 * 1.38) } : undefined}>
      {mark}
      {wordmark && (
        <span className="inline-flex items-center gap-[0.32em] pl-[0.12em] leading-none">
          {nameParts.clane && <Wordmark unit={wordmarkUnit} />}
          {nameParts.rest && <span className="font-display font-semibold tracking-[-0.02em] text-[var(--vm-text)]">{nameParts.rest}</span>}
        </span>
      )}
    </span>
  );
}
