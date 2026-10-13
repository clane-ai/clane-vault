import { VaultMark, type VaultMarkState } from "./VaultMark";

// Mark sizes are multiples of 9 and wordmark units whole pixels, so every cell lands on the pixel grid.
const SIZES = {
  sm: { mark: 27, unit: 2, text: 22 },
  md: { mark: 36, unit: 2, text: 24 },
  lg: { mark: 45, unit: 3, text: 34 },
} as const;

/** The product logo: the animated 2b mark plus the name (CLANE wordmark + "Vault" by default). */
export function Logo({ size = "md", showProduct = true, onDark = false, state = "idle", animated = true }: {
  size?: keyof typeof SIZES; showProduct?: boolean; onDark?: boolean; state?: VaultMarkState; animated?: boolean;
}) {
  const s = SIZES[size];
  return <VaultMark size={s.mark} wordmark={showProduct} wordmarkUnit={s.unit} textSize={s.text} variant={onDark ? "dark" : "auto"} state={state} animated={animated} />;
}
