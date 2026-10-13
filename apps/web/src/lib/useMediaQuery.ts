import { useEffect, useState } from "react";

/** Phones and narrow windows: the sidebar becomes a drawer behind a top bar. */
export const MOBILE = "(max-width: 760px)";

const match = (q: string) => typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia(q).matches;

export function useMediaQuery(q: string): boolean {
  const [m, setM] = useState(() => match(q));
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const l = window.matchMedia(q);
    const on = () => setM(l.matches);
    on();
    l.addEventListener?.("change", on);
    return () => l.removeEventListener?.("change", on);
  }, [q]);
  return m;
}
