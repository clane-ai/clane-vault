import { useEffect, useRef, useState } from "react";
import { demoPassword } from "./startDemo";

/** The sandbox's end, as HH:MM in the visitor's time zone. */
export const deletedAt = (iso: string) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

/**
 * A demo sandbox locks like any vault (a reload, the idle timer), but its visitor never saw the master password: this tab
 * kept it (startDemo.ts), so the vault opens again by itself. Returns whether it's doing that.
 */
export function useDemoUnlock(user: { id: string; demoExpiresAt?: string } | null, unlock: (pw: string) => Promise<void>, offline: boolean): boolean {
  const pw = user?.demoExpiresAt && !offline ? demoPassword(user.id) : null;
  const tried = useRef(false);
  const [busy, setBusy] = useState(!!pw);
  useEffect(() => {
    if (!pw || tried.current) return;
    tried.current = true;
    unlock(pw).catch(() => setBusy(false));
  }, [pw, unlock]);
  return busy;
}
