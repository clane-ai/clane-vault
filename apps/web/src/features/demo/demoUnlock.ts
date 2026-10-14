import { useEffect, useRef, useState } from "react";
import { demoPassword } from "./startDemo";
import { clockTime } from "@/lib/time";

/** The sandbox's end, in the same time format as the rest of the app. */
export const deletedAt = (iso: string) => clockTime(iso);

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
