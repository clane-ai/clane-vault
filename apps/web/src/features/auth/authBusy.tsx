import { createContext, useContext, useEffect } from "react";

/** Lets a form inside AuthLayout say it's busy (key derivation, sign-in), so the logo can switch to its working motion. */
export const AuthBusyContext = createContext<(busy: boolean) => void>(() => undefined);

export function useReportBusy(busy: boolean) {
  const report = useContext(AuthBusyContext);
  useEffect(() => { report(busy); return () => report(false); }, [busy, report]);
}

/** Drop inside AuthLayout's children: <ReportBusy busy={busy} />. */
export function ReportBusy({ busy }: { busy: boolean }) {
  useReportBusy(busy);
  return null;
}
