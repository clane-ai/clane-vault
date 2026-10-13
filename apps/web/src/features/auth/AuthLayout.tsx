import { useState, type ReactNode } from "react";
import { Logo } from "@/components/brand/Logo";
import { VendorCredit } from "@/components/brand/VendorCredit";
import { useBrand } from "@/brand";
import { AuthBusyContext } from "./authBusy";
import { Showcase } from "./Showcase";


/**
 * Split auth screen: the form on the left (follows the theme), the navy product showcase on the right (always navy,
 * hidden below 1024px). A short `title` sits on the logo row (like "Sign in"); a longer one goes below it with the subtitle.
 */
export function AuthLayout({ title, subtitle, titleInHeader = false, children }: {
  title: string; subtitle?: string; titleInHeader?: boolean; children: ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const { productName, instanceLogoUrl } = useBrand();
  const [logoFailed, setLogoFailed] = useState<string | null>(null);
  return (
    <AuthBusyContext value={setBusy}>
    <div className="grid min-h-dvh bg-card lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <main className="flex min-h-dvh flex-col bg-card px-4 sm:px-8">
        <div className="mx-auto flex w-full max-w-[420px] flex-1 flex-col justify-center gap-9 py-12">
          <div className="flex items-center justify-between gap-4">
            {instanceLogoUrl && logoFailed !== instanceLogoUrl ? (
              // The instance logo an admin uploaded (docs/branding.md), with the product name beside it.
              <span className="flex min-w-0 items-center gap-2.5" role="img" aria-label={productName} data-testid="instance-logo">
                <img src={instanceLogoUrl} alt="" className="h-9 max-w-[160px] shrink-0 object-contain" onError={() => setLogoFailed(instanceLogoUrl)} />
                <span aria-hidden="true" className="truncate font-display text-[20px] font-semibold tracking-[-0.02em] text-text-primary">{productName}</span>
              </span>
            ) : <Logo size="md" state={busy ? "working" : "idle"} />}
            {titleInHeader && <h1 className="font-display text-[20px] font-semibold tracking-[-0.01em] text-text-primary">{title}</h1>}
          </div>
          <div className="flex flex-col gap-6">
            {!titleInHeader && (
              <div className="flex flex-col gap-1.5">
                <h1 className="font-display text-[24px] font-semibold leading-tight tracking-[-0.01em] text-text-primary">{title}</h1>
                {subtitle && <p className="text-[14px] leading-relaxed text-text-secondary">{subtitle}</p>}
              </div>
            )}
            {titleInHeader && subtitle && <p className="-mt-3 text-[14px] leading-relaxed text-text-secondary">{subtitle}</p>}
            {children}
          </div>
        </div>
        <p className="mx-auto flex w-full max-w-[420px] items-start gap-2 pb-2 font-mono text-[11.5px] leading-relaxed text-text-tertiary">
          <span aria-hidden="true" className="mt-[5px] size-1.5 shrink-0 rounded-full bg-green-600" />
          <span><span className="inline-block">End-to-end encrypted ·</span> <span className="inline-block">your master password never leaves this device</span></span>
        </p>
        <p className="mx-auto w-full max-w-[420px] pb-5 font-mono text-[11px] text-text-tertiary">
          {productName} · <VendorCredit className="text-text-tertiary hover:text-text-secondary" />
        </p>
      </main>
      <aside aria-label={`About ${productName}`} className="hidden border-l border-[var(--border-dark-2)] bg-[image:var(--grad-hero)] bg-[var(--navy-900)] lg:sticky lg:top-0 lg:block lg:h-dvh">
        <Showcase />
      </aside>
    </div>
    </AuthBusyContext>
  );
}
