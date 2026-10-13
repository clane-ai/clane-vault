import { Puzzle } from "lucide-react";
import { useBrand } from "@/brand";
import { cn } from "@/lib/utils";
import { appUrl } from "@/lib/base";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";

/** Settings → Browser extension: where to get it and which server address to give it (docs/extension.md). */
export function ExtensionSection() {
  const { productName } = useBrand();
  return (
    <section id="settings-apps" className="flex scroll-mt-4 flex-col gap-3" aria-label="Browser extension">
      <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Browser extension</h2>
      <div className={cn(card, "flex items-start gap-3")}>
        <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Puzzle className="size-4" /></span>
        <div className="min-w-0 flex-1 text-[13px] leading-relaxed text-text-secondary">
          <p className="text-[14px] font-medium text-text-primary">Fill and save passwords in Chrome, Edge and Firefox</p>
          <p>
            Install the {productName} extension, then connect it to <span className="font-mono text-[12.5px] text-text-primary">{appUrl()}</span> and
            sign in with your master password and authenticator code. The setup guide is <span className="font-mono text-[12.5px]">docs/extension.md</span>.
          </p>
        </div>
      </div>
    </section>
  );
}
