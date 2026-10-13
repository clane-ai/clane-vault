import { useCallback, useEffect, useState } from "react";
import { Link2, LockKeyhole, Pause, Play, Users } from "lucide-react";
import { cn } from "@/lib/utils";
import { productName } from "@/brand";
import { withBase } from "@/lib/base";

export const SLIDES = [
  {
    key: "vault", icon: LockKeyhole, product: "Vault",
    title: "Your team's passwords, one place",
    text: "Folders for every team, with each record's details a click away.",
    src: withBase("/showcase/vault.webp"), alt: `The ${productName} app: a list of records in folders, with the AWS root account record open beside it.`,
  },
  {
    key: "share", icon: Users, product: "Sharing",
    title: "Share with exactly the right people",
    text: "Give each person edit or view access, and take it back in one click.",
    src: withBase("/showcase/share.webp"), alt: "The Share panel for a record, listing three people with owner, edit and view access.",
  },
  {
    key: "link", icon: Link2, product: "One-time links",
    title: "Send a password to a client, once",
    text: "A link that opens once, then expires. The key never reaches our server.",
    src: withBase("/showcase/link.webp"), alt: "A one-time link ready to copy and send for the Customer portal record.",
  },
] as const;

export const SLIDE_MS = 6000;

function prefersReducedMotion() {
  return typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** The navy product showcase on the right of the sign-in screens: an auto-rotating, pausable carousel of app screenshots. */
export function Showcase() {
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(() => !prefersReducedMotion());
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  // Announce slide changes only when the person moved the carousel themselves; autoplay stays quiet.
  const [userMoved, setUserMoved] = useState(false);

  useEffect(() => {
    if (!playing || hovered || focused) return;
    const t = window.setTimeout(() => setIndex((i) => (i + 1) % SLIDES.length), SLIDE_MS);
    return () => window.clearTimeout(t);
  }, [index, playing, hovered, focused]);

  const go = useCallback((i: number) => { setUserMoved(true); setIndex(i); }, []);

  return (
    <section
      aria-roledescription="carousel" aria-label={`What's in ${productName}`}
      className="flex h-full flex-col gap-6 px-10 py-10 xl:px-14"
      onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
      onFocus={() => setFocused(true)} onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocused(false); }}
    >
      <div className="flex flex-col gap-5">
        <div className="flex items-center justify-between gap-4">
          <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--text-dark-secondary)]">{productName}</span>
          <button
            type="button" onClick={() => { go(0); setPlaying(!prefersReducedMotion()); }}
            className="rounded-full border border-[var(--border-dark-3)] px-4 py-1.5 text-[13px] font-medium text-[var(--text-on-dark)] transition-colors hover:border-white/40 hover:bg-white/6 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-[var(--blue-500)]/50"
          >
            What's new
          </button>
        </div>
        <hr className="border-0 border-t border-[var(--border-dark-2)]" />
      </div>

      <div className="flex min-h-0 flex-1 flex-col justify-center">
        <div aria-live={userMoved ? "polite" : "off"} className="grid">
          {SLIDES.map((s, i) => {
            const active = i === index;
            const Icon = s.icon;
            return (
              <div
                key={s.key} role="group" aria-roledescription="slide" aria-label={`${i + 1} of ${SLIDES.length}: ${s.title}`}
                aria-hidden={!active} inert={!active}
                className={cn("col-start-1 row-start-1 flex flex-col gap-7 transition-opacity duration-500 ease-out motion-reduce:transition-none", active ? "opacity-100" : "pointer-events-none opacity-0")}
              >
                <div className="mx-auto w-full max-w-[680px] overflow-hidden rounded-[12px] border border-white/10 bg-[var(--navy-850)] shadow-[0_24px_60px_-20px_rgba(0,0,0,.65),0_2px_6px_rgba(0,0,0,.25)]">
                  <img src={s.src} alt={s.alt} width={1280} height={800} loading={i === 0 ? "eager" : "lazy"} decoding="async" className="block h-auto w-full" />
                </div>
                <div className="mx-auto flex w-full max-w-[680px] flex-col gap-2.5">
                  <span className="inline-flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.12em] text-[var(--orange-500)]">
                    <Icon aria-hidden="true" className="size-3.5" />{s.product}
                  </span>
                  <h2 className="font-display text-[26px] font-semibold leading-[1.15] tracking-[-0.02em] text-[var(--text-on-dark)]">{s.title}</h2>
                  <p className="text-[15px] leading-relaxed text-[var(--text-dark-secondary)]">{s.text}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mx-auto flex w-full max-w-[680px] items-center gap-3">
        <div className="flex items-center gap-2">
          {SLIDES.map((s, i) => (
            <button
              key={s.key} type="button" onClick={() => go(i)}
              aria-label={`Show slide ${i + 1} of ${SLIDES.length}: ${s.title}`} aria-current={i === index ? "true" : undefined}
              className="grid h-6 place-items-center rounded-full px-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--blue-500)]/60"
            >
              <span className={cn("block h-2 rounded-full transition-all duration-300 motion-reduce:transition-none", i === index ? "w-6 bg-[var(--text-on-dark)]" : "w-2 bg-white/25 hover:bg-white/45")} />
            </button>
          ))}
        </div>
        <button
          type="button" onClick={() => setPlaying(!playing)} aria-label={playing ? "Pause slideshow" : "Play slideshow"}
          className="ml-auto grid size-8 place-items-center rounded-full text-[var(--text-dark-tertiary)] transition-colors hover:bg-white/6 hover:text-[var(--text-on-dark)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--blue-500)]/60"
        >
          {playing ? <Pause aria-hidden="true" className="size-3.5" /> : <Play aria-hidden="true" className="size-3.5" />}
        </button>
      </div>
    </section>
  );
}
