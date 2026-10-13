import { createContext, useContext } from "react";
import { Link, NavLink } from "react-router";
import { ChevronLeft, ChevronRight, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/** Where a page's Back goes (phones: a section page goes back to its section list; detail pages to their list). */
const BackContext = createContext<{ to: string; label: string } | null>(null);
export const BackProvider = BackContext.Provider;

/**
 * A page's top bar: its title (h1), optional actions and, when the page sits under a list (phones, detail pages), a
 * Back link. Every page in the app's main area uses it, so they all line up.
 */
export function PageHeader({ title, sub, back: own, children }: { title: React.ReactNode; sub?: React.ReactNode; back?: { to: string; label: string } | null; children?: React.ReactNode }) {
  const ctx = useContext(BackContext);
  const back = own === undefined ? ctx : own;
  return (
    <header className="flex h-[60px] shrink-0 items-center gap-3 border-b border-border-default bg-[var(--surface-overlay)] px-6 backdrop-blur-[8px] max-[760px]:gap-2 max-[760px]:px-3">
      {back && (
        <Link to={back.to} aria-label={`Back to ${back.label}`} title={`Back to ${back.label}`}
          className="-ml-2 grid size-9 shrink-0 place-items-center rounded-[9px] text-text-secondary hover:bg-well hover:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40">
          <ChevronLeft className="size-5" />
        </Link>
      )}
      <h1 className="min-w-0 flex-1 truncate text-[22px] leading-tight text-text-primary">{title}</h1>
      {sub && <span className="min-w-0 shrink truncate font-mono text-[12px] text-text-tertiary">{sub}</span>}
      {children}
    </header>
  );
}

/**
 * A page of cards under a PageHeader that scrolls on its own. The first section's own heading usually repeats the page
 * title, so it is kept for screen readers only (unless `keepHeadings`).
 */
export function SectionPage({ title, sub, actions, wide, keepHeadings, children, label }: {
  title: string; sub?: React.ReactNode; actions?: React.ReactNode; wide?: boolean;
  /** Keep the first section's heading visible (pages made of several titled sections). */ keepHeadings?: boolean; label?: string; children: React.ReactNode;
}) {
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label={label ?? title}>
      <PageHeader title={title} sub={sub}>{actions}</PageHeader>
      <div className="relative min-h-0 flex-1 overflow-y-auto px-6 py-5 max-[760px]:px-3">
        <div className={cn("mx-auto flex flex-col gap-8", wide ? "max-w-[960px]" : "max-w-[760px]",
          !keepHeadings && "[&>section:first-child>h2:first-child]:sr-only [&>section:first-child>div:first-child>h2:first-child]:sr-only")}>{children}</div>
      </div>
    </section>
  );
}

export interface NavItem { id: string; label: string; icon: LucideIcon; to: string; badge?: number; dot?: boolean }
export interface NavGroup { label: string; items: NavItem[] }

const groupLabel = "px-3 pt-1 pb-1.5 font-mono text-[10.5px] tracking-[.12em] text-text-tertiary uppercase";

function Badge({ item }: { item: NavItem }) {
  if (item.badge) return <span className="ml-auto rounded-[6px] bg-amber-500/20 px-1.5 py-px font-mono text-[11px] text-orange-ink tabular-nums">{item.badge}</span>;
  if (item.dot) return <span className="ml-auto size-2 rounded-full bg-amber-500" aria-label="Needs attention" />;
  return null;
}

/** The left sub-navigation of Settings and Admin: grouped links, the current one marked. */
function SubNav({ title, groups, active }: { title: string; groups: NavGroup[]; active: string | null }) {
  return (
    <nav aria-label={`${title} sections`} className="flex w-[236px] shrink-0 flex-col overflow-y-auto border-r border-border-default bg-card/60">
      <div className="flex h-[60px] shrink-0 items-center border-b border-border-default px-5">
        <p className="font-display text-[17px] font-semibold tracking-[-0.01em] text-text-primary">{title}</p>
      </div>
      <div className="flex flex-col px-2 py-3">
        {groups.map((g, i) => (
          <div key={g.label} role="group" aria-label={g.label} className={cn("flex flex-col gap-0.5", i > 0 && "mt-4")}>
            <p className={groupLabel} aria-hidden="true">{g.label}</p>
            {g.items.map((it) => {
              const on = active === it.id;
              return (
                <NavLink key={it.id} to={it.to} aria-current={on ? "page" : undefined}
                  className={cn("flex items-center gap-2.5 rounded-[8px] px-3 py-2 text-[13.5px] text-text-secondary transition-colors duration-100 hover:bg-well hover:text-text-primary",
                    on && "bg-well font-medium text-text-primary")}>
                  <it.icon className={cn("size-4 shrink-0", on ? "text-blue-500" : "text-text-tertiary")} />
                  <span className="min-w-0 flex-1 truncate">{it.label}</span><Badge item={it} />
                </NavLink>
              );
            })}
          </div>
        ))}
      </div>
    </nav>
  );
}

/** Phones: the sub-navigation as a page of its own (a list of sections); each section page has Back to it. */
function SectionList({ title, groups }: { title: string; groups: NavGroup[] }) {
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label={title}>
      <PageHeader title={title} back={null} />
      <nav aria-label={`${title} sections`} className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
        {groups.map((g) => (
          <div key={g.label} role="group" aria-label={g.label} className="mb-4">
            <p className="px-1 pb-1.5 font-mono text-[10.5px] tracking-[.12em] text-text-tertiary uppercase" aria-hidden="true">{g.label}</p>
            <ul className="overflow-hidden rounded-[14px] border border-border-default bg-card shadow-[var(--shadow-card)]">
              {g.items.map((it) => (
                <li key={it.id} className="border-b border-border-default last:border-b-0">
                  <Link to={it.to} className="flex min-h-12 items-center gap-3 px-4 py-3 text-[14.5px] text-text-primary active:bg-well">
                    <it.icon className="size-[18px] shrink-0 text-text-tertiary" />
                    <span className="min-w-0 flex-1 truncate">{it.label}</span><Badge item={it} />
                    <ChevronRight className="size-4 shrink-0 text-text-tertiary" />
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </section>
  );
}

/**
 * Settings and Admin: a sub-navigation beside the section's page. On phones the sub-navigation is its own list page
 * (`active` null) and a section page gets Back to it. `back`: a detail page's own Back (member → People).
 */
export function SectionLayout({ title, base, groups, active, mobile, back, children }: {
  title: string; base: string; groups: NavGroup[]; active: string | null; mobile: boolean; back?: { to: string; label: string }; children?: React.ReactNode;
}) {
  if (mobile) {
    if (active === null) return <SectionList title={title} groups={groups} />;
    return <BackProvider value={back ?? { to: base, label: title }}><div className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</div></BackProvider>;
  }
  return (
    <div className="flex min-h-0 min-w-0 flex-1">
      <SubNav title={title} groups={groups} active={active} />
      <BackProvider value={back ?? null}><div className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</div></BackProvider>
    </div>
  );
}
