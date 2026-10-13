import { cn } from "cn";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";

/** Clane buttons: primary is the orange CTA, secondary a bordered card button, ghost a quiet icon/text button. */
export function Button({ variant = "secondary", className, ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  return (
    <button type="button" {...p} className={cn(
      "inline-flex h-9 items-center justify-center gap-1.5 rounded-md px-3 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
      variant === "primary" && "bg-orange-500 text-navy-900 hover:brightness-105",
      variant === "secondary" && "border border-border-mid bg-card text-text-primary hover:bg-well",
      variant === "ghost" && "text-text-secondary hover:bg-well hover:text-text-primary",
      variant === "danger" && "border border-border-mid bg-card text-red-500 hover:bg-red-tint",
      className)} />
  );
}

export function IconButton({ label, className, ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return <button type="button" aria-label={label} title={label} {...p} className={cn("inline-flex size-8 items-center justify-center rounded-md text-text-secondary transition-colors hover:bg-well hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40", className)} />;
}

export function Field({ label, hint, className, ...p }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[12px] font-medium text-text-secondary">{label}</span>
      <input {...p} className={cn("h-9 rounded-lg border border-border-mid bg-card px-3 text-[13px] text-text-primary outline-none placeholder:text-text-tertiary focus:border-blue-500", className)} />
      {hint && <span className="text-[12px] text-text-tertiary">{hint}</span>}
    </label>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "error"; children: ReactNode }) {
  return (
    <div role={tone === "error" ? "alert" : "status"} className={cn("rounded-lg border px-3 py-2 text-[12px] leading-snug",
      tone === "info" && "border-border-default bg-blue-tint text-text-primary",
      tone === "warn" && "border-border-default bg-orange-tint text-orange-ink",
      tone === "error" && "border-border-default bg-red-tint text-red-500")}>{children}</div>
  );
}
