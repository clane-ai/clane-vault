import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Palette } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { VaultMark } from "@/components/brand/VaultMark";
import { api, ApiError } from "@/lib/api";
import { applyBrand, buildBrand, useBrand, type ServerBrand } from "@/brand";
import { cn } from "@/lib/utils";
import { LogoField } from "./LogoField";

const card = "rounded-[14px] border border-border-default bg-card p-4 shadow-[var(--shadow-card)]";
const KEY = ["instance-brand"];
export const BRAND_NAME_MAX = 40;

/** Why a name won't be accepted, or null (the server checks the same: 1–40 characters, no markup). */
export function brandNameProblem(v: string): string | null {
  const s = v.trim();
  if (!s) return "Give it a name.";
  if (s.length > BRAND_NAME_MAX) return `Use at most ${BRAND_NAME_MAX} characters.`;
  if (/[<>]/.test(s)) return "Leave out < and >.";
  return null;
}

/**
 * Settings → Server → Branding (instance admins, docs/branding.md): the product name and short name everyone sees
 * (sign-in page, page title, emails), overriding the build's, and an optional logo for the sign-in page.
 */
export function BrandingSection() {
  const qc = useQueryClient();
  const live = useBrand();
  const q = useQuery({ queryKey: KEY, queryFn: () => api.get<ServerBrand>("/admin/instance/brand") });
  const [name, setName] = useState("");
  const [short, setShort] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!q.data) return;
    setName(q.data.productName ?? ""); setShort(q.data.shortName ?? "");
  }, [q.data]);
  const done = (b: ServerBrand) => { qc.setQueryData(KEY, b); applyBrand(b); };
  const save = useMutation({
    mutationFn: (b: { productName: string | null; shortName: string | null }) => api.put<ServerBrand>("/admin/instance/brand", b),
    onSuccess: (b) => { done(b); toast.success(b.productName || b.shortName ? "Branding saved" : "Back to the default names"); },
    onError: (e) => setError(e instanceof ApiError && e.code === "invalid_request" ? `Use 1–${BRAND_NAME_MAX} characters, without < or >.` : "Couldn't save. Try again."),
  });

  function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    const p = name.trim() ? brandNameProblem(name) : null, s = short.trim() ? brandNameProblem(short) : null;
    if (p || s) return setError(p ?? s);
    save.mutate({ productName: name.trim() || null, shortName: short.trim() || null });
  }

  return (
    <section className="flex flex-col gap-3" aria-label="Branding">
      <h2 className="font-display text-[15px] font-semibold tracking-[-0.01em] text-text-primary">Branding</h2>
      <div className={cn(card, "flex flex-col gap-4")}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-[10px] bg-well text-text-tertiary"><Palette className="size-4" /></span>
          <p className="min-w-0 flex-1 text-[13px] leading-relaxed text-text-secondary">
            The product name on the sign-in page, in the page title, the app and the emails this server sends. Leave a field empty to use the default
            (<span className="font-medium text-text-primary">{buildBrand.productName}</span> / <span className="font-medium text-text-primary">{buildBrand.shortName}</span>).
          </p>
        </div>
        <form onSubmit={submit} className="flex flex-col gap-3" noValidate>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <div className="flex flex-col gap-1.5"><Label htmlFor="brand-name">Product name</Label>
              <Input id="brand-name" maxLength={BRAND_NAME_MAX} placeholder={buildBrand.productName} value={name} onChange={(e) => setName(e.target.value)} disabled={!q.data} /></div>
            <div className="flex flex-col gap-1.5"><Label htmlFor="brand-short">Short name</Label>
              <Input id="brand-short" maxLength={BRAND_NAME_MAX} placeholder={buildBrand.shortName} value={short} onChange={(e) => setShort(e.target.value)} disabled={!q.data} /></div>
          </div>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex flex-wrap items-center justify-end gap-2">
            {live.custom && <Button type="button" variant="ghost" disabled={save.isPending} onClick={() => { setError(null); save.mutate({ productName: null, shortName: null }); }}>Use defaults</Button>}
            <Button type="submit" disabled={!q.data || save.isPending}>{save.isPending ? "Saving…" : "Save names"}</Button>
          </div>
        </form>
        <div className="border-t border-border-default pt-4">
          <LogoField id="instance-logo" label="Sign-in page logo" url={live.instanceLogoUrl} fallback={<VaultMark size={27} decorative />}
            onUpload={async (f) => done(await api.upload<ServerBrand>("/admin/instance/brand/logo", f))}
            onRemove={async () => done((await api.del("/admin/instance/brand/logo")) as unknown as ServerBrand)} />
        </div>
      </div>
    </section>
  );
}
