import { useRef, useState, type ElementType, type FormEvent } from "react";
import { ArrowDown, ArrowUp, Dices, Eye, EyeOff, Plus, Trash2, X } from "lucide-react";
import {
  base32Decode, expiryValid, generatePassword, luhnValid, MAX_CUSTOM_FIELDS, MAX_FIELD_LABEL, templateOf, typeLabel,
  FIELD_KINDS, type CustomField, type FieldKind, type RecordBody, type RecordType, type TemplateField,
} from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SheetBody, SheetFooter, SheetHeader } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { emptyField, groupCardNumber, KIND_LABEL, lowerFirst, PLACEHOLDER } from "./recordKinds";
import { canFileInto, type VaultFolder } from "./types";

const NO_FOLDER = "__none__";
const NO_OPTION = "__none__";
const MONO = "font-mono text-[13.5px]";

function Field({ id, label, hint, children }: { id: string; label: string; hint?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id} className="text-[13px] text-text-primary">{label}</Label>
      {children}
      {hint && <p className="text-[12px] leading-snug text-text-tertiary">{hint}</p>}
    </div>
  );
}

const validTotp = (s: string) => { try { return base32Decode(s.replace(/\s/g, "")).length >= 10; } catch { return false; } };
const cleanTotp = (s: string) => s.replace(/\s/g, "").toUpperCase();

/** "1229" → "12/29": digits only, slash after the month. */
function formatExpiry(raw: string, prev: string): string {
  const d = raw.replace(/\D/g, "").slice(0, 4);
  // Deleting the slash deletes the month's last digit too, so backspace never gets stuck.
  if (raw.length < prev.length && prev.endsWith("/") && !raw.includes("/")) return d.slice(0, 1);
  return d.length >= 2 ? `${d.slice(0, 2)}/${d.slice(2)}` : d;
}

/** Eye button for masked inputs. */
function RevealButton({ label, revealed, onToggle }: { label: string; revealed: boolean; onToggle: () => void }) {
  const l = lowerFirst(label);
  return (
    <Button type="button" variant="ghost" size="icon" aria-label={revealed ? `Hide ${l}` : `Show ${l}`} onClick={onToggle}>
      {revealed ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
    </Button>
  );
}

/**
 * The input for one value, by kind and format: masked secrets with reveal, card numbers in groups of four, MM/YY,
 * ports, dates, lists, multi-line text and hidden multi-line keys.
 */
function ValueInput({ id, label, kind, format, options, mono, placeholder, value, onChange, revealed, onReveal, onGenerate, autoFocus }: {
  id: string; label: string; kind: FieldKind; format?: TemplateField["format"]; options?: TemplateField["options"]; mono?: boolean; placeholder?: string;
  value: string; onChange: (v: string) => void; revealed: boolean; onReveal: () => void; onGenerate?: () => void; autoFocus?: boolean;
}) {
  const font = mono ? MONO : undefined;
  if (options) return (
    <Select value={value || NO_OPTION} onValueChange={(v) => onChange(v === NO_OPTION ? "" : v)}>
      <SelectTrigger id={id} className="w-full" autoFocus={autoFocus}><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value={NO_OPTION}><span className="text-text-tertiary">Not set</span></SelectItem>
        {options.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
        {value && !options.some((o) => o.value === value) && <SelectItem value={value}>{value}</SelectItem>}
      </SelectContent>
    </Select>
  );
  if (kind === "multiline" || kind === "hiddenMultiline") {
    const hidden = kind === "hiddenMultiline" && !revealed;
    return (
      <div className="relative">
        <Textarea id={id} autoFocus={autoFocus} rows={kind === "hiddenMultiline" ? 4 : 3} value={value} placeholder={placeholder} spellCheck={false} autoComplete="off"
          onChange={(e) => onChange(e.target.value)} data-masked={hidden || undefined}
          className={cn(font, kind === "hiddenMultiline" && "pr-11", hidden && "[-webkit-text-security:disc]")} />
        {kind === "hiddenMultiline" && <span className="absolute top-1 right-1"><RevealButton label={label} revealed={revealed} onToggle={onReveal} /></span>}
      </div>
    );
  }
  if (format === "cardNumber") {
    return (
      <div className="relative">
        <Input id={id} autoFocus={autoFocus} inputMode="numeric" autoComplete="off" type={revealed ? "text" : "password"} value={groupCardNumber(value)} placeholder={placeholder}
          onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 19))} className={cn(font, "pr-11")} />
        <span className="absolute inset-y-0 right-1 flex items-center"><RevealButton label={label} revealed={revealed} onToggle={onReveal} /></span>
      </div>
    );
  }
  if (format === "expiry") return <Input id={id} autoFocus={autoFocus} inputMode="numeric" autoComplete="off" maxLength={5} value={value} placeholder={placeholder} onChange={(e) => onChange(formatExpiry(e.target.value, value))} className={font} />;
  if (format === "port") return <Input id={id} autoFocus={autoFocus} inputMode="numeric" autoComplete="off" maxLength={5} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value.replace(/\D/g, ""))} className={cn(font, "max-w-[120px]")} />;
  if (kind === "secret") {
    return (
      <div className="relative">
        <Input id={id} autoFocus={autoFocus} type={revealed ? "text" : "password"} autoComplete="new-password" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
          className={cn(font, onGenerate ? "pr-[76px]" : "pr-11")} />
        <span className="absolute inset-y-0 right-1 flex items-center gap-0.5">
          <RevealButton label={label} revealed={revealed} onToggle={onReveal} />
          {onGenerate && <Button type="button" variant="ghost" size="icon" aria-label={`Generate ${lowerFirst(label)}`} title={`Generate ${lowerFirst(label)}`} onClick={onGenerate}><Dices className="size-4" /></Button>}
        </span>
      </div>
    );
  }
  const type = kind === "date" ? "date" : kind === "email" ? "email" : kind === "phone" ? "tel" : "text";
  return <Input id={id} autoFocus={autoFocus} type={type} autoComplete="off" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
    inputMode={kind === "url" ? "url" : undefined} className={cn(font, kind === "totp" && MONO)} />;
}

/** Card number hint: the check digit catches most typos (a hint only: some cards and test numbers don't follow it). */
function cardHint(v: string) {
  const d = v.replace(/\D/g, "");
  if (d.length < 12) return undefined;
  return luhnValid(d) ? undefined : <span className="text-amber-700 dark:text-amber-500">This number doesn't pass the card check. Check it for typos.</span>;
}

export function RecordEditor({ mode, type, initial, folderId, folders, canMove: canMoveProp = true, noFolder = true, onSave, onCancel, TitleAs = "h2", files }: {
  mode: "create" | "edit"; type: RecordType; initial?: RecordBody; folderId: string | null; folders: VaultFolder[];
  /** "No folder" is a place (Personal); in an organisation records stay in its shared folders. */ noFolder?: boolean;
  /** Only the record owner can move it between folders. */ canMove?: boolean;
  onSave: (body: RecordBody, folderId: string | null) => Promise<void>; onCancel: () => void;
  /** Heading element for the title (a SheetTitle inside a sheet). */
  TitleAs?: ElementType;
  /** The Files part at the bottom (features/attachments): uploads for an existing record, a queue for a new one. */
  files?: React.ReactNode;
}) {
  const template = templateOf(type);
  const [title, setTitle] = useState(initial?.title ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  // Template values by key (core fields and data alike).
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(template.map((f) => [f.key,
    (f.core ? (initial as unknown as Record<string, string | undefined> | undefined)?.[f.key] : initial?.data?.[f.key]) ?? ""])));
  const [fields, setFields] = useState<CustomField[]>(() => initial?.fields?.map((f) => ({ ...f })) ?? []);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [folder, setFolder] = useState<string | null>(folderId);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const labelRefs = useRef(new Map<string, HTMLInputElement>());
  const focusNext = useRef<string | null>(null);
  const setValue = (k: string) => (v: string) => setValues((x) => ({ ...x, [k]: v }));
  const toggle = (k: string) => () => setRevealed((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  const setField = (id: string, p: Partial<CustomField>) => setFields((fs) => fs.map((f) => (f.id === id ? { ...f, ...p } : f)));
  const move = (i: number, d: -1 | 1) => setFields((fs) => { const n = [...fs]; const [x] = n.splice(i, 1); n.splice(i + d, 0, x!); return n; });

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!title.trim()) return setError("Give it a title.");
    for (const f of template) {
      const v = values[f.key]!.trim();
      if (!v) continue;
      if (f.kind === "totp" && !validTotp(v)) return setError("That 2FA secret isn't valid. Copy the setup key from the website.");
      if (f.format === "expiry" && !expiryValid(v)) return setError(`${f.label}: use MM/YY, for example 08/29.`);
      if (f.format === "port" && !(Number(v) >= 1 && Number(v) <= 65535)) return setError(`${f.label}: use a number from 1 to 65535.`);
    }
    const custom = fields.filter((f) => f.label.trim() || f.value !== "");
    for (const f of custom) {
      if (!f.label.trim()) return setError("Give every custom field a label.");
      if (f.label.trim().length > MAX_FIELD_LABEL) return setError(`Custom field labels are at most ${MAX_FIELD_LABEL} characters.`);
      if (f.kind === "totp" && f.value.trim() && !validTotp(f.value)) return setError(`${f.label.trim()}: that 2FA secret isn't valid.`);
    }
    const body: RecordBody = { type, title: title.trim() };
    const data: Record<string, string> = {};
    for (const f of template) {
      let v = values[f.key]!;
      if (f.kind === "totp") v = cleanTotp(v);
      else if (f.kind !== "secret" && f.kind !== "multiline" && f.kind !== "hiddenMultiline") v = v.trim();
      if (!v) continue;
      if (f.core) (body as unknown as Record<string, string>)[f.key] = v; else data[f.key] = v;
    }
    // Password health's "old" check: when the password itself last changed (kept as is otherwise).
    if (body.password) {
      const changedAt = body.password !== (initial?.password ?? "") ? new Date().toISOString() : initial?.passwordChangedAt;
      if (changedAt) body.passwordChangedAt = changedAt;
    }
    if (notes) body.notes = notes;
    if (Object.keys(data).length) body.data = data;
    const kept = custom.filter((f) => f.value !== "").map((f) => ({ id: f.id, label: f.label.trim(), kind: f.kind, value: f.kind === "totp" ? cleanTotp(f.value) : f.value }));
    if (kept.length) body.fields = kept;
    setBusy(true); setError(null);
    try { await onSave(body, folder); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }

  // My private folders and team folders I can add to; the current folder always stays listed.
  const live = folders.filter((x) => canFileInto(x) || (x.id === folderId && !x.deleted));
  // In an organisation, a record outside its shared folders is a personal record shared here directly: it stays put.
  const elsewhere = !noFolder && mode === "edit" && !live.some((x) => x.id === folderId);
  const canMove = canMoveProp && !elsewhere;
  // A new record arrives from New Record with its title: start at the next field.
  const [focusTitle] = useState(() => !(mode === "create" && initial?.title));
  const heading = mode === "create" ? `New ${lowerFirst(typeLabel(type))}` : "Edit record";
  return (
    <form onSubmit={submit} className="flex h-full min-h-0 flex-col" noValidate>
      <SheetHeader>
        <TitleAs className="font-display text-[18px] font-semibold tracking-[-0.02em] text-text-primary">{heading}</TitleAs>
        <Button type="button" variant="ghost" size="icon" aria-label="Close" className="-mr-2" onClick={onCancel}><X className="size-4" /></Button>
      </SheetHeader>
      <SheetBody>
        <Field id="ed-title" label="Title"><Input id="ed-title" value={title} onChange={(e) => setTitle(e.target.value)} autoFocus={focusTitle} placeholder={type === "login" ? "e.g. AWS root account" : `e.g. ${PLACEHOLDER[type]}`} /></Field>
        {template.map((f, i) => {
          const id = `ed-${f.key}`;
          const totp = f.kind === "totp" && f.core;
          return (
            <Field key={f.key} id={id} label={totp ? `${f.label} (optional)` : f.label}
              hint={totp ? "The setup key the website shows when you turn on two-factor sign-in." : f.format === "cardNumber" ? cardHint(values[f.key]!) : undefined}>
              <ValueInput id={id} label={f.label} kind={f.kind} format={f.format} options={f.options} mono={f.mono} placeholder={f.placeholder}
                value={values[f.key]!} onChange={setValue(f.key)} revealed={revealed.has(f.key)} onReveal={toggle(f.key)} autoFocus={!focusTitle && i === 0}
                onGenerate={f.core && f.key === "password" ? () => setValue("password")(generatePassword()) : undefined} />
            </Field>
          );
        })}
        <Field id="ed-notes" label="Notes"><Textarea id="ed-notes" autoFocus={!focusTitle && template.length === 0} rows={type === "note" ? 8 : 3} value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>

        <section aria-label="Custom fields" className="flex flex-col gap-2.5">
          {fields.length > 0 && <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Custom fields</h3>}
          {fields.map((f, i) => {
            const n = i + 1;
            return (
              <div key={f.id} data-testid="custom-field" className="flex flex-col gap-2 rounded-[10px] border border-border-default bg-app p-2.5">
                <div className="flex items-center gap-1.5">
                  <Input aria-label={`Field ${n} label`} placeholder="Label" value={f.label} maxLength={MAX_FIELD_LABEL} className="h-8 min-w-0 flex-1 text-[13px]"
                    ref={(el) => { if (el) { labelRefs.current.set(f.id, el); if (focusNext.current === f.id) { focusNext.current = null; el.focus(); } } else labelRefs.current.delete(f.id); }}
                    onChange={(e) => setField(f.id, { label: e.target.value })} />
                  <Select value={f.kind} onValueChange={(k) => setField(f.id, { kind: k as FieldKind })}>
                    <SelectTrigger aria-label={`Field ${n} type`} className="h-8 w-[132px] shrink-0 text-[12.5px] data-[size=default]:h-8"><SelectValue /></SelectTrigger>
                    <SelectContent align="end">{FIELD_KINDS.map((k) => <SelectItem key={k} value={k}>{KIND_LABEL[k]}</SelectItem>)}</SelectContent>
                  </Select>
                  <Button type="button" variant="ghost" size="icon" className="size-8" aria-label={`Move field ${n} up`} disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp className="size-3.5" /></Button>
                  <Button type="button" variant="ghost" size="icon" className="size-8" aria-label={`Move field ${n} down`} disabled={i === fields.length - 1} onClick={() => move(i, 1)}><ArrowDown className="size-3.5" /></Button>
                  <Button type="button" variant="ghost" size="icon" className="size-8 hover:bg-red-tint hover:text-red-500" aria-label={`Remove field ${n}`} onClick={() => setFields((fs) => fs.filter((x) => x.id !== f.id))}><Trash2 className="size-3.5" /></Button>
                </div>
                <ValueInput id={`ed-cf-${f.id}`} label={f.label.trim() || `field ${n}`} kind={f.kind} mono={f.kind === "secret" || f.kind === "hiddenMultiline" || f.kind === "totp"}
                  placeholder={f.kind === "totp" ? "2FA setup key" : "Value"} value={f.value} onChange={(v) => setField(f.id, { value: v })}
                  revealed={revealed.has(`cf:${f.id}`)} onReveal={toggle(`cf:${f.id}`)} />
              </div>
            );
          })}
          <Button type="button" variant="outline" size="sm" className="self-start" disabled={fields.length >= MAX_CUSTOM_FIELDS}
            onClick={() => { const f = emptyField(); focusNext.current = f.id; setFields((fs) => [...fs, f]); }}>
            <Plus className="size-3.5" />Add field
          </Button>
        </section>

        <Field id="ed-folder" label="Folder">
          <Select value={elsewhere ? NO_FOLDER : folder ?? NO_FOLDER} onValueChange={(v) => setFolder(v === NO_FOLDER ? null : v)} disabled={!canMove}>
            <SelectTrigger id="ed-folder" className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              {(noFolder || elsewhere) && <SelectItem value={NO_FOLDER}>{elsewhere ? "Shared directly" : "No folder"}</SelectItem>}
              {(noFolder || elsewhere) && live.length > 0 && <SelectSeparator />}
              {live.map((x) => <SelectItem key={x.id} value={x.id}>{x.name}{x.kind === "team" ? " · Team" : ""}</SelectItem>)}
            </SelectContent>
          </Select>
        </Field>
        {files}
        {error && <p role="alert" className="rounded-[9px] border border-[var(--red-tint-border)] bg-red-tint px-3 py-2 text-[13px] text-red-500">{error}</p>}
      </SheetBody>
      <SheetFooter>
        <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button type="submit" disabled={busy} className="min-w-20">{busy ? "Saving…" : "Save"}</Button>
      </SheetFooter>
    </form>
  );
}
