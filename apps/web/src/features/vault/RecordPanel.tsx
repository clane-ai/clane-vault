import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ArrowLeft, Dices, Eye, EyeOff, Folder, Pencil, RotateCcw, Share2, Trash2, Users, X } from "lucide-react";
import { totpCode, totpSecondsLeft, typeLabel } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { relativeTime } from "@/lib/time";
import { OneTimeLinkButton } from "@/features/links/OneTimeLinkButton";
import type { StrengthScore } from "@/lib/strength";
import { reasonLine, strengthForScore, strengthOf, type AttentionReason } from "./attention";
import { CopyButton } from "./CopyButton";
import { RecordAvatar } from "./RecordAvatar";
import { displayValue, isSecretField, last4, lowerFirst, shownFields, TYPE_ICON, type ShownField } from "./recordKinds";
import { StrengthMeter } from "./StrengthMeter";
import type { VaultRecord } from "./types";

/** One row of the fields card: label (104px) · value · actions. */
function Row({ label, children, actions }: { label: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="grid min-h-[48px] grid-cols-[104px_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-border-default px-4 py-2 last:border-b-0 max-[760px]:grid-cols-[minmax(0,1fr)_auto] max-[760px]:gap-y-0.5 max-[760px]:py-2.5">
      <span className="text-[13px] text-text-secondary max-[760px]:col-span-2 max-[760px]:text-[12px]">{label}</span>
      <div className="min-w-0">{children}</div>
      <span className="-mr-2 flex items-center gap-0.5">{actions}</span>
    </div>
  );
}

export function TotpRow({ secret, label = "2FA code" }: { secret: string; label?: string }) {
  const [code, setCode] = useState("");
  const [left, setLeft] = useState(totpSecondsLeft());
  useEffect(() => {
    let alive = true;
    const tick = async () => { const c = await totpCode(secret).catch(() => ""); if (alive) { setCode(c); setLeft(totpSecondsLeft()); } };
    void tick(); const t = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(t); };
  }, [secret]);
  return (
    <Row label={label} actions={code && <CopyButton value={code} label={`Copy ${lowerFirst(label)}`} />}>
      <span className="flex items-center gap-2">
        <span aria-label={label} className="font-mono text-[15px] font-medium tracking-[.06em] text-text-primary">{code ? `${code.slice(0, 3)} ${code.slice(3)}` : "—"}</span>
        <span className={"rounded-[6px] px-1.5 py-px font-mono text-[11px] tabular-nums " + (left <= 5 ? "bg-red-tint text-red-500" : "bg-well text-text-secondary")} title="Seconds until the code changes">{left}s</span>
      </span>
    </Row>
  );
}

const MONO = "font-mono text-[13px] break-all text-text-primary";
/** A field's value: masked while hidden (a card keeps its last four digits), multi-line text kept as typed. */
function FieldValue({ f, shown }: { f: ShownField; shown: boolean }) {
  const multi = f.kind === "multiline" || f.kind === "hiddenMultiline";
  if (!shown) {
    const mask = f.format === "cardNumber" ? `•••• •••• •••• ${last4(f.value)}` : "•".repeat(14);
    return <span aria-label={f.label} className={MONO}>{mask}</span>;
  }
  const text = displayValue(f);
  if (multi) return <span aria-label={f.label} className={(f.mono || f.kind === "hiddenMultiline" ? "font-mono text-[12.5px]" : "text-[14px]") + " block max-h-[240px] overflow-y-auto whitespace-pre-wrap break-all text-text-primary"}>{text}</span>;
  if (f.kind === "url") return <span aria-label={f.label} className="text-[14px] break-all text-text-primary">{text}</span>;
  return <span aria-label={f.label} className={f.mono || f.format ? MONO : "text-[14px] break-words text-text-primary"}>{text}</span>;
}

export function RecordPanel({ record, folderName, teamFolder, onClose, onEdit, onTrash, onRestore, onPurge, onShare, reasons, onNewPassword, children, files, scoreOf }: {
  record: VaultRecord; folderName: string | null; teamFolder?: boolean; onClose: () => void; onEdit: () => void; onTrash: () => void; onRestore?: () => void; onPurge?: () => void;
  /** Opens the share sheet (record owners only; its "One-time link" tab makes links). */ onShare?: () => void;
  /** Needs-attention reasons for this record, if any. */ reasons?: AttentionReason[];
  /** Opens the editor with a generated password (shown to people who can edit). */ onNewPassword?: () => void;
  /** Extra sections under the fields (who can open it, activity). */ children?: React.ReactNode;
  /** The Files section (features/attachments), right under the fields and notes, for every record type. */ files?: React.ReactNode;
  /** Scores the vault already worked out (usePasswordScores): opening a record then scores nothing. */ scoreOf?: (pw: string) => StrengthScore | undefined;
}) {
  // Revealed secret fields (by field id); every record opens with all of them hidden.
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setRevealed((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const [confirmPurge, setConfirmPurge] = useState(false);
  useEffect(() => { setRevealed(new Set()); setConfirmPurge(false); }, [record.id]);
  const b = record.body;
  const canEdit = record.permission === "owner" || record.permission === "edit";
  const canTrash = record.permission === "owner";
  const canShare = record.permission === "owner" && !!onShare;
  // "Use only" (spec §5.6): the app never shows any secret field (password, card number, CVV, keys…), but Copy still
  // works. A soft limit, not a cryptographic one.
  const useOnly = record.permission === "use";
  const fields = useMemo(() => (b ? shownFields(b) : []), [b]);
  const pw = b?.password;
  const strength = useMemo(() => { if (!pw) return null; const s = scoreOf?.(pw); return s === undefined ? strengthOf(pw) : strengthForScore(pw, s); }, [pw, scoreOf]);

  return (
    <aside className="relative flex h-full flex-col overflow-y-auto bg-card" aria-label="Record details">
      <div className="flex flex-col gap-5 px-6 pt-5 pb-8 max-[760px]:px-4">
        <div className="flex items-start gap-3">
          <Button variant="ghost" size="icon" aria-label="Back" className="-ml-2 min-[1100px]:hidden" onClick={onClose}><ArrowLeft className="size-4" /></Button>
          <RecordAvatar title={b?.title} kind={b?.type} size={36} />
          <div className="min-w-0 flex-1 pt-0.5">
            <h2 className="text-[18px] leading-tight break-words text-text-primary">{b ? b.title : "Can't open this record"}</h2>
            {b && (
              <p className="mt-1 flex flex-wrap items-center gap-x-1.5 text-[13px] text-text-secondary">
                {(() => { const Icon = TYPE_ICON[b.type] ?? TYPE_ICON.login; return <Icon className="size-3.5" />; })()}
                {typeLabel(b.type)}
                {folderName && <><span className="text-text-tertiary" aria-hidden="true">·</span>{teamFolder ? <Users className="size-3.5" /> : <Folder className="size-3.5" />}{folderName}</>}
                {record.sharedBy && <><span className="text-text-tertiary" aria-hidden="true">·</span>Shared by {record.sharedBy}</>}
              </p>
            )}
          </div>
          <Button variant="ghost" size="icon" aria-label="Close" className="-mr-2 max-[1099px]:hidden" onClick={onClose}><X className="size-4" /></Button>
        </div>

        {!b ? (
          <p className="rounded-[12px] border border-border-default bg-app px-4 py-3 text-[14px] text-text-secondary">The key for this record doesn't match your account. Ask the person who shared it to share it again.</p>
        ) : (
          <>
            {record.deleted ? (record.permission === "owner" && (
              <div className="flex flex-wrap items-center gap-2 rounded-[12px] border border-border-default bg-app px-3 py-2.5">
                {confirmPurge ? (
                  <>
                    <span className="mr-auto text-[13px] text-text-primary">Delete forever? This can't be undone.</span>
                    <Button variant="ghost" size="sm" onClick={() => setConfirmPurge(false)}>Cancel</Button>
                    <Button variant="destructive" size="sm" onClick={() => onPurge?.()}>Delete</Button>
                  </>
                ) : (
                  <>
                    <span className="mr-auto text-[13px] text-text-secondary">In trash</span>
                    <Button variant="outline" size="sm" onClick={() => onRestore?.()}><RotateCcw className="size-3.5" />Restore</Button>
                    <Button variant="ghost" size="sm" className="text-red-500 hover:bg-red-tint hover:text-red-500" onClick={() => setConfirmPurge(true)}>Delete forever</Button>
                  </>
                )}
              </div>
            )) : (canEdit || canTrash) && (
              <div className="flex items-center gap-2">
                {canEdit && <Button variant="outline" onClick={onEdit}><Pencil className="size-4" />Edit</Button>}
                {canShare && <Button variant="outline" onClick={onShare}><Share2 className="size-4" />Share</Button>}
                {/* Editors who aren't the owner can't share with people, but can still send a one-time link. */}
                {!canShare && <OneTimeLinkButton record={record} />}
                {canTrash && (
                  <TooltipProvider delayDuration={300}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label="Move to trash" className="size-9 hover:bg-red-tint hover:text-red-500" onClick={onTrash}><Trash2 className="size-4" /></Button>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" sideOffset={6}>Move to trash</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                )}
              </div>
            )}

            {!record.deleted && reasons && reasons.length > 0 && (
              <div role="note" aria-label="Needs attention" className="flex flex-col gap-2.5 rounded-[12px] border border-amber-500/40 bg-amber-500/10 px-4 py-3">
                <p className="flex items-start gap-2 text-[13.5px] text-text-primary"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-500" />{reasonLine(reasons)}</p>
                {canEdit && onNewPassword && <Button variant="outline" size="sm" className="self-start" onClick={onNewPassword}><Dices className="size-3.5" />Generate new password</Button>}
              </div>
            )}

            {fields.length > 0 && (
              <div className="overflow-hidden rounded-[12px] border border-border-default">
                {fields.map((f) => {
                  if (f.kind === "totp") return <TotpRow key={f.id} secret={f.value} label={f.core ? "2FA code" : f.label} />;
                  const secret = isSecretField(f);
                  const shown = !secret || (revealed.has(f.id) && !useOnly);
                  const l = lowerFirst(f.label);
                  const password = f.core && f.key === "password";
                  return (
                    <Row key={f.id} label={f.label} actions={<>
                      {secret && !useOnly && <Button variant="ghost" size="icon" aria-label={shown ? `Hide ${l}` : `Show ${l}`} onClick={() => toggle(f.id)}>{shown ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>}
                      <CopyButton value={f.value} label={`Copy ${l}`} />
                    </>}>
                      {secret ? (
                        <span className="flex flex-col gap-1.5 py-1">
                          <FieldValue f={f} shown={shown} />
                          {useOnly ? <span className="text-[12px] text-text-secondary">Use only: you can copy it, not view it.</span>
                            : password && strength ? <StrengthMeter score={strength.score} label={strength.label} /> : null}
                        </span>
                      ) : <FieldValue f={f} shown />}
                    </Row>
                  );
                })}
              </div>
            )}

            {b.notes && (
              <section className="flex flex-col gap-2" aria-label="Notes">
                <h3 className="font-mono text-[10.5px] font-normal tracking-[.12em] text-text-tertiary uppercase">Notes</h3>
                <p className="rounded-[12px] border border-border-default bg-app px-4 py-3 text-[14px] leading-relaxed whitespace-pre-wrap break-words text-text-primary">{b.notes}</p>
              </section>
            )}

            {files}

            {children}

            <p className="border-t border-border-default pt-4 font-mono text-[11.5px] text-text-tertiary">
              <span title={new Date(record.updatedAt).toLocaleString()}>Changed {relativeTime(record.updatedAt) || "—"}</span>
            </p>
          </>
        )}
      </div>
    </aside>
  );
}
