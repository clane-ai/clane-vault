import { useRef, useState, type FormEvent } from "react";
import { RECORD_TYPE_GROUPS, type RecordType } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FolderGlyph } from "./FolderGlyph";
import { PLACEHOLDER, TYPE_ICON } from "./recordKinds";
import { canFileInto, glyphFor, type VaultFolder } from "./types";

const NO_FOLDER = "__none__";
export type NewRecordStart = { type: RecordType; title: string; folderId: string | null };

/**
 * The location a new record starts in: the open folder when a record can be filed there, else no folder (in an
 * organisation, where every record goes into a shared folder: the first one I can add to).
 */
export const startFolder = (folders: VaultFolder[], folderId: string | null | undefined, noFolder = true) => {
  const f = folders.find((x) => x.id === folderId);
  return f && canFileInto(f) ? f.id : noFolder ? null : folders.find(canFileInto)?.id ?? null;
};

/**
 * Step one of a new record (Keeper's "New Record"): where it goes, what kind it is and its title. Next hands these to
 * the full editor; nothing is created until the editor saves.
 */
export function NewRecordDialog({ open, folders, folderId, noFolder = true, onNext, onCancel }: {
  open: boolean; folders: VaultFolder[];
  /** "No folder" is a location (Personal); in an organisation records go into its shared folders. */ noFolder?: boolean;
  /** The folder open in the vault list: the default location. */ folderId?: string | null;
  onNext: (start: NewRecordStart) => void; onCancel: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      {/* Remounted on every open: it starts from the folder open now, with an empty title. */}
      {open && <NewRecordForm folders={folders} folderId={startFolder(folders, folderId, noFolder)} noFolder={noFolder} onNext={onNext} onCancel={onCancel} />}
    </Dialog>
  );
}

function NewRecordForm({ folders, folderId, noFolder, onNext, onCancel }: { folders: VaultFolder[]; folderId: string | null; noFolder: boolean; onNext: (s: NewRecordStart) => void; onCancel: () => void }) {
  const [folder, setFolder] = useState<string | null>(folderId);
  const [type, setType] = useState<RecordType>("login");
  const [title, setTitle] = useState("");
  const titleRef = useRef<HTMLInputElement>(null);
  const live = folders.filter(canFileInto);
  const ready = title.trim() !== "" && (noFolder || folder !== null);
  function submit(e: FormEvent) {
    e.preventDefault();
    if (ready) onNext({ type, title: title.trim(), folderId: folder });
  }
  return (
    <DialogContent className="sm:max-w-[420px]" aria-describedby={undefined}
      // Title first (the dialog would focus its first control, Location).
      onOpenAutoFocus={(e) => { e.preventDefault(); titleRef.current?.focus(); }}>
      <DialogHeader><DialogTitle>New record</DialogTitle></DialogHeader>
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="new-location">Location</Label>
          <Select value={folder ?? NO_FOLDER} onValueChange={(x) => setFolder(x === NO_FOLDER ? null : x)}>
            <SelectTrigger id="new-location" className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              {noFolder && <SelectItem value={NO_FOLDER}><FolderGlyph kind="none" size={16} />No folder</SelectItem>}
              {noFolder && live.length > 0 && <SelectSeparator />}
              {live.map((x) => (
                <SelectItem key={x.id} value={x.id}>
                  <FolderGlyph {...glyphFor(x)} size={16} />{x.name}{x.kind === "team" ? " · Shared" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="new-type">Record Type</Label>
          <Select value={type} onValueChange={(x) => setType(x as RecordType)}>
            <SelectTrigger id="new-type" className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent className="max-h-[min(420px,var(--radix-select-content-available-height))]">
              {RECORD_TYPE_GROUPS.map((g, i) => (
                <SelectGroup key={g.group}>
                  {i > 0 && <SelectSeparator />}
                  <SelectLabel className="px-2 pt-1.5 pb-1 text-[11.5px] font-medium text-text-secondary">{g.label}</SelectLabel>
                  {g.types.map((t) => { const Icon = TYPE_ICON[t.id]; return <SelectItem key={t.id} value={t.id}><Icon className="text-text-tertiary" />{t.label}</SelectItem>; })}
                </SelectGroup>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="new-title">Title</Label>
          <Input id="new-title" ref={titleRef} value={title} onChange={(e) => setTitle(e.target.value)} autoComplete="off" placeholder={`e.g. ${PLACEHOLDER[type]}`} />
        </div>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button type="submit" disabled={!ready} className="min-w-20">Next</Button>
        </div>
      </form>
    </DialogContent>
  );
}
