import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function FolderDialog({ open, mode, initialName = "", onSave, onCancel }: { open: boolean; mode: "create" | "rename"; initialName?: string; onSave: (n: string) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState(initialName);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return setError("Give the folder a name.");
    try { await onSave(name.trim()); setName(""); setError(null); } catch { setError(mode === "create" ? "Couldn't create the folder. Try again." : "Couldn't rename the folder. Try again."); }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent>
        <DialogHeader><DialogTitle>{mode === "create" ? "New folder" : "Rename folder"}</DialogTitle></DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5"><Label htmlFor="folder-name">{mode === "create" ? "Folder name" : "Name"}</Label><Input id="folder-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus autoComplete="off" /></div>
          <p className="text-[13px] text-text-secondary">{mode === "create" ? "Only you can see this folder. To share with people, create a shared folder instead." : "Only the folder name changes. Nothing is re-encrypted."}</p>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button><Button type="submit">{mode === "create" ? "Create" : "Save"}</Button></div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
