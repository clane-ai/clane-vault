import { useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PeoplePicker } from "./PeoplePicker";
import { PermissionSelect, PersonRow } from "./people";
import type { Grant, Person } from "./types";

export function TeamFolderDialog({ open, onSave, onCancel }: { open: boolean; onSave: (name: string, people: { person: Person; permission: Grant }[]) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [people, setPeople] = useState<{ person: Person; permission: Grant }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const reset = () => { setName(""); setPeople([]); setError(null); };

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return setError("Give the folder a name.");
    setBusy(true);
    try { await onSave(name.trim(), people); reset(); }
    catch { setError("Couldn't create the shared folder. Try again."); }
    finally { setBusy(false); }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { reset(); onCancel(); } }}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>New shared folder</DialogTitle>
          <DialogDescription>A team folder: everyone you add can open the records in it. You can add people later too.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5"><Label htmlFor="team-name">Folder name</Label><Input id="team-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus autoComplete="off" placeholder="e.g. Infrastructure" /></div>
          <div className="flex flex-col gap-2">
            <span className="text-[13px] font-medium text-text-primary">People</span>
            <PeoplePicker exclude={people.map((p) => p.person.id)} onAdd={async (person, permission) => setPeople((xs) => [...xs, { person, permission }])} />
            {people.length > 0 && (
              <ul className="rounded-[12px] border border-border-default px-3">
                {people.map(({ person, permission }) => (
                  <PersonRow key={person.id} id={person.id} name={person.name} email={person.email} publicKey={person.membershipKey ?? person.publicKey}>
                    <PermissionSelect value={permission} label={`Permission for ${person.name}`} onChange={(p) => setPeople((xs) => xs.map((x) => (x.person.id === person.id ? { ...x, permission: p } : x)))} />
                    <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${person.name}`} onClick={() => setPeople((xs) => xs.filter((x) => x.person.id !== person.id))}><X className="size-4" /></Button>
                  </PersonRow>
                ))}
              </ul>
            )}
          </div>
          {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => { reset(); onCancel(); }}>Cancel</Button>
            <Button type="submit" disabled={busy}>{busy ? "Creating…" : "Create"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
