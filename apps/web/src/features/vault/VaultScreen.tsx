import { useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { generatePassword, type RecordBody } from "@clane-vault/crypto";
import { Button } from "@/components/ui/button";
import { Sheet, SheetBody, SheetCloseButton, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ImportSheet } from "@/features/import/ImportSheet";
import { FolderDialog } from "./FolderDialog";
import { GeneratorPanel } from "./GeneratorPanel";
import { NewMenu, type NewKind } from "./NewMenu";
import { NewRecordDialog, type NewRecordStart } from "./NewRecordDialog";
import { RecordEditor } from "./RecordEditor";
import { TeamFolderDialog } from "./TeamFolderDialog";
import { ApiError } from "@/lib/api";
import { ConflictError, useVault } from "./useVault";
import VaultPage from "./VaultPage";
import { useSession } from "@/lib/session";
import { adminPath, spacePrefix } from "@/lib/paths";
import { canFileInto } from "./types";
import { EditorFiles, QueuedFiles } from "@/features/attachments/EditorFiles";
import { useFileDrop } from "@/features/attachments/AttachmentDropZone";
import { useAttachmentLimits, useRecordDrop } from "@/features/attachments/useAttachments";
import { precheck, startUpload } from "@/features/attachments/uploader";
import { useOrgApi } from "@/lib/scope";
import { useSpacePaths } from "@/lib/space";
import { planMessage, useLocked } from "@/features/admin/plan";
import { agentsOff, useGateway } from "@/features/admin/agents";

type Editing = ({ mode: "create" } & NewRecordStart) | { mode: "edit"; id: string; newPassword?: string } | null;

export default function VaultScreen() {
  const v = useVault();
  const [editing, setEditing] = useState<Editing>(null);
  // New Record (step one: location, type, title), opened at a folder; Next opens the editor with them.
  const [newRecordAt, setNewRecordAt] = useState<{ folderId: string | null } | null>(null);
  // The folder open in the vault list: + New → Record starts there.
  const [folderId, setFolderId] = useState<string | null>(null);
  const [folderOpen, setFolderOpen] = useState(false);
  const [teamOpen, setTeamOpen] = useState(false);
  const [genOpen, setGenOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const navigate = useNavigate();
  const { org, orgs, offline } = useSession();
  // The space decides what can be made: an organisation has shared folders (and records in them), Personal private ones.
  const team = !!org;
  // The plan is readable by owners and admins; for plain members the server cannot enforce Business-only policy fields (they are ciphertext).
  // Agents off answers 404 (members can read this); a 503 or any other error keeps the section.
  const gw = useGateway(!!org, true);
  const pathsLocked = useLocked("agentPathPolicy", !!org && org.role !== "member");
  // Bulk migration (Keeper with shared folders and people) is an org admin's: Import lives in Personal, so it offers the
  // organisation the user administers.
  const migrateOrg = org ? (org.role !== "member" ? org : null) : orgs.find((o) => o.role !== "member") ?? null;
  const recordHint = team && !v.isLoading && !v.folders.some(canFileInto) ? "Create a shared folder first" : undefined;
  const current = editing?.mode === "edit" ? v.records.find((r) => r.id === editing.id) : undefined;
  // Files picked for a record that doesn't exist yet: uploaded right after its first save (docs/attachments.md).
  const [queue, setQueue] = useState<File[]>([]);
  const oapi = useOrgApi();
  const paths = useSpacePaths();
  const limits = useAttachmentLimits();
  const recordDrop = useRecordDrop(current ?? null);
  const addToQueue = (files: File[]) => {
    const next = [...queue];
    for (const f of files) {
      const why = precheck(f, { maxFileMb: limits.maxFileMb, maxPerRecord: limits.maxPerRecord, maxRecordMb: limits.maxRecordMb, existingFiles: 0, existingBytes: 0, pending: next });
      if (why) toast.error(why); else next.push(f);
    }
    setQueue(next);
  };
  const editorDrop = useFileDrop({
    canDrop: editing?.mode === "create" ? limits.uploadsAllowed : recordDrop.canDrop, title: editing?.mode === "create" ? editing.title : current?.body?.title,
    onFiles: editing?.mode === "create" ? addToQueue : recordDrop.onFiles, disabled: !editing || !limits.enabled || offline,
  });
  const closeEditor = () => { setEditing(null); setQueue([]); };

  const onNew = (k: NewKind, at: string | null = folderId) => (k === "folder" ? setFolderOpen(true) : k === "team" ? setTeamOpen(true) : k === "generate" ? setGenOpen(true) : k === "import" ? setImportOpen(true) : setNewRecordAt({ folderId: at }));
  // "Generate new password" (Needs attention) opens the editor with a fresh password; the panel offers it to editors only.
  const initial = current?.body && editing?.mode === "edit" && editing.newPassword ? { ...current.body, password: editing.newPassword, passwordChangedAt: new Date().toISOString() } : current?.body ?? undefined;

  async function save(body: RecordBody, folderId: string | null) {
    try {
      if (editing?.mode === "create") {
        const files = queue;
        const created = await v.createRecord({ folderId, body, onCreated: (id, recordKey) => {
          for (const file of files) startUpload({ api: oapi, recordId: id, recordKey, file, member: org?.role === "member", onDone: () => { void v.refresh(); } });
        } });
        toast.success(files.length ? `Saved. Uploading ${files.length} ${files.length === 1 ? "file" : "files"}…` : "Saved");
        // The record's panel shows the uploads' progress.
        if (files.length && created) navigate(paths.record("vault", created));
        setQueue([]);
      }
      else if (current) {
        await v.updateRecord(current, body);
        // Moving re-wraps the record key for the target folder (team folders) or drops the folder wrap (private).
        if (folderId !== current.folderId && current.permission === "owner") await v.moveRecord(current, folderId);
        toast.success("Saved");
      }
      setEditing(null);
      setQueue([]);
    } catch (e) {
      if (e instanceof ConflictError) { toast.error(e.message); return; }
      if (e instanceof ApiError && e.code === "in_trash") { toast.error("This record is in the trash."); return; }
      const pm = planMessage(e, org?.role === "member");
      if (pm) throw new Error(pm);
      // The body's own limits (crypto validate): shown in the editor as they are.
      if (e instanceof Error && /too large|too long|at most \d+/.test(e.message)) throw new Error("This record is too large. Shorten long fields or notes, or remove some custom fields.");
      throw new Error("Couldn't save. Check your connection and try again.");
    }
  }

  return (
    <>
      <VaultPage folderId={folderId} onFolderChange={setFolderId} onNew={onNew}
        newButton={offline ? undefined : (compact) => <NewMenu onNew={(k) => onNew(k)} team={team} recordHint={recordHint} compact={compact} />} onCreate={() => setNewRecordAt({ folderId })} onEdit={offline ? undefined : (id, o) => setEditing({ mode: "edit", id, ...(o?.newPassword ? { newPassword: generatePassword() } : {}) })} />
      <Sheet open={!!editing} onOpenChange={(o) => !o && closeEditor()}>
        <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="w-full sm:max-w-[440px]" {...editorDrop.handlers}>
          {editorDrop.overlay}
          {editing && (
            <RecordEditor key={editing.mode === "edit" ? `${editing.id}-${current?.revision}` : "new"} TitleAs={SheetTitle}
              mode={editing.mode} type={editing.mode === "create" ? editing.type : (current?.body?.type ?? "login")}
              initial={editing.mode === "create" ? { type: editing.type, title: editing.title } : initial} folderId={editing.mode === "create" ? editing.folderId : current?.folderId ?? null} folders={v.folders} agentUse={team && !agentsOff(gw.error) && (editing.mode === "create" || current?.permission === "owner" || current?.permission === "edit")} pathsLocked={pathsLocked} canMove={editing.mode === "create" || current?.permission === "owner"} noFolder={!team}
              onSave={save} onCancel={closeEditor}
              files={!limits.enabled || offline ? undefined : editing.mode === "create" ? <QueuedFiles queue={queue} onChange={setQueue} /> : current?.body ? <EditorFiles record={current} /> : undefined} />
          )}
        </SheetContent>
      </Sheet>
      <NewRecordDialog open={!!newRecordAt} folders={v.folders} folderId={newRecordAt?.folderId} noFolder={!team} onCancel={() => setNewRecordAt(null)}
        onNext={(start) => { setNewRecordAt(null); setEditing({ mode: "create", ...start }); }} />
      <Sheet open={genOpen} onOpenChange={setGenOpen}>
        <SheetContent side="right" showCloseButton={false} aria-describedby={undefined} className="w-full sm:max-w-[440px]">
          <SheetHeader><SheetTitle>Generate password</SheetTitle><SheetCloseButton /></SheetHeader>
          <SheetBody><GeneratorPanel /></SheetBody>
          <SheetFooter><Button type="button" onClick={() => setGenOpen(false)}>Done</Button></SheetFooter>
        </SheetContent>
      </Sheet>
      <ImportSheet open={importOpen} onOpenChange={setImportOpen} folders={v.folders} onBulkMigration={migrateOrg ? () => { setImportOpen(false); navigate(adminPath(spacePrefix(migrateOrg), "migrate")); } : undefined} />
      <FolderDialog open={folderOpen} mode="create" onCancel={() => setFolderOpen(false)}
        onSave={async (name) => { await v.createFolder(name); setFolderOpen(false); toast.success("Folder created"); }} />
      <TeamFolderDialog open={teamOpen} onCancel={() => setTeamOpen(false)}
        onSave={async (name, people) => { await v.createTeamFolder(name, people); setTeamOpen(false); toast.success("Shared folder created"); }} />
    </>
  );
}
