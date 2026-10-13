import { useState } from "react";
import { Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { VaultRecord } from "@/features/vault/types";
import { OneTimeLinkSheet } from "./OneTimeLinkSheet";

/** Record panel action: opens the One-time link sheet. Only for people who can edit the record. */
export function OneTimeLinkButton({ record }: { record: VaultRecord }) {
  const [open, setOpen] = useState(false);
  if (record.deleted || !record.body || (record.permission !== "owner" && record.permission !== "edit")) return null;
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}><Link2 className="size-4" />One-time link</Button>
      {open && <OneTimeLinkSheet record={record} open onOpenChange={setOpen} />}
    </>
  );
}
