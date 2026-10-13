import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { copySecret } from "@/lib/clipboard";

/** Icon button that copies a secret and shows a check for 1.5 s. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState(false);
  const t = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(t.current), []);
  return (
    <Button variant="ghost" size="icon" aria-label={label} className={done ? "text-green-600 hover:text-green-600" : undefined}
      onClick={async () => {
        await copySecret(value);
        toast.success("Copied. Clipboard clears in 30 s");
        setDone(true); clearTimeout(t.current); t.current = setTimeout(() => setDone(false), 1500);
      }}>
      {done ? <Check className="size-4" /> : <Copy className="size-4" />}
    </Button>
  );
}
