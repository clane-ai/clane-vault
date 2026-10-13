import * as React from "react"
import { cn } from "@/lib/utils"

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "min-h-20 w-full min-w-0 resize-y rounded-[10px] border border-input bg-card px-3 py-2.5 text-[14px] leading-relaxed text-text-primary transition-[border-color,box-shadow] duration-150 outline-none placeholder:text-text-tertiary hover:border-border-strong focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/20 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
