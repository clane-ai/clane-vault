"use client"

import { useEffect, useState } from "react"
import { Toaster as Sonner, type ToasterProps } from "sonner"
import { CircleCheckIcon, InfoIcon, TriangleAlertIcon, OctagonXIcon, Loader2Icon } from "lucide-react"

const readTheme = (): "light" | "dark" => (document.documentElement.dataset.theme === "dark" ? "dark" : "light")

function useTheme() {
  const [theme, setTheme] = useState(readTheme)
  useEffect(() => {
    const obs = new MutationObserver(() => setTheme(readTheme()))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] })
    return () => obs.disconnect()
  }, [])
  return theme
}

const Toaster = ({ ...props }: ToasterProps) => {
  const theme = useTheme()

  return (
    <Sonner
      theme={theme}
      position="bottom-center" /* bottom-right covered the side sheets' footer buttons */
      className="toaster group"
      icons={{
        success: <CircleCheckIcon className="size-4 text-green-600" />,
        info: <InfoIcon className="size-4 text-blue-500" />,
        warning: <TriangleAlertIcon className="size-4 text-blue-500" />,
        error: <OctagonXIcon className="size-4 text-red-500" />,
        loading: <Loader2Icon className="size-4 animate-spin text-text-secondary" />,
      }}
      style={
        {
          "--normal-bg": "var(--card)",
          "--normal-text": "var(--card-foreground)",
          "--normal-border": "var(--border-default)",
          "--border-radius": "12px",
        } as React.CSSProperties
      }
      toastOptions={{
        unstyled: false,
        classNames: {
          toast:
            "cn-toast !bg-card !text-card-foreground !border !border-border-default !rounded-[12px] !font-sans !text-[14px] !gap-2.5 !shadow-[var(--shadow-card),0_8px_24px_rgba(10,18,36,0.12)]",
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
