import type { ReactNode } from "react";
import { BrowserRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/sonner";
import { SessionProvider } from "@/lib/session";
import { AppRoutes } from "./routes";
import { basePath } from "@/lib/base";

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: true } } });

/** The router, under the base path the server serves the app at (BASE_PATH, e.g. /vault; none at the root). */
export function AppRouter({ children }: { children: ReactNode }) {
  return <BrowserRouter basename={basePath() || undefined}>{children}</BrowserRouter>;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <SessionProvider>
        <AppRouter><AppRoutes /></AppRouter>
        <Toaster />
      </SessionProvider>
    </QueryClientProvider>
  );
}
