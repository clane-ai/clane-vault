import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/index.css";
import App from "./App.tsx";
import { applyTheme, getTheme } from "./lib/theme";
import { loadBrand, productName } from "./brand";
import { registerServiceWorker } from "./pwa/register";

applyTheme(getTheme());
document.title = productName;
registerServiceWorker();

// The server's branding (docs/branding.md) before the first paint, so the names don't flicker; the build's names when it
// can't be asked quickly (offline, older server).
void loadBrand(1500).finally(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
