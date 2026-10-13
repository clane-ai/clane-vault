import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./popup.css";

const dark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
document.documentElement.dataset.theme = dark ? "dark" : "light";
if (new URLSearchParams(location.search).has("tab")) document.body.classList.add("as-page");
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
