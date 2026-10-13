import { afterEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { render, screen, fireEvent } from "@testing-library/react";
import { Link, Route, Routes, useLocation } from "react-router";
import { server } from "@/test/server";
import { AppRouter } from "@/App";
import { api } from "./api";
import { apiUrl, appUrl, basePath, readBasePath, resetBasePath, storageKey, withBase } from "./base";
import { linkUrl } from "@/features/links/useLinks";

function setBase(content: string | null) {
  document.querySelectorAll('meta[name="clane-base"]').forEach((m) => m.remove());
  if (content !== null) {
    const m = document.createElement("meta");
    m.name = "clane-base";
    m.content = content;
    document.head.appendChild(m);
  }
  resetBasePath();
}

afterEach(() => { setBase(null); window.history.replaceState(null, "", "/"); });

describe("base path (<meta name=clane-base>)", () => {
  it("is the root without the tag, and the tag's path otherwise", () => {
    setBase(null);
    expect(basePath()).toBe("");
    setBase("/vault");
    expect(basePath()).toBe("/vault");
    setBase("/a/b.c/");
    expect(basePath()).toBe("/a/b.c");
  });
  it("ignores anything that isn't a plain path (falls back to the root)", () => {
    for (const bad of ["vault", "//evil.example", "https://evil.example/x", "/a b", "/../x", "/x?y", "/\"x"]) {
      setBase(bad);
      expect(readBasePath(), bad).toBe("");
    }
  });
  it("prefixes API calls, assets, absolute links and storage keys under a base", () => {
    setBase("/vault");
    expect(apiUrl("/auth/refresh")).toBe("/vault/api/v1/auth/refresh");
    expect(withBase("/showcase/vault.webp")).toBe("/vault/showcase/vault.webp");
    expect(appUrl("/s/abc", "https://northwind.example.com")).toBe("https://northwind.example.com/vault/s/abc");
    expect(linkUrl("abc", "k", "https://northwind.example.com")).toBe("https://northwind.example.com/vault/s/abc#k");
    expect(storageKey("cv.org.u1")).toBe("cv.org.u1@/vault");
  });
  it("leaves everything unchanged at the root", () => {
    setBase("");
    expect(apiUrl("/me")).toBe("/api/v1/me");
    expect(appUrl("/s/abc", "https://h")).toBe("https://h/s/abc");
    expect(storageKey("cv.org.u1")).toBe("cv.org.u1");
  });
  it("the API client calls ${base}/api/v1", async () => {
    setBase("/vault");
    server.use(http.get("/vault/api/v1/me", () => HttpResponse.json({ where: "vault" })));
    api.setAccessToken("t");
    expect(await api.get("/me")).toEqual({ where: "vault" });
  });
});

function Where() { const l = useLocation(); return <p data-testid="where">{l.pathname}</p>; }

describe("router basename", () => {
  it("routes deep links below the base and keeps the base in the address bar", () => {
    setBase("/vault");
    window.history.replaceState(null, "", "/vault/p/vault/record/1");
    render(<AppRouter><Routes><Route path="*" element={<><Where /><Link to="/settings">settings</Link></>} /></Routes></AppRouter>);
    expect(screen.getByTestId("where")).toHaveTextContent("/p/vault/record/1");
    expect(screen.getByText("settings")).toHaveAttribute("href", "/vault/settings");
    fireEvent.click(screen.getByText("settings"));
    expect(window.location.pathname).toBe("/vault/settings");
    expect(screen.getByTestId("where")).toHaveTextContent("/settings");
  });
  it("has no basename at the root", () => {
    setBase(null);
    window.history.replaceState(null, "", "/p/vault");
    render(<AppRouter><Routes><Route path="*" element={<><Where /><Link to="/settings">settings</Link></>} /></Routes></AppRouter>);
    expect(screen.getByTestId("where")).toHaveTextContent("/p/vault");
    expect(screen.getByText("settings")).toHaveAttribute("href", "/settings");
  });
});
