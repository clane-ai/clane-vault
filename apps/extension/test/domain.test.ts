import { describe, expect, it } from "vitest";
import { matchUrl, normaliseServerUrl, originPattern, parsePageUrl, parseUrl, siteOf } from "../src/shared/domain";

describe("registrable domains", () => {
  it("uses the public suffix list", () => {
    expect(siteOf("login.example.com")).toBe("example.com");
    expect(siteOf("a.b.example.co.uk")).toBe("example.co.uk");
    expect(siteOf("WWW.Example.COM.")).toBe("example.com");
    expect(siteOf("alice.github.io")).toBe("alice.github.io");
    expect(siteOf("localhost")).toBe("localhost");
    expect(siteOf("127.0.0.1")).toBe("127.0.0.1");
  });

  it("matches an item to a page by host, then by registrable domain", () => {
    expect(matchUrl("https://example.com/login", "https://example.com/account")).toBe("exact");
    expect(matchUrl("example.com", "https://accounts.example.com/x")).toBe("site");
    expect(matchUrl("https://bank.co.uk", "https://evil.co.uk")).toBe("none");
    expect(matchUrl("https://alice.github.io", "https://mallory.github.io")).toBe("none");
    expect(matchUrl("https://example.com", "https://example.com.evil.net")).toBe("none");
    expect(matchUrl("https://example.com", "https://notexample.com")).toBe("none");
    expect(matchUrl(undefined, "https://example.com")).toBe("none");
    expect(matchUrl("https://example.com", "chrome://settings")).toBe("none");
    expect(matchUrl("http://localhost:3000", "http://localhost:5173/")).toBe("exact");
  });

  it("parses page URLs strictly: only absolute http(s)", () => {
    expect(parsePageUrl("https://example.com:8443/x")?.origin).toBe("https://example.com:8443");
    expect(parsePageUrl("https://xn--pple-43d.com/")?.hostname).toBe("xn--pple-43d.com");
    for (const u of ["about:blank", "about:srcdoc", "data:text/html,x", "blob:https://example.com/1", "file:///etc/passwd", "javascript:alert(1)", "example.com", "chrome://newtab/", "view-source:https://example.com/"])
      expect(parsePageUrl(u)).toBeNull();
    expect(matchUrl("https://example.com", "example.com")).toBe("none");
    expect(matchUrl("https://apple.com", "https://xn--pple-43d.com/")).toBe("none");
  });

  it("parses loose item URLs", () => {
    expect(parseUrl("example.com/login")?.hostname).toBe("example.com");
    expect(parseUrl("ftp://example.com")).toBeNull();
    expect(parseUrl("  ")).toBeNull();
  });
});

describe("server URL", () => {
  it("accepts https and local http only", () => {
    expect(normaliseServerUrl("vault.clane.si")).toBe("https://vault.clane.si");
    expect(normaliseServerUrl("https://vault.clane.si/")).toBe("https://vault.clane.si");
    expect(normaliseServerUrl("http://localhost:5173")).toBe("http://localhost:5173");
    expect(normaliseServerUrl("http://127.0.0.1:3001/")).toBe("http://127.0.0.1:3001");
    expect(normaliseServerUrl("http://vault.example.com")).toBeNull();
    expect(normaliseServerUrl("https://user:pw@vault.example.com")).toBeNull();
    expect(normaliseServerUrl("javascript:alert(1)")).toBeNull();
    // Served under a path (BASE_PATH): the path is kept, without trailing slashes.
    expect(normaliseServerUrl("https://northwind.example.com/vault/")).toBe("https://northwind.example.com/vault");
    expect(normaliseServerUrl("northwind.example.com/vault")).toBe("https://northwind.example.com/vault");
    expect(normaliseServerUrl("https://northwind.example.com/a/b//")).toBe("https://northwind.example.com/a/b");
    expect(normaliseServerUrl("https://northwind.example.com/vault?x=1")).toBeNull();
  });
  it("derives the host permission pattern", () => {
    expect(originPattern("http://localhost:5173")).toBe("http://localhost/*");
    expect(originPattern("https://vault.clane.si")).toBe("https://vault.clane.si/*");
    // The host permission is the origin, whatever path the server is under.
    expect(originPattern("https://northwind.example.com/vault")).toBe("https://northwind.example.com/*");
  });
});
