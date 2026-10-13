// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";
import { fillPage, findLoginFields, readSubmission } from "../src/shared/forms";

const page = (html: string) => { document.body.innerHTML = html; };

describe("login form detection", () => {
  beforeEach(() => page(""));

  it("finds the username before the password in the same form", () => {
    page(`<input id="search" type="text">
      <form id="f"><input id="news" type="email" name="newsletter-x"><input id="u" name="login"><input id="p" type="password"></form>`);
    const f = findLoginFields(document);
    expect(f.password?.id).toBe("p");
    expect(f.username?.id).toBe("u");
  });

  it("prefers autocomplete=username and current-password", () => {
    page(`<form><input id="a" name="x"><input id="u" autocomplete="username"><input id="n" type="password" autocomplete="new-password"><input id="c" type="password" autocomplete="current-password"></form>`);
    const f = findLoginFields(document);
    expect(f.username?.id).toBe("u");
    expect(f.password?.id).toBe("c");
  });

  it("ignores hidden, invisible and disabled fields", () => {
    page(`<form><input id="trap" name="user" style="display:none"><div style="opacity:0"><input id="trap2" name="email"></div>
      <input id="u" name="email"><input type="password" id="hp" style="visibility:hidden"><input type="password" id="p"><input type="password" id="d" disabled></form>`);
    const f = findLoginFields(document);
    expect(f.username?.id).toBe("u");
    expect(f.password?.id).toBe("p");
  });

  it("works without a form element and for a username-only first step", () => {
    page(`<div><input id="e" type="email"><button>Next</button></div>`);
    const f = findLoginFields(document);
    expect(f.password).toBeNull();
    expect(f.username?.id).toBe("e");
  });

  it("reads a submission only when a password is present", () => {
    page(`<form><input id="u" name="username" value=" ana@example.com "><input type="password" id="p" value="s3cret"></form>`);
    expect(readSubmission(document)).toEqual({ username: "ana@example.com", password: "s3cret" });
    (document.getElementById("p") as HTMLInputElement).value = "";
    expect(readSubmission(document)).toBeNull();
  });

  it("uses a remembered username for password-only second steps", () => {
    page(`<form><input type="password" id="p" value="pw"></form>`);
    expect(readSubmission(document, "ana")).toEqual({ username: "ana", password: "pw" });
  });
});

describe("filling", () => {
  it("fills both fields and fires input events", () => {
    page(`<form><input id="u" name="user"><input type="password" id="p"></form>`);
    const seen: string[] = [];
    document.addEventListener("input", (e) => seen.push((e.target as HTMLInputElement).id), true);
    const r = fillPage(document, window.location.origin, "ana", "pw");
    expect(r).toEqual({ ok: true, filled: ["username", "password"] });
    expect((document.getElementById("u") as HTMLInputElement).value).toBe("ana");
    expect((document.getElementById("p") as HTMLInputElement).value).toBe("pw");
    expect(seen).toEqual(["u", "p"]);
  });

  it("refuses when the page navigated to another origin since the check", () => {
    page(`<form><input id="u"><input type="password" id="p"></form>`);
    expect(fillPage(document, "https://other.example", "ana", "pw")).toEqual({ ok: false, reason: "navigated" });
    expect((document.getElementById("p") as HTMLInputElement).value).toBe("");
  });

  it("reports pages without login fields", () => {
    page(`<p>Hello</p>`);
    expect(fillPage(document, window.location.origin, "ana", "pw")).toEqual({ ok: false, reason: "no_fields" });
  });
});
