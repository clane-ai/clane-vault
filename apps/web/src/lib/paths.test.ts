import { describe, expect, it } from "vitest";
import { adminPath, findOrg, folderPath, parseAppPath, recordPath, spaceOf, spacePrefix, type PathContext } from "./paths";
import { wantedSpace } from "./space";

const P = { kind: "personal" } as const;
const ACME = { kind: "org", ref: "acme" } as const;
const inPersonal: PathContext = { space: "/p", adminOrg: "/o/acme" };
const inAcme: PathContext = { space: "/o/acme", adminOrg: "/o/acme" };

describe("app URLs: the space is in the path", () => {
  it("Personal: vault lists, folders and records; no Shared with me", () => {
    expect(parseAppPath("/p/vault")).toEqual({ area: "list", space: P, view: "vault", folderId: null, recordId: null });
    expect(parseAppPath("/p/vault/folder/f1")).toEqual({ area: "list", space: P, view: "vault", folderId: "f1", recordId: null });
    expect(parseAppPath("/p/vault/record/r1")).toEqual({ area: "list", space: P, view: "vault", folderId: null, recordId: "r1" });
    expect(parseAppPath("/p/trash/record/r2")).toEqual({ area: "list", space: P, view: "trash", folderId: null, recordId: "r2" });
    for (const v of ["attention", "links"]) expect(parseAppPath(`/p/${v}`)).toMatchObject({ area: "list", space: P, view: v });
    expect(parseAppPath("/p/shared")).toEqual({ area: "redirect", to: "/p/vault" });
    expect(parseAppPath("/p")).toEqual({ area: "redirect", to: "/p/vault" });
    expect(parseAppPath("/p/vault/x/y/z")).toEqual({ area: "redirect", to: "/p/vault" });
    expect(parseAppPath("/p/admin/people")).toEqual({ area: "redirect", to: "/server" });
  });

  it("an organisation: its lists (with Shared with me), folders, records and admin pages", () => {
    expect(parseAppPath("/o/acme/vault")).toEqual({ area: "list", space: ACME, view: "vault", folderId: null, recordId: null });
    expect(parseAppPath("/o/acme/vault/folder/f1")).toEqual({ area: "list", space: ACME, view: "vault", folderId: "f1", recordId: null });
    expect(parseAppPath("/o/acme/shared/record/r1")).toEqual({ area: "list", space: ACME, view: "shared", folderId: null, recordId: "r1" });
    for (const v of ["attention", "links", "trash"]) expect(parseAppPath(`/o/acme/${v}`)).toMatchObject({ area: "list", space: ACME, view: v });
    expect(parseAppPath("/o/acme")).toEqual({ area: "redirect", to: "/o/acme/vault" });
    expect(parseAppPath("/o/acme/admin")).toEqual({ area: "admin", space: ACME, section: null, detailId: null });
    expect(parseAppPath("/o/acme/admin/people/u1")).toEqual({ area: "admin", space: ACME, section: "people", detailId: "u1" });
    expect(parseAppPath("/o/acme/admin/groups/g1")).toEqual({ area: "admin", space: ACME, section: "groups", detailId: "g1" });
    for (const s of ["risk", "events", "health", "migrate", "org/general", "org/policies", "org/sso", "org/recovery", "org/email"])
      expect(parseAppPath(`/o/acme/admin/${s}`)).toEqual({ area: "admin", space: ACME, section: s, detailId: null });
    expect(parseAppPath("/o/acme/admin/nope")).toEqual({ area: "redirect", to: "/o/acme/admin" });
    expect(parseAppPath("/o/acme/admin/org")).toEqual({ area: "redirect", to: "/o/acme/admin/org/general" });
    expect(parseAppPath("/o/acme/admin/server/email")).toEqual({ area: "redirect", to: "/server/email" });
    expect(parseAppPath("/o/acme/settings/security")).toEqual({ area: "redirect", to: "/settings/security" });
    // A reference with characters that need encoding round-trips.
    expect(parseAppPath("/o/a%20b/vault")).toMatchObject({ space: { kind: "org", ref: "a b" } });
  });

  it("settings stay global; the server's pages live outside any org", () => {
    expect(parseAppPath("/settings")).toEqual({ area: "settings", section: null });
    for (const s of ["account", "security", "device", "extension", "health"]) expect(parseAppPath(`/settings/${s}`)).toEqual({ area: "settings", section: s });
    expect(parseAppPath("/settings/people")).toEqual({ area: "redirect", to: "/settings" });
    expect(parseAppPath("/server")).toEqual({ area: "admin", space: null, section: null, detailId: null });
    for (const s of ["branding", "email", "backups"]) expect(parseAppPath(`/server/${s}`)).toEqual({ area: "admin", space: null, section: `server/${s}`, detailId: null });
    expect(parseAppPath("/server/nope")).toEqual({ area: "redirect", to: "/server" });
  });

  it("old paths go to the space used last (and old admin paths to its org, or one the user administers)", () => {
    expect(parseAppPath("/", inPersonal)).toEqual({ area: "redirect", to: "/p/vault" });
    expect(parseAppPath("/", inAcme)).toEqual({ area: "redirect", to: "/o/acme/vault" });
    expect(parseAppPath("/whatever", inAcme)).toEqual({ area: "redirect", to: "/o/acme/vault" });
    expect(parseAppPath("/vault/record/r1", inAcme)).toEqual({ area: "redirect", to: "/o/acme/vault/record/r1" });
    expect(parseAppPath("/vault/folder/f1", inPersonal)).toEqual({ area: "redirect", to: "/p/vault/folder/f1" });
    expect(parseAppPath("/shared", inAcme)).toEqual({ area: "redirect", to: "/o/acme/shared" });
    expect(parseAppPath("/shared", inPersonal)).toEqual({ area: "redirect", to: "/p/vault" });
    expect(parseAppPath("/trash/record/r2", inPersonal)).toEqual({ area: "redirect", to: "/p/trash/record/r2" });
    expect(parseAppPath("/links", inAcme)).toEqual({ area: "redirect", to: "/o/acme/links" });
    expect(parseAppPath("/vault/x/y/z", inAcme)).toEqual({ area: "redirect", to: "/o/acme/vault" });
    expect(parseAppPath("/health", inAcme)).toEqual({ area: "redirect", to: "/settings/health" });
    expect(parseAppPath("/migrate", inPersonal)).toEqual({ area: "redirect", to: "/o/acme/admin/migrate" });
    expect(parseAppPath("/admin", inPersonal)).toEqual({ area: "redirect", to: "/o/acme/admin" });
    expect(parseAppPath("/admin/people/u1", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin/people/u1" });
    expect(parseAppPath("/admin/org/logo", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin/org/general" });
    expect(parseAppPath("/admin/nope", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin" });
    expect(parseAppPath("/org/settings/sso", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin/org/sso" });
    expect(parseAppPath("/org/settings", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin/org/general" });
    expect(parseAppPath("/settings/org/logo", inAcme)).toEqual({ area: "redirect", to: "/o/acme/admin/org/general" });
    expect(parseAppPath("/admin/server/email", inAcme)).toEqual({ area: "redirect", to: "/server/email" });
    expect(parseAppPath("/admin/backups", inAcme)).toEqual({ area: "redirect", to: "/server/backups" });
    // No org at all: old admin paths go to the server's pages (No access there unless an instance admin).
    expect(parseAppPath("/admin/people", { space: "/p", adminOrg: null })).toEqual({ area: "redirect", to: "/server" });
  });

  it("builds paths in a space", () => {
    expect(spacePrefix(null)).toBe("/p");
    expect(spacePrefix({ id: "8b1e5c1a-0c4b-4b8e-9a77-2f2d7a1c0e11", slug: "acme" })).toBe("/o/acme");
    expect(spacePrefix({ id: "8b1e5c1a-0c4b-4b8e-9a77-2f2d7a1c0e11", slug: "" })).toBe("/o/8b1e5c1a-0c4b-4b8e-9a77-2f2d7a1c0e11");
    expect(recordPath("/o/acme", "attention", "r3")).toBe("/o/acme/attention/record/r3");
    expect(recordPath("/p", "links", "r3")).toBe("/p/vault/record/r3");
    expect(folderPath("/p", null)).toBe("/p/vault");
    expect(folderPath("/o/acme", "f1")).toBe("/o/acme/vault/folder/f1");
    expect(adminPath("/o/acme", "people", "u1")).toBe("/o/acme/admin/people/u1");
    expect(adminPath("/o/acme", "server/backups")).toBe("/server/backups");
    expect(adminPath(null, "people")).toBe("/server");
  });

  it("an org reference matches the user's own orgs only (slug, or id), never anyone else's", () => {
    const orgs = [{ id: "8b1e5c1a-0c4b-4b8e-9a77-2f2d7a1c0e11", slug: "acme" }, { id: "1a2b3c4d-0000-4000-8000-000000000000", slug: "beta" }];
    expect(findOrg(orgs, "acme")).toBe(orgs[0]);
    expect(findOrg(orgs, "1A2B3C4D-0000-4000-8000-000000000000")).toBe(orgs[1]);
    expect(findOrg(orgs, "gamma")).toBeUndefined();
    expect(spaceOf("/settings/account")).toBeUndefined();
    expect(spaceOf("/p/trash")).toEqual(P);
    const full = orgs.map((o) => ({ ...o, name: o.slug, role: "member" as const, isDefault: false }));
    expect(wantedSpace("/p/vault", full)).toBeNull();
    expect(wantedSpace("/o/beta/shared", full)).toBe(full[1]);
    expect(wantedSpace("/o/gamma/vault", full)).toBe("unknown");
    expect(wantedSpace("/server/backups", full)).toBeUndefined();
  });
});
