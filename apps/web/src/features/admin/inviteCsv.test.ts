import { describe, expect, it } from "vitest";
import { parseCsv, rowsFromCsv, rowsFromPaste } from "./inviteCsv";

describe("invite input parsing", () => {
  it("splits pasted addresses on commas, semicolons, spaces and new lines, with display names", () => {
    expect(rowsFromPaste("ann@acme.com, bob@acme.com\n\ncara@acme.com;dan@acme.com eve@acme.com\r\n\"Fay Example\" <fay@acme.com>")).toEqual([
      { email: "ann@acme.com" }, { email: "bob@acme.com" }, { email: "cara@acme.com" }, { email: "dan@acme.com" }, { email: "eve@acme.com" },
      { email: "fay@acme.com", name: "Fay Example" },
    ]);
    expect(rowsFromPaste("  \n , ")).toEqual([]);
  });

  it("parses quoted CSV cells", () => {
    expect(parseCsv('a,"b, c","say ""hi"""\r\n\r\nx,,y\n')).toEqual([["a", "b, c", 'say "hi"'], ["x", "", "y"]]);
  });

  it("reads a CSV with a header in any order, or by position without one", () => {
    expect(rowsFromCsv("Name,Email,Groups,Role\nAnn,ann@acme.com,Engineering;Ops,admin\n,bob@acme.com,,\n")).toEqual([
      { name: "Ann", email: "ann@acme.com", groups: "Engineering;Ops", role: "admin" }, { email: "bob@acme.com" },
    ]);
    expect(rowsFromCsv("﻿ann@acme.com,Ann,member,Sales\nbob@acme.com\n")).toEqual([{ email: "ann@acme.com", name: "Ann", role: "member", groups: "Sales" }, { email: "bob@acme.com" }]);
  });
});
