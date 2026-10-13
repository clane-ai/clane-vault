import { describe, expect, it } from "vitest";
import { strToU8, zipSync } from "fflate";
import { normalizeRecordBody } from "@clane-vault/crypto";
import { folderCounts, guessMapping, ImportFormatError, parseCsv, parseImport as parseRaw, parseImportFile as parseFileRaw, parseMappedCsv, totpSecretFrom, UnrecognisedCsvError, type ParseResult } from "./parsers";

/** Every parsed item must be a body the vault accepts (encrypt would refuse it otherwise). */
const valid = (r: ParseResult) => { for (const it of r.items) expect(() => normalizeRecordBody(it.body), it.body.title).not.toThrow(); return r; };
const parseImport = (t: string) => valid(parseRaw(t));
const parseImportFile = (b: Uint8Array) => valid(parseFileRaw(b));

const SECRET = "JBSWY3DPEHPK3PXP";

describe("csv", () => {
  it("handles quotes, doubled quotes, embedded newlines, CRLF and BOM", () => {
    expect(parseCsv('﻿a,b\r\n"x, y","say ""hi"""\n"line1\nline2",\n')).toEqual([["a", "b"], ["x, y", 'say "hi"'], ["line1\nline2", ""]]);
  });
  it("rejects an unclosed quote", () => {
    expect(() => parseCsv('a,"b')).toThrow(ImportFormatError);
  });
});

describe("totp", () => {
  it("takes the secret from an otpauth URI or a bare secret", () => {
    expect(totpSecretFrom(`otpauth://totp/Acme:ops?secret=${SECRET}&issuer=Acme`)).toBe(SECRET);
    expect(totpSecretFrom("jbsw y3dp ehpk 3pxp")).toBe(SECRET);
    expect(totpSecretFrom("not a secret!")).toBeNull();
    expect(totpSecretFrom("")).toBeNull();
  });
});

describe("Keeper JSON", () => {
  const file = JSON.stringify({
    shared_folders: [],
    records: [
      { title: "Figma", login: "design@clane.ai", password: "figma123", login_url: "https://figma.com", notes: "team", folders: [{ folder: "Design" }], custom_fields: { "TFC:Keeper": `otpauth://totp/Figma?secret=${SECRET}`, "Account ID": "42" } },
      { title: "AWS root", login: "ops@clane.ai", password: "x", folders: [{ shared_folder: "Infra", folder: "Cloud" }] },
      { title: "Wi-Fi", notes: "PSK: hunter22" },
      { title: "", login: "nobody" },
      { title: "Empty" },
    ],
  });
  it("maps fields, folders, TOTP and custom fields; skips rows with a reason", () => {
    const r = parseImport(file);
    expect(r.format).toBe("keeper-json");
    expect(r.items).toHaveLength(3);
    expect(r.items[0]).toEqual({ folder: "Design", body: { type: "login", title: "Figma", username: "design@clane.ai", password: "figma123", url: "https://figma.com", totpSecret: SECRET, notes: "team",
      fields: [{ id: "f1", label: "Account ID", kind: "text", value: "42" }] } });
    expect(r.items[1]!.folder).toBe("Infra / Cloud");
    expect(r.items[2]).toEqual({ folder: null, body: { type: "note", title: "Wi-Fi", notes: "PSK: hunter22" } });
    expect(r.skipped).toEqual([{ row: 4, reason: "No title" }, { row: 5, title: "Empty", reason: "Nothing to import" }]);
    expect(folderCounts(r.items)).toEqual([{ folder: "Design", count: 1 }, { folder: "Infra / Cloud", count: 1 }, { folder: null, count: 1 }]);
  });
  it("uses the website as the title when the title is missing", () => {
    const r = parseImport(JSON.stringify({ records: [{ login: "a", password: "b", login_url: "https://app.example.com/login" }] }));
    expect(r.items[0]!.body.title).toBe("app.example.com");
  });
});

describe("Keeper CSV", () => {
  it("reads headerless rows with shared folder and custom field pairs", () => {
    const csv = [
      `Design,Figma,design@clane.ai,figma123,https://figma.com,team,,TFC:Keeper,otpauth://totp/F?secret=${SECRET}`,
      `Cloud,AWS root,ops@clane.ai,"p,w",console.aws.amazon.com,"multi\nline",Infra`,
      `,Note only,,,,remember this`,
    ].join("\n");
    const r = parseImport(csv);
    expect(r.format).toBe("keeper-csv");
    expect(r.items[0]).toEqual({ folder: "Design", body: { type: "login", title: "Figma", username: "design@clane.ai", password: "figma123", url: "https://figma.com", totpSecret: SECRET, notes: "team" } });
    expect(r.items[1]).toMatchObject({ folder: "Infra / Cloud", body: { password: "p,w", notes: "multi\nline" } });
    expect(r.items[2]).toEqual({ folder: null, body: { type: "note", title: "Note only", notes: "remember this" } });
  });
  it("accepts a header row", () => {
    const r = parseImport("folder,title,login,password,website,notes\nOps,VPN,me,pw,vpn.example.com,");
    expect(r.format).toBe("keeper-csv");
    expect(r.items).toEqual([{ folder: "Ops", body: { type: "login", title: "VPN", username: "me", password: "pw", url: "vpn.example.com" } }]);
  });
});

describe("Bitwarden", () => {
  it("CSV: maps columns, folders, notes and fields; skips unsupported types", () => {
    const csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
      `Work,,login,GitHub,,"PIN: 1234",0,https://github.com,dev,gh-pass,${SECRET}\n` +
      ",,note,Alarm code,4321,,0,,,,\n" +
      ",,card,Visa,,,0,,,,\n";
    const r = parseImport(csv);
    expect(r.format).toBe("bitwarden-csv");
    expect(r.items).toEqual([
      { folder: "Work", body: { type: "login", title: "GitHub", username: "dev", password: "gh-pass", url: "https://github.com", totpSecret: SECRET, fields: [{ id: "f1", label: "PIN", kind: "secret", value: "1234" }] } },
      { folder: null, body: { type: "note", title: "Alarm code", notes: "4321" } },
    ]);
    expect(r.skipped).toEqual([{ row: 4, reason: "Card items aren't in Bitwarden's CSV export: export as JSON to import them" }]);
  });
  it("JSON: maps folders by id and refuses encrypted exports", () => {
    const r = parseImport(JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Work" }], items: [
      { type: 1, name: "GitHub", folderId: "f1", login: { username: "dev", password: "pw", totp: `otpauth://totp/x?secret=${SECRET}`, uris: [{ uri: "https://github.com" }] } },
      { type: 2, name: "Note", notes: "text", folderId: null },
      { type: 3, name: "Visa", card: { cardholderName: "Ada Lovelace", brand: "Visa", number: "4242 4242 4242 4242", expMonth: "7", expYear: "2029", code: "123" } },
      { type: 7, name: "Future item" },
    ] }));
    expect(r.format).toBe("bitwarden-json");
    expect(r.items[0]).toEqual({ folder: "Work", body: { type: "login", title: "GitHub", username: "dev", password: "pw", url: "https://github.com", totpSecret: SECRET } });
    expect(r.items[1]!.body).toEqual({ type: "note", title: "Note", notes: "text" });
    expect(r.items[2]!.body).toEqual({ type: "card", title: "Visa", data: { cardholder: "Ada Lovelace", number: "4242424242424242", expiry: "07/29", cvv: "123" } });
    expect(r.skipped).toEqual([{ row: 4, reason: "Unsupported item type" }]);
    expect(() => parseImport(JSON.stringify({ encrypted: true, encKeyValidation_DO_NOT_EDIT: "x" }))).toThrow(/encrypted/);
  });
});

describe("malformed input", () => {
  it("Keeper JSON: coerces numbers, skips non-objects, ignores bad folders and custom fields", () => {
    const r = parseImport(JSON.stringify({ records: [
      null, "text", 42,
      { title: 2024, login: 12345, password: 987654, folders: "Design", custom_fields: ["x"] },
      { title: "Bad folders", password: "p", folders: [null, { folder: 7 }] },
      { title: { nested: true }, password: "p" },
    ] }));
    expect(r.items[0]).toEqual({ folder: null, body: { type: "login", title: "2024", username: "12345", password: "987654" } });
    expect(r.items[1]).toEqual({ folder: null, body: { type: "login", title: "Bad folders", password: "p" } });
    expect(r.skipped).toEqual([
      { row: 1, reason: "Not a record" }, { row: 2, reason: "Not a record" }, { row: 3, reason: "Not a record" }, { row: 6, reason: "No title" },
    ]);
  });
  it("Bitwarden JSON: skips null items and survives broken folders, uris and fields", () => {
    const r = parseImport(JSON.stringify({ folders: [null, { id: 3 }, { id: "f1", name: "Work" }], items: [
      null,
      { type: 1, name: "A", folderId: "f1", login: { username: 5, password: null, uris: "nope", totp: 123 }, fields: [null, { name: "k", value: 1 }] },
      { type: 1, name: "B", login: "broken", fields: "x" },
    ] }));
    expect(r.skipped).toEqual([{ row: 1, reason: "Not an item" }, { row: 3, title: "B", reason: "Nothing to import" }]);
    expect(r.items).toEqual([{ folder: "Work", body: { type: "login", title: "A", username: "5", notes: "2FA (not recognised): 123", fields: [{ id: "f1", label: "k", kind: "text", value: "1" }] } }]);
  });
});

describe("Chrome / Edge CSV", () => {
  it("maps name,url,username,password,note and keeps a bad TOTP-free row", () => {
    const r = parseImport("name,url,username,password,note\nexample.com,https://example.com/,me@x.ie,pw1,\n,https://nameless.example.org/a,u,p,hi\n");
    expect(r.format).toBe("chrome-csv");
    expect(r.items).toEqual([
      { folder: null, body: { type: "login", title: "example.com", username: "me@x.ie", password: "pw1", url: "https://example.com/" } },
      { folder: null, body: { type: "login", title: "nameless.example.org", username: "u", password: "p", url: "https://nameless.example.org/a", notes: "hi" } },
    ]);
  });
});

describe("detection", () => {
  it("explains files it can't read", () => {
    expect(() => parseImport("")).toThrow(/empty/);
    expect(() => parseImport("{ nope")).toThrow(/JSON/);
    expect(() => parseImport(JSON.stringify({ foo: 1 }))).toThrow(/isn't a Keeper, Bitwarden or 1Password/);
    expect(() => parseImport("a,b\nc")).toThrow(/Unrecognised format/);
  });
  it("does not read another exporter's header row as Keeper data", () => {
    // Some other exporter's header: refused rather than imported as a record titled "website".
    expect(() => parseImport("account,website,user,pass,comment\nX,https://x.ie,me,pw,")).toThrow(/Unrecognised format/);
  });
});

describe("LastPass CSV", () => {
  // LastPass → Advanced options → Export: url,username,password,totp,extra,name,grouping,fav; secure notes have url http://sn.
  const csv = "url,username,password,totp,extra,name,grouping,fav\r\n" +
    `https://github.com/login,dev@clane.ai,gh-pass,${SECRET},recovery codes in safe,GitHub,Work\\Dev,1\r\n` +
    "https://mail.example.com,me,pw,,,Mail,(none),0\r\n" +
    'http://sn,,,,"NoteType:Server\nHostname:db1\nUsername:root",DB server,Shared-Infra,0\r\n' +
    "http://sn,,,,,Empty note,,0\r\n";
  it("maps columns, nested groups, TOTP and secure notes", () => {
    const r = parseImport(csv);
    expect(r.format).toBe("lastpass-csv");
    expect(r.items).toEqual([
      { folder: "Work / Dev", body: { type: "login", title: "GitHub", username: "dev@clane.ai", password: "gh-pass", url: "https://github.com/login", totpSecret: SECRET, notes: "recovery codes in safe" } },
      { folder: null, body: { type: "login", title: "Mail", username: "me", password: "pw", url: "https://mail.example.com" } },
      { folder: "Shared-Infra", body: { type: "server", title: "DB server", username: "root", data: { hostname: "db1" } } },
    ]);
    expect(r.skipped).toEqual([{ row: 5, title: "Empty note", reason: "Nothing to import" }]);
  });
});

describe("Zoho Vault CSV", () => {
  // Zoho Vault → Tools → Export Secrets → CSV. Username and password live inside SecretData as "Name:value" lines.
  const csv = "Password Name,Description,Password URL,SecretData,Notes,CustomData,Tags,Classification,Favorite,TOTP,Folder Name\n" +
    `Salesforce,CRM admin,https://login.salesforce.com,"SecretType:Web Account\nUser Name:ops@clane.ai\nPassword:sf:pa55",rotate quarterly,"PIN:4321",crm,P,1,otpauth://totp/SF?secret=${SECRET},Sales\n` +
    `Router,,,"SecretType:Unix\nusername:admin\npassword:r0uter",,,,P,0,,\n` +
    ",,,,,,,,,,\n";
  it("reads SecretData and CustomData lines, TOTP, folder and description", () => {
    const r = parseImport(csv);
    expect(r.format).toBe("zoho-csv");
    expect(r.items).toEqual([
      { folder: "Sales", body: { type: "login", title: "Salesforce", username: "ops@clane.ai", password: "sf:pa55", url: "https://login.salesforce.com", totpSecret: SECRET, notes: "CRM admin\n\nrotate quarterly", fields: [{ id: "f1", label: "PIN", kind: "secret", value: "4321" }] } },
      { folder: null, body: { type: "login", title: "Router", username: "admin", password: "r0uter" } },
    ]);
  });
});

describe("Dashlane CSV", () => {
  it("credentials: username, title, url, note, category as folder, otpSecret or otpUrl", () => {
    const csv = "username,username2,username3,title,password,note,url,category,otpSecret\n" +
      `dev@clane.ai,,,GitHub,gh-pass,backup codes in safe,https://github.com,Work,${SECRET}\n` +
      "me,,,Netflix,nf,,netflix.com,,\n";
    const r = parseImport(csv);
    expect(r.format).toBe("dashlane-csv");
    expect(r.items).toEqual([
      { folder: "Work", body: { type: "login", title: "GitHub", username: "dev@clane.ai", password: "gh-pass", url: "https://github.com", totpSecret: SECRET, notes: "backup codes in safe" } },
      { folder: null, body: { type: "login", title: "Netflix", username: "me", password: "nf", url: "netflix.com" } },
    ]);
    const r2 = parseImport(`username,username2,username3,title,password,note,url,category,otpUrl\nu,,,T,p,,,,otpauth://totp/T?secret=${SECRET}\n`);
    expect(r2.items[0]!.body).toMatchObject({ totpSecret: SECRET });
  });
  it("secure notes file", () => {
    const r = parseImport('title,note\nAlarm,"code 4321\nfront door"\n');
    expect(r.format).toBe("dashlane-csv");
    expect(r.items).toEqual([{ folder: null, body: { type: "note", title: "Alarm", notes: "code 4321\nfront door" } }]);
  });
});

describe("1Password", () => {
  it("CSV (1Password 8): Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes", () => {
    const csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n" +
      `GitHub,https://github.com,dev,gh-pass,otpauth://totp/GitHub:dev?secret=${SECRET}&issuer=GitHub,true,false,work,codes in safe\n` +
      "Wi-Fi,,,,,false,false,,PSK: hunter22\n";
    const r = parseImport(csv);
    expect(r.format).toBe("1password-csv");
    expect(r.items).toEqual([
      { folder: null, body: { type: "login", title: "GitHub", username: "dev", password: "gh-pass", url: "https://github.com", totpSecret: SECRET, notes: "codes in safe" } },
      { folder: null, body: { type: "note", title: "Wi-Fi", notes: "PSK: hunter22" } },
    ]);
  });

  const exportData = {
    accounts: [{ attrs: { accountName: "Clane", name: "Sara", email: "sara@clane.ai", uuid: "A1", domain: "https://clane.1password.eu/" }, vaults: [
      { attrs: { uuid: "v1", desc: "", avatar: "", name: "Private", type: "P" }, items: [
        { uuid: "i1", favIndex: 1, createdAt: 1700000000, updatedAt: 1700000000, state: "active", categoryUuid: "001",
          details: { loginFields: [
            { value: "dev@clane.ai", id: "", name: "email", fieldType: "E", designation: "username" },
            { value: "gh-pass", id: "", name: "password", fieldType: "P", designation: "password" },
          ], notesPlain: "codes in safe", sections: [
            { title: "", name: "add more", fields: [{ title: "one-time password", id: "TOTP_1", value: { totp: `otpauth://totp/GitHub?secret=${SECRET}` } }] },
            { title: "Extra", name: "s2", fields: [{ title: "PIN", id: "p", value: { concealed: "4321" } }, { title: "Recovery email", id: "e", value: { email: { email_address: "r@clane.ai", provider: null } } }] },
          ], passwordHistory: [] },
          overview: { subtitle: "dev@clane.ai", urls: [{ label: "website", url: "https://github.com/login" }], title: "GitHub", url: "https://github.com/login", tags: ["work"] } },
        { uuid: "i2", state: "active", categoryUuid: "003", details: { loginFields: [], notesPlain: "PSK: hunter22", sections: [] }, overview: { title: "Wi-Fi" } },
        { uuid: "i3", state: "active", categoryUuid: "005", details: { password: "standalone-pw", sections: [] }, overview: { title: "Router" } },
        { uuid: "i4", state: "active", categoryUuid: "002", details: { sections: [{ title: "", fields: [
          { title: "cardholder name", id: "cardholder", value: { string: "Sara Smith" } }, { title: "number", id: "ccnum", value: { creditCardNumber: "4242424242424242" } },
          { title: "verification number", id: "cvv", value: { concealed: "321" } }, { title: "expiry date", id: "expiry", value: { monthYear: 202811 } },
          { title: "type", id: "type", value: { creditCardType: "visa" } }] }] }, overview: { title: "Visa" } },
        { uuid: "i5", state: "archived", categoryUuid: "001", details: { loginFields: [] }, overview: { title: "Old" } },
      ] },
      { attrs: { uuid: "v2", name: "Infra", type: "U" }, items: [
        { uuid: "i6", state: "active", categoryUuid: "001", details: { loginFields: [{ value: "root", designation: "username" }, { value: "aws-pw", designation: "password" }] }, overview: { title: "AWS", url: "console.aws.amazon.com" } },
      ] },
    ] }],
  };
  const expected = [
    { folder: "Private", body: { type: "login", title: "GitHub", username: "dev@clane.ai", password: "gh-pass", url: "https://github.com/login", totpSecret: SECRET, notes: "codes in safe",
      fields: [{ id: "f1", label: "PIN", kind: "secret", value: "4321" }, { id: "f2", label: "Recovery email", kind: "email", value: "r@clane.ai" }] } },
    { folder: "Private", body: { type: "note", title: "Wi-Fi", notes: "PSK: hunter22" } },
    { folder: "Private", body: { type: "login", title: "Router", password: "standalone-pw" } },
    { folder: "Private", body: { type: "card", title: "Visa", data: { cardholder: "Sara Smith", number: "4242424242424242", cvv: "321", expiry: "11/28" }, fields: [{ id: "f1", label: "type", kind: "text", value: "visa" }] } },
    { folder: "Infra", body: { type: "login", title: "AWS", username: "root", password: "aws-pw", url: "console.aws.amazon.com" } },
  ];

  it(".1pux: unzips export.data; vaults become folders; maps cards; skips archived items", () => {
    const zip = zipSync({ "export.attributes": strToU8('{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}'), "export.data": strToU8(JSON.stringify(exportData)) });
    const r = parseImportFile(zip);
    expect(r.format).toBe("1password-1pux");
    expect(r.items).toEqual(expected);
    expect(r.skipped).toEqual([{ row: 5, title: "Old", reason: "Archived" }]);
  });
  it("export.data JSON on its own, and a zip without export.data", () => {
    expect(parseImport(JSON.stringify(exportData)).items).toEqual(expected);
    expect(() => parseImportFile(zipSync({ "other.txt": strToU8("x") }))).toThrow(/1Password/);
  });
  it("hostile .1pux files: a huge declared export.data is refused before inflating; odd categories are just skipped", () => {
    const zip = zipSync({ "export.data": strToU8(JSON.stringify(exportData)) });
    // Patch the central directory's uncompressed size (offset 24 of the 0x02014b50 record) to 2 GB.
    const cd = zip.findIndex((_, i) => zip[i] === 0x50 && zip[i + 1] === 0x4b && zip[i + 2] === 0x01 && zip[i + 3] === 0x02);
    new DataView(zip.buffer, zip.byteOffset).setUint32(cd + 24, 0x7fffffff, true);
    expect(() => parseImportFile(zip)).toThrow(/too large/);
    const proto = { accounts: [{ vaults: [{ attrs: { name: "V" }, items: [{ categoryUuid: "__proto__", overview: { title: "X" } }, { categoryUuid: "constructor", overview: { title: "Y" } }] }] }] };
    expect(parseImport(JSON.stringify(proto)).skipped.map((s) => s.reason)).toEqual(["These items aren't supported", "These items aren't supported"]);
  });
  it("text files go through parseImportFile too", () => {
    expect(parseImportFile(strToU8("name,url,username,password\nX,https://x.ie,u,p\n")).format).toBe("chrome-csv");
  });
});

describe("generic CSV with column mapping", () => {
  const csv = "Account,Website,User,Pass,Comment,Group,2FA\nAcme,https://acme.io,ops,pw1,hello,Ops," + SECRET + "\n,https://b.example.com/x,u2,pw2,,,\n";
  it("an unknown header raises UnrecognisedCsvError with the rows", () => {
    let err: unknown;
    try { parseImport(csv); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(UnrecognisedCsvError);
    expect((err as UnrecognisedCsvError).rows[0]).toEqual(["Account", "Website", "User", "Pass", "Comment", "Group", "2FA"]);
  });
  it("guesses the mapping from header names", () => {
    expect(guessMapping(["Account", "Website", "User", "Pass", "Comment", "Group", "2FA"])).toEqual({ title: 0, url: 1, username: 2, password: 3, notes: 4, folder: 5, totp: 6 });
    expect(guessMapping(["foo", "bar"])).toEqual({});
  });
  it("parses with a mapping", () => {
    const rows = parseCsv(csv);
    const r = parseMappedCsv(rows, guessMapping(rows[0]!));
    expect(r.format).toBe("generic-csv");
    expect(r.items).toEqual([
      { folder: "Ops", body: { type: "login", title: "Acme", username: "ops", password: "pw1", url: "https://acme.io", totpSecret: SECRET, notes: "hello" } },
      { folder: null, body: { type: "login", title: "b.example.com", username: "u2", password: "pw2", url: "https://b.example.com/x" } },
    ]);
    expect(() => parseMappedCsv(rows, { notes: 4 })).toThrow(/title, password or website/);
  });
});

describe("record types", () => {
  const PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";

  it("Keeper JSON quick import maps typed records too (and custom fields with kinds)", () => {
    const r = parseImport(JSON.stringify({ records: [
      { title: "Prod DB", $type: "databaseCredentials", login: "app", password: "pw", custom_fields: { "$host::1": { hostName: "db1", port: "5432" }, "$text:type::1": "MySQL", "$url::1": "https://pgadmin.acme.test" } },
      { title: "Card", $type: "bankCard", custom_fields: { "$paymentCard::1": { cardNumber: "4111 1111 1111 1111", cardExpirationDate: "03/2031", cardSecurityCode: "999" }, "$securityQuestion::1": [{ question: "Pet?", answer: "Rex" }] } },
      { title: "Login", login: "u", password: "p", custom_fields: { "$oneTimeCode::1": [`otpauth://totp/a?secret=${SECRET}`, "otpauth://totp/b?secret=KRSXG5CTMVRXEZLU"], "$multiline:Recovery::1": "a\nb" } },
    ] }));
    expect(r.items.map((i) => i.body)).toEqual([
      { type: "database", title: "Prod DB", username: "app", password: "pw", data: { host: "db1", port: "5432", dbType: "mysql" }, fields: [{ id: "f1", label: "Website", kind: "url", value: "https://pgadmin.acme.test" }] },
      { type: "card", title: "Card", data: { number: "4111111111111111", expiry: "03/31", cvv: "999" },
        fields: [{ id: "f1", label: "Security question", kind: "text", value: "Pet?" }, { id: "f2", label: "Answer", kind: "secret", value: "Rex" }] },
      { type: "login", title: "Login", username: "u", password: "p", totpSecret: SECRET,
        fields: [{ id: "f1", label: "Recovery", kind: "multiline", value: "a\nb" }, { id: "f2", label: "One-time code", kind: "totp", value: "KRSXG5CTMVRXEZLU" }] },
    ]);
  });

  it("Keeper CSV: a $type pair makes a typed record", () => {
    const r = parseImport(`Infra,Bastion,deploy,,,,$type,sshKeys,$keyPair,"{}",$text:Notes,x\n`);
    expect(r.items[0]!.body.type).toBe("sshKey");
    const wifi = parseImport(`,Guest Wi-Fi,,wifi-pw,,,$type,wifiCredentials,$text:SSID,guest\n`);
    expect(wifi.items[0]!.body).toEqual({ type: "wifi", title: "Guest Wi-Fi", password: "wifi-pw", data: { ssid: "guest" } });
  });

  it("Bitwarden JSON: identities (document, contact, address), SSH keys, custom field kinds", () => {
    const r = parseImport(JSON.stringify({ items: [
      { type: 4, name: "Passport", identity: { firstName: "Ada", lastName: "Lovelace", passportNumber: "P123", email: "ada@x.ie" } },
      { type: 4, name: "Jane", identity: { firstName: "Jane", lastName: "Doe", company: "Acme", phone: "+353 1 555", city: "Dublin" } },
      { type: 4, name: "Home", identity: { address1: "1 Main St", city: "Dublin", postalCode: "D01", country: "IE" } },
      { type: 5, name: "Deploy key", sshKey: { privateKey: PEM, publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:abc" } },
      { type: 2, name: "Fields", notes: "n", fields: [{ name: "Shown", value: "a", type: 0 }, { name: "Hidden", value: "b", type: 1 }, { name: "Flag", value: "true", type: 2 }, { name: "Linked", value: null, type: 3 }] },
    ] }));
    expect(r.items.map((i) => i.body)).toEqual([
      { type: "identity", title: "Passport", data: { docType: "passport", fullName: "Ada Lovelace", number: "P123" }, fields: [{ id: "f1", label: "Email", kind: "email", value: "ada@x.ie" }] },
      { type: "contact", title: "Jane", data: { name: "Jane Doe", company: "Acme", phone: "+353 1 555" }, fields: [{ id: "f1", label: "Address", kind: "multiline", value: "Dublin" }] },
      { type: "address", title: "Home", data: { street1: "1 Main St", city: "Dublin", postcode: "D01", country: "IE" } },
      { type: "sshKey", title: "Deploy key", data: { privateKey: PEM, publicKey: "ssh-ed25519 AAAA" }, fields: [{ id: "f1", label: "Fingerprint", kind: "text", value: "SHA256:abc" }] },
      { type: "note", title: "Fields", notes: "n", fields: [
        { id: "f1", label: "Shown", kind: "text", value: "a" }, { id: "f2", label: "Hidden", kind: "secret", value: "b" }, { id: "f3", label: "Flag", kind: "text", value: "true" }] },
    ]);
  });

  it("LastPass typed secure notes: card, Wi-Fi, SSH key (multi-line key), passport; unknown note types stay notes", () => {
    const note = (t: string) => `"${t.replace(/"/g, '""')}"`;
    const csv = "url,username,password,totp,extra,name,grouping,fav\n" +
      `http://sn,,,,${note("NoteType:Credit Card\nLanguage:en-US\nName on Card:Ada\nType:Visa\nNumber:4242424242424242\nSecurity Code:123\nStart Date:,\nExpiration Date:June,2030\nNotes:line one\nline two")},Visa,,0\n` +
      `http://sn,,,,${note("NoteType:Wi-Fi Password\nSSID:office\nPassword:wifi-pw\nAuthentication:WPA2 Personal")},Wi-Fi,,0\n` +
      `http://sn,,,,${note(`NoteType:SSH Key\nPrivate Key:${PEM}\nPublic Key:ssh-ed25519 AAAA\nHostname:bastion\nPassphrase:pp`)},SSH,,0\n` +
      `http://sn,,,,${note("NoteType:Passport\nName:Ada Lovelace\nNumber:P1\nIssued Date:January,15,2020\nExpiration Date:January,15,2030\nNationality:Irish")},Passport,,0\n` +
      `http://sn,,,,${note("NoteType:Health Insurance\nCompany:X")},Insurance,,0\n`;
    const r = parseImport(csv);
    expect(r.items.map((i) => i.body)).toEqual([
      { type: "card", title: "Visa", data: { cardholder: "Ada", number: "4242424242424242", cvv: "123", expiry: "06/30" }, fields: [{ id: "f1", label: "Type", kind: "text", value: "Visa" }], notes: "line one\nline two" },
      { type: "wifi", title: "Wi-Fi", password: "wifi-pw", data: { ssid: "office", security: "wpa2" } },
      { type: "sshKey", title: "SSH", data: { privateKey: PEM, publicKey: "ssh-ed25519 AAAA", host: "bastion", passphrase: "pp" } },
      { type: "identity", title: "Passport", data: { docType: "passport", fullName: "Ada Lovelace", number: "P1", issueDate: "2020-01-15", expiryDate: "2030-01-15", nationality: "Irish" } },
      { type: "note", title: "Insurance", notes: "NoteType:Health Insurance\nCompany:X" },
    ]);
  });

  it("Dashlane payments and IDs exports", () => {
    const pay = parseImport("type,account_name,account_holder,cc_number,code,expiration_month,expiration_year,routing_number,account_number,country,issuing_bank\n" +
      "payment_card,Work card,Ada Lovelace,4242424242424242,123,9,2028,,,IE,\n" +
      "bank,Main account,Acme Ltd,,,,,AIBKIE2D,IE29AIBK93115212345678,IE,AIB\n");
    expect(pay.format).toBe("dashlane-csv");
    expect(pay.items.map((i) => i.body)).toEqual([
      { type: "card", title: "Work card", data: { cardholder: "Ada Lovelace", number: "4242424242424242", cvv: "123", expiry: "09/28" }, fields: [{ id: "f1", label: "Country", kind: "text", value: "IE" }] },
      { type: "bankAccount", title: "Main account", data: { accountName: "Acme Ltd", bank: "AIB", accountNumber: "IE29AIBK93115212345678", routing: "AIBKIE2D" }, fields: [{ id: "f1", label: "Country", kind: "text", value: "IE" }] },
    ]);
    const ids = parseImport("type,number,name,issue_date,expiration_date,place_of_issue,state\npassport,P99,Ada Lovelace,2020-02-01,2030-02-01,Dublin,\ndriver_license,DL1,Ada Lovelace,,2031-01-01,,Leinster\n");
    expect(ids.items.map((i) => i.body)).toEqual([
      { type: "identity", title: "Passport · Ada Lovelace", data: { docType: "passport", fullName: "Ada Lovelace", number: "P99", authority: "Dublin", issueDate: "2020-02-01", expiryDate: "2030-02-01" } },
      { type: "identity", title: "Driving licence · Ada Lovelace", data: { docType: "drivingLicence", fullName: "Ada Lovelace", number: "DL1", expiryDate: "2031-01-01" }, fields: [{ id: "f1", label: "State", kind: "text", value: "Leinster" }] },
    ]);
  });

  it("1Password categories map to record types; other categories are still skipped", () => {
    const item = (categoryUuid: string, title: string, fields: object[], extra: object = {}) => ({ uuid: title, state: "active", categoryUuid, overview: { title }, details: { sections: [{ title: "", fields }], ...extra } });
    const f = (id: string, value: object, title = id) => ({ id, title, value });
    const r = parseImport(JSON.stringify({ accounts: [{ vaults: [{ attrs: { name: "IT" }, items: [
      item("110", "Web 1", [f("url", { string: "web1.acme.test" }), f("username", { string: "root" }), f("password", { concealed: "srv-pw" })]),
      item("102", "DB", [f("database_type", { menu: "postgresql" }), f("hostname", { string: "db" }), f("port", { string: "5432" }), f("database", { string: "app" }), f("username", { string: "u" }), f("password", { concealed: "p" })]),
      item("109", "Router", [f("network_name", { string: "office" }), f("wireless_password", { concealed: "wpw" }), f("wireless_security", { menu: "wpa3" })]),
      item("100", "Office", [f("reg_code", { string: "KEY-1" }), f("reg_name", { string: "Acme" }), f("product_version", { string: "2024" }), f("order_date", { date: 1704067200 })]),
      item("106", "Passport", [f("fullname", { string: "Ada Lovelace" }), f("number", { string: "P1" }), f("expiry_date", { date: 1893456000 })]),
      item("103", "Licence", [f("fullname", { string: "Ada Lovelace" }), f("number", { string: "D1" }), f("expiry_date", { monthYear: 203001 })]),
      item("112", "Stripe", [f("credential", { concealed: "sk_live_x" }), f("username", { string: "key-id" }), f("hostname", { string: "https://api.stripe.com" }), f("expires", { date: 1893456000 })]),
      item("114", "Key", [f("private_key", { sshKey: { privateKey: PEM, metadata: { publicKey: "ssh-ed25519 AAAA" } } })]),
      item("105", "Gym", [f("org_name", { string: "FitCo" }), f("membership_no", { string: "M1" }), f("pin", { concealed: "1234" })]),
      item("004", "Jane", [f("firstname", { string: "Jane" }), f("lastname", { string: "Doe" }), f("company", { string: "Acme" }), f("cellphone", { phone: "+353 1" })]),
      item("101", "Bank", [f("bankName", { string: "AIB" }), f("owner", { string: "Acme" }), f("iban", { string: "IE29" }), f("swift", { string: "AIBKIE2D" })]),
      item("113", "Medical", []),
    ] }] }] }));
    expect(r.items.map((i) => i.body)).toEqual([
      { type: "server", title: "Web 1", username: "root", password: "srv-pw", data: { hostname: "web1.acme.test" } },
      { type: "database", title: "DB", username: "u", password: "p", data: { dbType: "postgresql", host: "db", port: "5432", database: "app" } },
      { type: "wifi", title: "Router", password: "wpw", data: { ssid: "office", security: "wpa3" } },
      { type: "softwareLicence", title: "Office", data: { licenceKey: "KEY-1", licensedTo: "Acme", version: "2024", purchaseDate: "2024-01-01" } },
      { type: "identity", title: "Passport", data: { docType: "passport", fullName: "Ada Lovelace", number: "P1", expiryDate: "2030-01-01" } },
      { type: "identity", title: "Licence", data: { docType: "drivingLicence", fullName: "Ada Lovelace", number: "D1", expiryDate: "2030-01-01" } },
      { type: "apiKey", title: "Stripe", data: { secret: "sk_live_x", keyId: "key-id", endpoint: "https://api.stripe.com" }, fields: [{ id: "f1", label: "expires", kind: "date", value: "2030-01-01" }] },
      { type: "sshKey", title: "Key", data: { privateKey: PEM, publicKey: "ssh-ed25519 AAAA" } },
      { type: "membership", title: "Gym", data: { organisation: "FitCo", memberId: "M1" }, fields: [{ id: "f1", label: "pin", kind: "secret", value: "1234" }] },
      { type: "contact", title: "Jane", data: { company: "Acme", phone: "+353 1", name: "Jane Doe" } },
      { type: "bankAccount", title: "Bank", data: { bank: "AIB", accountName: "Acme", accountNumber: "IE29", routing: "AIBKIE2D" } },
    ]);
    expect(r.skipped).toEqual([{ row: 12, title: "Medical", reason: "Medical records aren't supported" }]);
  });

  it("caps custom fields at 64; the rest go to the notes", () => {
    const custom = Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`F${i}`, `v${i}`]));
    const b = parseImport(JSON.stringify({ records: [{ title: "Many", login: "u", custom_fields: custom }] })).items[0]!.body;
    expect(b.fields).toHaveLength(64);
    expect(b.notes).toBe(Array.from({ length: 6 }, (_, i) => `F${64 + i}: v${64 + i}`).join("\n"));
  });
});
