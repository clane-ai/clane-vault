import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AGENT_PROMPT, SKILL_INSTALL } from "./agents";

const root = path.resolve(import.meta.dirname, "../../../../..");
const SKILL = readFileSync(path.join(root, "skills/clane-vault/SKILL.md"), "utf8").replace(/\r\n/g, "\n");

describe("the Clane Vault agent skill (spec §11)", () => {
  it("its rules in short are the Connect sheet's instructions, character for character", () => {
    const short = SKILL.split("\n## The rules in short\n\n")[1]!.split("\n\n## ")[0]!;
    expect(short).toBe(AGENT_PROMPT);
    expect(AGENT_PROMPT.length).toBeLessThanOrEqual(1500);
    expect(AGENT_PROMPT.split("\n")).toHaveLength(7);
  });

  it("is a valid skill: name, a one-line description, under 500 lines; the docs give its install command", () => {
    const [, name, description] = SKILL.match(/^---\nname: (.+)\ndescription: (.+)\n---\n/)!;
    expect(name).toBe("clane-vault");
    expect(description!.length).toBeLessThanOrEqual(1024);
    expect(SKILL.split("\n").length).toBeLessThanOrEqual(500);
    expect(SKILL).toContain("## Reading a value (personal agents)");
    expect(readFileSync(path.join(root, "docs/agents.md"), "utf8")).toContain(SKILL_INSTALL);
  });
});
