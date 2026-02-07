import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeContent } from "../../src/scanner/analyzers/content.js";
import { parseSkill } from "../../src/scanner/parser.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzeContent", () => {
	it("should score safe-basic skill above 90 (has safety boundaries + error handling)", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeContent(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
		expect(result.weight).toBe(0.1);
	});

	it("should award bonus for safety boundaries", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeContent(skill);

		const safetyFindings = result.findings.filter((f) => f.id === "CONT-SAFETY-GOOD");
		expect(safetyFindings.length).toBe(1);
	});

	it("should award bonus for output constraints", async () => {
		const skill = parseSkill(loadFixture("safe-complex.md"));
		const result = await analyzeContent(skill);

		const outputFindings = result.findings.filter((f) => f.id === "CONT-OUTPUT-GOOD");
		expect(outputFindings.length).toBe(1);
	});

	it("should award bonus for error handling instructions", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeContent(skill);

		const errorFindings = result.findings.filter((f) => f.id === "CONT-ERROR-GOOD");
		expect(errorFindings.length).toBe(1);
	});

	it("should penalize missing description", async () => {
		const skill = parseSkill("Just raw text");
		const result = await analyzeContent(skill);

		const descFindings = result.findings.filter((f) => f.id === "CONT-NO-DESC");
		expect(descFindings.length).toBe(1);
	});

	it("should detect base64 obfuscation", async () => {
		const skill = parseSkill(loadFixture("obfuscated-skill.md"));
		const result = await analyzeContent(skill);

		const b64Findings = result.findings.filter((f) => f.title.toLowerCase().includes("base64"));
		expect(b64Findings.length).toBeGreaterThan(0);
	});

	it("should detect hardcoded API keys", async () => {
		const skill = parseSkill(loadFixture("obfuscated-skill.md"));
		const result = await analyzeContent(skill);

		const keyFindings = result.findings.filter(
			(f) => f.title.toLowerCase().includes("api key") || f.title.toLowerCase().includes("secret"),
		);
		expect(keyFindings.length).toBeGreaterThan(0);
	});

	it("should note missing safety boundaries", async () => {
		const skill = parseSkill(loadFixture("excessive-permissions.md"));
		const result = await analyzeContent(skill);

		const noSafetyFindings = result.findings.filter((f) => f.id === "CONT-NO-SAFETY");
		expect(noSafetyFindings.length).toBe(1);
	});
});
