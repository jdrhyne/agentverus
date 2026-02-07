import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseSkill } from "../../src/scanner/parser.js";
import { analyzePermissions } from "../../src/scanner/analyzers/permissions.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzePermissions", () => {
	it("should score safe-basic skill above 90", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
		expect(result.weight).toBe(0.25);
		expect(result.findings.every((f) => f.severity !== "critical")).toBe(true);
	});

	it("should score safe-complex skill above 85", async () => {
		const skill = parseSkill(loadFixture("safe-complex.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeGreaterThanOrEqual(85);
	});

	it("should score excessive-permissions below 70", async () => {
		const skill = parseSkill(loadFixture("excessive-permissions.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeLessThan(70);
		expect(result.findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("should score malicious-escalation below 50", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeLessThan(50);
		expect(result.findings.length).toBeGreaterThan(3);
	});

	it("should detect permission-purpose mismatch", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzePermissions(skill);

		const mismatchFindings = result.findings.filter(
			(f) => f.id.includes("MISMATCH"),
		);
		expect(mismatchFindings.length).toBeGreaterThan(0);
	});

	it("should return weight of 0.25", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzePermissions(skill);
		expect(result.weight).toBe(0.25);
	});
});
