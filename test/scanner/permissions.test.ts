import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeInjection } from "../../src/scanner/analyzers/injection.js";
import { analyzePermissions } from "../../src/scanner/analyzers/permissions.js";
import { parseSkill } from "../../src/scanner/parser.js";

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

		const mismatchFindings = result.findings.filter((f) => f.id.includes("MISMATCH"));
		expect(mismatchFindings.length).toBeGreaterThan(0);
	});

	it("should return weight of 0.25", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzePermissions(skill);
		expect(result.weight).toBe(0.25);
	});

	it("should not penalize declared credential access", async () => {
		const skill = parseSkill(loadFixture("declared-permissions.md"));
		const injResult = await analyzeInjection(skill);

		// Credential-related findings should be downgraded to info severity
		const credentialFindings = injResult.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("credential") ||
				f.evidence.toLowerCase().includes("api_key") ||
				f.evidence.toLowerCase().includes("nutrient_api_key"),
		);
		for (const f of credentialFindings) {
			expect(f.severity).toBe("info");
			expect(f.deduction).toBe(0);
		}
	});

	it("should penalize undeclared credential access", async () => {
		const skill = parseSkill(loadFixture("undeclared-permissions.md"));
		const injResult = await analyzeInjection(skill);

		// Credential findings should remain at original high severity
		const credentialFindings = injResult.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("credential") ||
				f.evidence.toLowerCase().includes("api_key") ||
				f.evidence.toLowerCase().includes("openai_api_key"),
		);
		expect(credentialFindings.length).toBeGreaterThan(0);
		expect(credentialFindings.some((f) => f.severity === "high")).toBe(true);
	});
});
