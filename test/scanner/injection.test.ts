import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseSkill } from "../../src/scanner/parser.js";
import { analyzeInjection } from "../../src/scanner/analyzers/injection.js";
import { analyzeBehavioral } from "../../src/scanner/analyzers/behavioral.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzeInjection", () => {
	it("should score safe-basic skill above 95", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeInjection(skill);

		expect(result.score).toBeGreaterThanOrEqual(95);
		expect(result.weight).toBe(0.3);
	});

	it("should score safe-complex skill above 95", async () => {
		const skill = parseSkill(loadFixture("safe-complex.md"));
		const result = await analyzeInjection(skill);

		expect(result.score).toBeGreaterThanOrEqual(95);
	});

	it("should score malicious-injection below 30", async () => {
		const skill = parseSkill(loadFixture("malicious-injection.md"));
		const result = await analyzeInjection(skill);

		expect(result.score).toBeLessThan(30);
		expect(result.findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("should detect instruction override in malicious-injection", async () => {
		const skill = parseSkill(loadFixture("malicious-injection.md"));
		const result = await analyzeInjection(skill);

		const overrideFindings = result.findings.filter(
			(f) => f.owaspCategory === "ASST-01",
		);
		expect(overrideFindings.length).toBeGreaterThan(0);
	});

	it("should detect HTML comment injection in malicious-exfiltration", async () => {
		const skill = parseSkill(loadFixture("malicious-exfiltration.md"));
		const result = await analyzeInjection(skill);

		expect(result.score).toBeLessThan(50);
		const commentFindings = result.findings.filter(
			(f) => f.id.includes("COMMENT"),
		);
		expect(commentFindings.length).toBeGreaterThan(0);
	});

	it("should detect prompt injection relay markers", async () => {
		const skill = parseSkill(loadFixture("malicious-injection.md"));
		const result = await analyzeInjection(skill);

		const relayFindings = result.findings.filter(
			(f) => f.owaspCategory === "ASST-06",
		);
		expect(relayFindings.length).toBeGreaterThan(0);
	});

	it("should detect social engineering patterns", async () => {
		const skill = parseSkill(loadFixture("malicious-injection.md"));
		const result = await analyzeInjection(skill);

		const socialFindings = result.findings.filter(
			(f) => f.owaspCategory === "ASST-07",
		);
		expect(socialFindings.length).toBeGreaterThan(0);
	});

	it("should detect prerequisite trap", async () => {
		const skill = parseSkill(loadFixture("concealment-skill.md"));
		const result = await analyzeBehavioral(skill);

		const trapFindings = result.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("suspicious install") ||
				f.title.toLowerCase().includes("download and execute"),
		);
		expect(trapFindings.length).toBeGreaterThan(0);
	});

	it("should detect concealment directives", async () => {
		const skill = parseSkill(loadFixture("concealment-skill.md"));
		const result = await analyzeInjection(skill);

		const concealmentFindings = result.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("concealment") ||
				f.description.toLowerCase().includes("concealment"),
		);
		expect(concealmentFindings.length).toBeGreaterThan(0);
	});

	it("should not flag openclaw-format skill", async () => {
		const skill = parseSkill(loadFixture("openclaw-format.md"));
		const result = await analyzeInjection(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
	});
});
