import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";
import { buildSarifLog } from "../../src/scanner/sarif.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("buildSarifLog", () => {
	it("should generate SARIF 2.1.0 output with results for findings", async () => {
		const report = await scanSkill(loadFixture("malicious-exfiltration.md"));
		const sarif = buildSarifLog([
			{
				target: "test/fixtures/skills/malicious-exfiltration.md",
				report,
			},
		]);

		expect(sarif.version).toBe("2.1.0");
		expect(sarif.runs.length).toBe(1);
		expect(sarif.runs[0]?.tool.driver.name).toBe("AgentVerus Scanner");
		expect((sarif.runs[0]?.results ?? []).length).toBeGreaterThan(0);

		const ruleIds = new Set((sarif.runs[0]?.results ?? []).map((r) => r.ruleId));
		expect(ruleIds.has("ASST-02") || ruleIds.has("ASST-01")).toBe(true);
	});

	it("should include scan failures as SARIF results", async () => {
		const report = await scanSkill(loadFixture("safe-basic.md"));
		const sarif = buildSarifLog(
			[
				{
					target: "test/fixtures/skills/safe-basic.md",
					report,
				},
			],
			[
				{
					target: "https://example.invalid/SKILL.md",
					error: "Failed to fetch",
				},
			],
		);

		const results = sarif.runs[0]?.results ?? [];
		expect(results.some((r) => r.ruleId === "AGENTVERUS-SCAN-ERROR")).toBe(true);
	});
});

