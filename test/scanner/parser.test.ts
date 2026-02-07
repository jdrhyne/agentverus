import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseSkill } from "../../src/scanner/parser.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string): string {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("parseSkill", () => {
	it("should parse OpenClaw format with YAML frontmatter", () => {
		const content = loadFixture("safe-basic.md");
		const result = parseSkill(content);

		expect(result.format).toBe("openclaw");
		expect(result.name).toBe("Weather Checker");
		expect(result.description).toContain("weather");
		expect(result.tools).toContain("fetch");
		expect(result.permissions).toContain("network_restricted");
		expect(result.permissions).toContain("read");
	});

	it("should parse Claude Code format with ## headings", () => {
		const content = loadFixture("safe-complex.md");
		const result = parseSkill(content);

		expect(result.format).toBe("claude");
		expect(result.name).toBeDefined();
		expect(result.rawSections).toHaveProperty("Description");
		expect(result.rawSections).toHaveProperty("Tools");
	});

	it("should parse OpenClaw format with dependencies", () => {
		const content = loadFixture("openclaw-format.md");
		const result = parseSkill(content);

		expect(result.format).toBe("openclaw");
		expect(result.name).toBe("API Documentation Generator");
		expect(result.permissions.length).toBeGreaterThan(0);
	});

	it("should extract URLs from content", () => {
		const content = loadFixture("suspicious-urls.md");
		const result = parseSkill(content);

		expect(result.urls.length).toBeGreaterThan(3);
		expect(result.urls.some((u) => u.includes("github.com"))).toBe(true);
		expect(result.urls.some((u) => u.includes("pastebin.com"))).toBe(true);
	});

	it("should extract many permissions from excessive-permissions fixture", () => {
		const content = loadFixture("excessive-permissions.md");
		const result = parseSkill(content);

		expect(result.permissions.length).toBeGreaterThan(5);
		expect(result.tools.length).toBeGreaterThan(3);
	});

	it("should parse malicious files without crashing", () => {
		const files = [
			"malicious-exfiltration.md",
			"malicious-injection.md",
			"malicious-escalation.md",
		];

		for (const file of files) {
			const content = loadFixture(file);
			const result = parseSkill(content);
			expect(result.name).toBeTruthy();
			expect(result.rawContent).toBe(content);
		}
	});

	it("should add warning when description is missing", () => {
		const content = "Just text";
		const result = parseSkill(content);

		expect(result.format).toBe("generic");
		expect(result.warnings.length).toBeGreaterThan(0);
	});

	it("should handle empty content gracefully", () => {
		const result = parseSkill("");
		expect(result.name).toBeTruthy();
		expect(result.format).toBe("generic");
	});
});
