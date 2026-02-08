import { existsSync, readFileSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
	type ShieldsEndpoint,
	buildRepoCertifiedEndpoint,
	buildRepoCertifiedPercentEndpoint,
	buildSkillBadgeEndpoint,
	slugForTarget,
	writeBadgeBundle,
} from "../../src/scanner/badges.js";
import { scanSkill } from "../../src/scanner/index.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

const tmpDirs: string[] = [];

function tmpDir(): string {
	const dir = join(os.tmpdir(), `av-badges-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of tmpDirs) {
		await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
	tmpDirs.length = 0;
});

describe("badges", () => {
	it("should generate CERTIFIED repo badge only when all skills are certified", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const reports = [{ target: "skills/safe/SKILL.md", report: safe }];

		const repoCertified = buildRepoCertifiedEndpoint(reports, []);
		expect(repoCertified.message).toBe("CERTIFIED");
		expect(repoCertified.color).toBe("brightgreen");

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, []);
		expect(repoPct.message).toBe("Certified 100%");
		expect(repoPct.color).toBe("brightgreen");
	});

	it("should mark repo NOT CERTIFIED and compute percent when some skills are not certified", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const bad = await scanSkill(loadFixture("malicious-injection.md"));

		const reports = [
			{ target: "skills/good/SKILL.md", report: safe },
			{ target: "skills/bad/SKILL.md", report: bad },
		];

		const repoCertified = buildRepoCertifiedEndpoint(reports, []);
		expect(repoCertified.message).toBe("NOT CERTIFIED");
		expect(repoCertified.color).toBe("red");

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, []);
		expect(repoPct.message).toBe("Certified 50%");
		expect(repoPct.color).toBe("yellow");
	});

	it("should show Scan failed for repo percent badge when failures exist", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const reports = [{ target: "skills/safe/SKILL.md", report: safe }];

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, [
			{ target: "skills/unknown/SKILL.md", error: "boom" },
		]);
		expect(repoPct.message).toBe("Scan failed");
		expect(repoPct.color).toBe("red");
	});

	it("should show consistent No skills found for both repo badges when no skills exist", () => {
		const repoCertified = buildRepoCertifiedEndpoint([], []);
		expect(repoCertified.message).toBe("No skills found");
		expect(repoCertified.color).toBe("lightgrey");

		const repoPct = buildRepoCertifiedPercentEndpoint([], []);
		expect(repoPct.message).toBe("No skills found");
		expect(repoPct.color).toBe("lightgrey");
	});

	it("should generate per-skill endpoint badge", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const ep = buildSkillBadgeEndpoint({ target: "skills/safe/SKILL.md", report: safe });
		expect(ep.label).toBe("AgentVerus");
		expect(ep.message.startsWith("CERTIFIED")).toBe(true);
	});

	it("should not produce slug collisions for space vs slash paths", () => {
		const withSpace = slugForTarget("skills/my skill/SKILL.md");
		const withSlash = slugForTarget("skills/my/skill/SKILL.md");
		expect(withSpace).not.toBe(withSlash);
	});

	it("should slugify targets in a stable way", () => {
		expect(slugForTarget("skills/web-search/SKILL.md")).toBe("skills--web-search--SKILL.md");
		expect(slugForTarget("skills\\web-search\\SKILL.md")).toBe("skills--web-search--SKILL.md");
	});

	it("should default cacheSeconds to 3600 when not provided", () => {
		const ep = buildRepoCertifiedEndpoint([], []);
		expect(ep.cacheSeconds).toBe(3600);
	});

	it("should use provided cacheSeconds when specified", () => {
		const ep = buildRepoCertifiedEndpoint([], [], { label: "Test", cacheSeconds: 600 });
		expect(ep.cacheSeconds).toBe(600);
	});

	it("should write all badge files to disk (writeBadgeBundle integration)", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const bad = await scanSkill(loadFixture("malicious-injection.md"));

		const reports = [
			{ target: "skills/good/SKILL.md", report: safe },
			{ target: "skills/bad/SKILL.md", report: bad },
		];
		const failures = [{ target: "skills/broken/SKILL.md", error: "fetch failed" }];

		const outDir = tmpDir();
		await mkdir(outDir, { recursive: true });

		const index = await writeBadgeBundle(reports, failures, outDir);

		// Repo badges exist and are valid JSON
		const repoCertifiedPath = join(outDir, "repo-certified.json");
		const repoPctPath = join(outDir, "repo-certified-pct.json");
		expect(existsSync(repoCertifiedPath)).toBe(true);
		expect(existsSync(repoPctPath)).toBe(true);

		const repoCertified: ShieldsEndpoint = JSON.parse(readFileSync(repoCertifiedPath, "utf-8"));
		expect(repoCertified.schemaVersion).toBe(1);
		expect(repoCertified.message).toBe("NOT CERTIFIED");

		const repoPct: ShieldsEndpoint = JSON.parse(readFileSync(repoPctPath, "utf-8"));
		expect(repoPct.message).toBe("Scan failed");

		// Per-skill badges exist
		for (const skill of index.skills) {
			const skillPath = join(outDir, "skills", `${skill.slug}.json`);
			expect(existsSync(skillPath)).toBe(true);
			const parsed: ShieldsEndpoint = JSON.parse(readFileSync(skillPath, "utf-8"));
			expect(parsed.schemaVersion).toBe(1);
			expect(parsed.label).toBe("AgentVerus");
		}

		// Index file exists and matches return value
		const indexPath = join(outDir, "skills", "index.json");
		expect(existsSync(indexPath)).toBe(true);
		const parsedIndex = JSON.parse(readFileSync(indexPath, "utf-8"));
		expect(parsedIndex.totalSkills).toBe(2);
		expect(parsedIndex.failures).toHaveLength(1);
		expect(parsedIndex.skills).toHaveLength(2);

		// Return value matches
		expect(index.totalSkills).toBe(2);
		expect(index.certifiedSkills).toBe(1);
		expect(index.percentCertified).toBe(50);
	});
});
