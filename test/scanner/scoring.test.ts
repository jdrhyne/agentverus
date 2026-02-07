import { describe, it, expect } from "vitest";
import { aggregateScores } from "../../src/scanner/scoring.js";
import type { Category, CategoryScore, ScanMetadata } from "../../src/scanner/types.js";

function makeCategoryScore(score: number, weight: number, overrides?: Partial<CategoryScore>): CategoryScore {
	return {
		score,
		weight,
		findings: overrides?.findings ?? [],
		summary: overrides?.summary ?? "Test summary",
	};
}

const metadata: ScanMetadata = {
	scannedAt: new Date("2026-02-06T00:00:00Z"),
	scannerVersion: "0.1.0",
	durationMs: 100,
	skillFormat: "openclaw",
};

describe("aggregateScores", () => {
	it("should calculate weighted overall score", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(100, 0.25),
			injection: makeCategoryScore(100, 0.3),
			dependencies: makeCategoryScore(100, 0.2),
			behavioral: makeCategoryScore(100, 0.15),
			content: makeCategoryScore(100, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBe(100);
		expect(report.badge).toBe("certified");
	});

	it("should return CERTIFIED for score 90+ with no critical/high", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.25),
			injection: makeCategoryScore(90, 0.3),
			dependencies: makeCategoryScore(95, 0.2),
			behavioral: makeCategoryScore(90, 0.15),
			content: makeCategoryScore(85, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeGreaterThanOrEqual(90);
		expect(report.badge).toBe("certified");
	});

	it("should return REJECTED for any critical finding regardless of score", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.25),
			injection: makeCategoryScore(95, 0.3, {
				findings: [{
					id: "TEST-CRIT",
					category: "injection",
					severity: "critical",
					title: "Critical test",
					description: "Test",
					evidence: "test",
					deduction: 5,
					recommendation: "fix",
					owaspCategory: "ASST-01",
				}],
			}),
			dependencies: makeCategoryScore(95, 0.2),
			behavioral: makeCategoryScore(95, 0.15),
			content: makeCategoryScore(95, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.badge).toBe("rejected");
	});

	it("should return REJECTED for score below 50", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(10, 0.25),
			injection: makeCategoryScore(20, 0.3),
			dependencies: makeCategoryScore(30, 0.2),
			behavioral: makeCategoryScore(40, 0.15),
			content: makeCategoryScore(50, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeLessThan(50);
		expect(report.badge).toBe("rejected");
	});

	it("should return CONDITIONAL for score 75-89 with ≤2 high findings", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(80, 0.25, {
				findings: [{
					id: "TEST-HIGH",
					category: "permissions",
					severity: "high",
					title: "High test",
					description: "Test",
					evidence: "test",
					deduction: 15,
					recommendation: "fix",
					owaspCategory: "ASST-08",
				}],
			}),
			injection: makeCategoryScore(85, 0.3),
			dependencies: makeCategoryScore(80, 0.2),
			behavioral: makeCategoryScore(80, 0.15),
			content: makeCategoryScore(75, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeGreaterThanOrEqual(75);
		expect(report.overall).toBeLessThan(90);
		expect(report.badge).toBe("conditional");
	});

	it("should sort findings by severity (critical first)", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(80, 0.25, {
				findings: [{
					id: "LOW-1", category: "permissions", severity: "low",
					title: "Low", description: "t", evidence: "e", deduction: 3,
					recommendation: "r", owaspCategory: "ASST-08",
				}],
			}),
			injection: makeCategoryScore(50, 0.3, {
				findings: [{
					id: "CRIT-1", category: "injection", severity: "critical",
					title: "Critical", description: "t", evidence: "e", deduction: 40,
					recommendation: "r", owaspCategory: "ASST-01",
				}],
			}),
			dependencies: makeCategoryScore(90, 0.2),
			behavioral: makeCategoryScore(90, 0.15, {
				findings: [{
					id: "MED-1", category: "behavioral", severity: "medium",
					title: "Medium", description: "t", evidence: "e", deduction: 10,
					recommendation: "r", owaspCategory: "ASST-09",
				}],
			}),
			content: makeCategoryScore(80, 0.1),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings[0]?.severity).toBe("critical");
		expect(report.findings[1]?.severity).toBe("medium");
		expect(report.findings[2]?.severity).toBe("low");
	});
});
