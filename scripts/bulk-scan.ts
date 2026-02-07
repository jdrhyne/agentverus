#!/usr/bin/env node
/**
 * Bulk scan script — scans multiple skill files and prints summary.
 * Usage: pnpm bulk-scan <file-with-urls> or pnpm bulk-scan <directory>
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { scanSkill, scanSkillFromUrl } from "../src/scanner/index.js";
import type { BadgeTier, TrustReport } from "../src/scanner/types.js";

const CONCURRENCY = 5;
const DELAY_BETWEEN_BATCHES_MS = 100;
const FETCH_TIMEOUT_MS = 30_000;

interface ScanResult {
	readonly path: string;
	readonly report: TrustReport | null;
	readonly error: string | null;
}

/** Simple concurrency limiter */
async function withConcurrency<T, R>(
	items: readonly T[],
	limit: number,
	fn: (item: T) => Promise<R>,
): Promise<R[]> {
	const results: R[] = [];
	const queue = [...items];

	async function worker(): Promise<void> {
		while (queue.length > 0) {
			const item = queue.shift();
			if (item !== undefined) {
				const result = await fn(item);
				results.push(result);
			}
		}
	}

	const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
	await Promise.all(workers);
	return results;
}

/** Scan a single skill file */
async function scanOne(path: string): Promise<ScanResult> {
	try {
		if (path.startsWith("http")) {
			const report = await scanSkillFromUrl(path, { timeout: FETCH_TIMEOUT_MS });
			return { path, report, error: null };
		}

		const content = readFileSync(path, "utf-8");
		const report = await scanSkill(content);
		return { path, report, error: null };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { path, report: null, error: message };
	}
}

/** Get list of paths to scan */
function getPaths(input: string): string[] {
	try {
		const stat = statSync(input);
		if (stat.isDirectory()) {
			return readdirSync(input)
				.filter((f) => extname(f) === ".md")
				.map((f) => join(input, f));
		}
	} catch {
		// Not a file/directory, might be inline
	}

	// Treat as file containing URLs/paths (one per line)
	const content = readFileSync(input, "utf-8");
	return content
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0 && !l.startsWith("#"));
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	if (args.length === 0) {
		console.error("Usage: pnpm bulk-scan <file-with-urls | directory>");
		process.exit(1);
	}

	const inputPath = args[0] as string;
	const paths = getPaths(inputPath);

	console.log(`\n🔍 AgentVerus Bulk Scanner`);
	console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
	console.log(`Found ${paths.length} skills to scan\n`);

	const startTime = Date.now();
	let scanCount = 0;

	const results = await withConcurrency(paths, CONCURRENCY, async (path) => {
		const result = await scanOne(path);
		scanCount++;

		if (scanCount % 10 === 0 || scanCount === paths.length) {
			console.log(`  Progress: ${scanCount}/${paths.length} scanned`);
		}

		if (result.error) {
			console.log(`  ❌ ${path}: ${result.error}`);
		} else if (result.report) {
			const badge = result.report.badge.toUpperCase().padEnd(12);
			console.log(
				`  ${result.report.badge === "certified" ? "✅" : result.report.badge === "conditional" ? "🟡" : result.report.badge === "suspicious" ? "🟠" : "🔴"} ${badge} ${result.report.overall}/100  ${path}`,
			);
		}

		// Delay between items
		await new Promise((resolve) => setTimeout(resolve, DELAY_BETWEEN_BATCHES_MS));

		return result;
	});

	const durationMs = Date.now() - startTime;

	// Summary
	const successful = results.filter(
		(r): r is ScanResult & { report: TrustReport } => r.report !== null,
	);
	const failed = results.filter((r) => r.error !== null);

	const scores = successful.map((r) => r.report.overall);
	const avgScore =
		scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

	const gradeDistribution: Record<BadgeTier, number> = {
		certified: 0,
		conditional: 0,
		suspicious: 0,
		rejected: 0,
	};
	for (const r of successful) {
		gradeDistribution[r.report.badge]++;
	}

	const criticalCount = successful.filter((r) =>
		r.report.findings.some((f) => f.severity === "critical"),
	).length;

	const highCount = successful.filter((r) =>
		r.report.findings.some((f) => f.severity === "high"),
	).length;

	console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
	console.log(`📊 SCAN SUMMARY`);
	console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
	console.log(`  Total scanned:     ${successful.length}`);
	console.log(`  Failures:          ${failed.length}`);
	console.log(`  Average score:     ${avgScore}/100`);
	console.log(`  Duration:          ${(durationMs / 1000).toFixed(1)}s`);
	console.log();
	console.log(`  Badge Distribution:`);
	console.log(
		`    ✅ CERTIFIED:    ${gradeDistribution.certified} (${pct(gradeDistribution.certified, successful.length)}%)`,
	);
	console.log(
		`    🟡 CONDITIONAL:  ${gradeDistribution.conditional} (${pct(gradeDistribution.conditional, successful.length)}%)`,
	);
	console.log(
		`    🟠 SUSPICIOUS:   ${gradeDistribution.suspicious} (${pct(gradeDistribution.suspicious, successful.length)}%)`,
	);
	console.log(
		`    🔴 REJECTED:     ${gradeDistribution.rejected} (${pct(gradeDistribution.rejected, successful.length)}%)`,
	);
	console.log();
	console.log(
		`  With critical findings: ${criticalCount} (${pct(criticalCount, successful.length)}%)`,
	);
	console.log(`  With high findings:     ${highCount} (${pct(highCount, successful.length)}%)`);
	console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
}

function pct(n: number, total: number): string {
	if (total === 0) return "0";
	return ((n / total) * 100).toFixed(1);
}

main().catch((err) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
