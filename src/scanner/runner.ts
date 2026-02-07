import { readFile } from "node:fs/promises";

import { scanSkill, scanSkillFromUrl } from "./index.js";
import type { ScanOptions, TrustReport } from "./types.js";
import { isUrlTarget } from "./targets.js";

export interface ScanTargetReport {
	readonly target: string;
	readonly report: TrustReport;
}

export interface ScanFailure {
	readonly target: string;
	readonly error: string;
}

export async function scanTarget(target: string, options?: ScanOptions): Promise<ScanTargetReport> {
	if (isUrlTarget(target)) {
		const report = await scanSkillFromUrl(target, options);
		return { target, report };
	}

	const content = await readFile(target, "utf-8");
	const report = await scanSkill(content, options);
	return { target, report };
}

export async function scanTargets(
	targets: readonly string[],
	options?: ScanOptions,
): Promise<readonly ScanTargetReport[]> {
	const results: ScanTargetReport[] = [];
	for (const target of targets) results.push(await scanTarget(target, options));
	return results;
}

export async function scanTargetsBatch(
	targets: readonly string[],
	options?: ScanOptions,
): Promise<{ readonly reports: readonly ScanTargetReport[]; readonly failures: readonly ScanFailure[] }> {
	const reports: ScanTargetReport[] = [];
	const failures: ScanFailure[] = [];

	for (const target of targets) {
		try {
			reports.push(await scanTarget(target, options));
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			failures.push({ target, error: message });
		}
	}

	return { reports, failures };
}
