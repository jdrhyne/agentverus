import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

const SKILL_BASENAMES = new Set(["skill.md", "skills.md"]);

const DEFAULT_IGNORED_DIRS = new Set([
	".git",
	"node_modules",
	"dist",
	"build",
	"coverage",
	".next",
	".turbo",
]);

export function isUrlTarget(target: string): boolean {
	return target.startsWith("http://") || target.startsWith("https://");
}

async function walkForSkills(dir: string, out: string[]): Promise<void> {
	const entries = await readdir(dir, { withFileTypes: true });
	for (const entry of entries) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
			await walkForSkills(full, out);
			continue;
		}

		if (!entry.isFile()) continue;

		const lower = entry.name.toLowerCase();
		if (SKILL_BASENAMES.has(lower)) out.push(full);
	}
}

export async function expandScanTargets(inputs: readonly string[]): Promise<readonly string[]> {
	const out: string[] = [];

	for (const input of inputs) {
		if (isUrlTarget(input)) {
			out.push(input);
			continue;
		}

		let s: Awaited<ReturnType<typeof stat>>;
		try {
			s = await stat(input);
		} catch {
			throw new Error(`Target not found: ${input}`);
		}

		if (s.isDirectory()) {
			await walkForSkills(input, out);
		} else if (s.isFile()) {
			out.push(input);
		} else {
			throw new Error(`Unsupported target type: ${input}`);
		}
	}

	// Preserve a stable scan order for CI logs and reproducibility.
	return [...new Set(out)].sort((a, b) => a.localeCompare(b));
}
