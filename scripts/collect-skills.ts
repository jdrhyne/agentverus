#!/usr/bin/env node
/**
 * Collect public skill URLs from ClawHub and GitHub.
 * Usage:
 *   pnpm collect-skills
 *   pnpm collect-skills --clawhub-only
 *   pnpm collect-skills --github-only
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const OUTPUT_FILE = join(process.cwd(), "data", "skill-urls.txt");

const GITHUB_API = "https://api.github.com";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? "";
const CLAWHUB_API = "https://auth.clawdhub.com/api/v1";

/** Search queries to find SKILL.md files */
const SEARCH_QUERIES = [
	"filename:SKILL.md",
	"filename:SKILL.md path:skills",
	"filename:skill.md",
] as const;

/** Known repositories likely to have skills */
const KNOWN_REPOS = [
	"anthropic/skill-library",
	"openclaw/community-skills",
	"openclaw/skill-examples",
] as const;

interface GitHubSearchItem {
	readonly name: string;
	readonly path: string;
	readonly html_url: string;
	readonly repository: {
		readonly full_name: string;
	};
}

interface GitHubSearchResponse {
	readonly total_count: number;
	readonly items: readonly GitHubSearchItem[];
}

interface ClawHubSkillListItem {
	readonly slug: string;
	readonly tags?: Readonly<Record<string, string>>;
}

interface ClawHubSkillListResponse {
	readonly items: readonly ClawHubSkillListItem[];
	readonly nextCursor?: string | null;
}

/** Make a GitHub API request */
async function githubFetch(url: string): Promise<Response> {
	const headers: Record<string, string> = {
		Accept: "application/vnd.github.v3+json",
		"User-Agent": "AgentVerus-Collector",
	};

	if (GITHUB_TOKEN) {
		headers.Authorization = `Bearer ${GITHUB_TOKEN}`;
	}

	const response = await fetch(url, { headers });

	// Handle rate limiting
	const remaining = response.headers.get("x-ratelimit-remaining");
	if (remaining && Number.parseInt(remaining) < 5) {
		const resetAt = response.headers.get("x-ratelimit-reset");
		const waitMs = resetAt ? Number.parseInt(resetAt) * 1000 - Date.now() + 1000 : 60_000;
		console.log(`  Rate limit approaching, waiting ${Math.ceil(waitMs / 1000)}s...`);
		await new Promise((resolve) => setTimeout(resolve, Math.max(waitMs, 1000)));
	}

	return response;
}

async function collectClawHub(): Promise<string[]> {
	const urls: string[] = [];
	let cursor: string | undefined;

	while (true) {
		const url = new URL(`${CLAWHUB_API}/skills`);
		url.searchParams.set("limit", "100");
		if (cursor) url.searchParams.set("cursor", cursor);

		const response = await fetch(url, { headers: { Accept: "application/json" } });
		if (!response.ok) {
			console.error(`  ClawHub fetch failed: ${response.status} ${response.statusText}`);
			break;
		}

		// Handle rate limiting if headers are present
		const remainingRaw = response.headers.get("x-ratelimit-remaining");
		const resetAtRaw = response.headers.get("x-ratelimit-reset");
		const remaining = remainingRaw ? Number.parseInt(remainingRaw, 10) : Number.NaN;
		const resetAt = resetAtRaw ? Number.parseInt(resetAtRaw, 10) : Number.NaN;

		const data = (await response.json()) as ClawHubSkillListResponse;
		for (const item of data.items) {
			if (!item.slug) continue;
			const dl = new URL(`${CLAWHUB_API}/download`);
			dl.searchParams.set("slug", item.slug);
			const latest = item.tags?.latest;
			if (latest) dl.searchParams.set("version", latest);
			urls.push(dl.toString());
		}

		if (!data.nextCursor) break;
		cursor = data.nextCursor;

		// If we're close to the limit, wait until reset.
		if (!Number.isNaN(remaining) && remaining < 5 && !Number.isNaN(resetAt)) {
			const waitMs = resetAt * 1000 - Date.now() + 1000;
			console.log(`  ClawHub rate limit approaching, waiting ${Math.ceil(waitMs / 1000)}s...`);
			await new Promise((resolve) => setTimeout(resolve, Math.max(waitMs, 1000)));
		} else {
			// Be nice.
			await new Promise((resolve) => setTimeout(resolve, 250));
		}
	}

	return urls;
}

/** Search GitHub code for SKILL.md files */
async function searchGitHub(query: string): Promise<string[]> {
	const urls: string[] = [];
	let page = 1;
	const perPage = 100;

	while (page <= 10) {
		// GitHub limits to 1000 results
		const searchUrl = `${GITHUB_API}/search/code?q=${encodeURIComponent(query)}&per_page=${perPage}&page=${page}`;

		try {
			const response = await githubFetch(searchUrl);
			if (!response.ok) {
				console.error(`  Search failed: ${response.status}`);
				break;
			}

			const data = (await response.json()) as GitHubSearchResponse;

			for (const item of data.items) {
				// Construct raw content URL
				const rawUrl = `https://raw.githubusercontent.com/${item.repository.full_name}/main/${item.path}`;
				urls.push(rawUrl);
			}

			if (data.items.length < perPage) break;
			page++;

			// Be nice to the API
			await new Promise((resolve) => setTimeout(resolve, 2000));
		} catch (err) {
			console.error(`  Error searching: ${err}`);
			break;
		}
	}

	return urls;
}

/** Check known repos for SKILL.md files */
async function checkKnownRepos(): Promise<string[]> {
	const urls: string[] = [];

	for (const repo of KNOWN_REPOS) {
		try {
			const response = await githubFetch(
				`${GITHUB_API}/search/code?q=filename:SKILL.md+repo:${repo}`,
			);

			if (response.ok) {
				const data = (await response.json()) as GitHubSearchResponse;
				for (const item of data.items) {
					const rawUrl = `https://raw.githubusercontent.com/${repo}/main/${item.path}`;
					urls.push(rawUrl);
				}
			}

			await new Promise((resolve) => setTimeout(resolve, 2000));
		} catch {
			// Repository may not exist
		}
	}

	return urls;
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	const clawHubOnly = args.includes("--clawhub-only");
	const githubOnly = args.includes("--github-only");

	if (clawHubOnly && githubOnly) {
		console.error("Error: Provide at most one of --clawhub-only or --github-only");
		process.exit(1);
	}

	console.log(`\n📥 AgentVerus Skill URL Collector`);
	console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
	console.log(
		`  GitHub token: ${GITHUB_TOKEN ? "configured" : "not set (limited to 10 req/min)"}\n`,
	);

	const allUrls: string[] = [];

	// Collect from ClawHub
	if (!githubOnly) {
		console.log("  Collecting from ClawHub...");
		const clawHubUrls = await collectClawHub();
		console.log(`    Found ${clawHubUrls.length} URLs from ClawHub`);
		allUrls.push(...clawHubUrls);
	}

	// Search GitHub
	if (!clawHubOnly) {
		for (const query of SEARCH_QUERIES) {
			console.log(`  Searching: ${query}...`);
			const urls = await searchGitHub(query);
			console.log(`    Found ${urls.length} results`);
			allUrls.push(...urls);
		}

		// Check known repos
		console.log(`  Checking known repositories...`);
		const knownUrls = await checkKnownRepos();
		console.log(`    Found ${knownUrls.length} from known repos`);
		allUrls.push(...knownUrls);
	}

	// Deduplicate
	const unique = [...new Set(allUrls.map((u) => u.toLowerCase()))];

	// Write output
	writeFileSync(OUTPUT_FILE, unique.join("\n") + "\n");

	console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
	console.log(`  Total unique URLs: ${unique.length}`);
	console.log(`  Written to: ${OUTPUT_FILE}`);
	console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
}

main().catch((err) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
