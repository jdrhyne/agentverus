import { unzipSync } from "fflate";

import type { ScanOptions } from "./types.js";
import { SCANNER_VERSION } from "./types.js";

const DEFAULT_HEADERS: Readonly<Record<string, string>> = {
	Accept: "text/plain,text/markdown,text/html;q=0.9,application/zip;q=0.8,*/*;q=0.7",
	"User-Agent": `AgentVerusScanner/${SCANNER_VERSION}`,
};

const CLAWHUB_HOST = "clawhub.ai";
const CLAWHUB_DOWNLOAD_BASE = "https://auth.clawdhub.com/api/v1/download";

function normalizeGithubUrl(url: URL): string {
	if (url.hostname !== "github.com") return url.toString();

	// Convert GitHub "blob" URLs to raw content URLs.
	// https://github.com/<owner>/<repo>/blob/<branch>/<path>
	const parts = url.pathname.split("/").filter(Boolean);
	if (parts.length >= 5 && parts[2] === "blob") {
		const owner = parts[0] as string;
		const repo = parts[1] as string;
		const branch = parts[3] as string;
		const path = parts.slice(4).join("/");
		return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
	}

	return url.toString();
}

function normalizeClawHubUrl(url: URL): string {
	// Skill pages are at: https://clawhub.ai/<owner>/<slug>
	// Bulk scan should prefer downloading the bundle zip and extracting SKILL.md.
	if (url.hostname !== CLAWHUB_HOST) return url.toString();

	const parts = url.pathname.split("/").filter(Boolean);
	if (parts.length < 2) return url.toString();

	const [first, second] = parts;
	if (!first || !second) return url.toString();

	// Exclude known non-skill routes. This list is intentionally small.
	if (
		first === "admin" ||
		first === "assets" ||
		first === "cli" ||
		first === "dashboard" ||
		first === "import" ||
		first === "management" ||
		first === "og" ||
		first === "settings" ||
		first === "skills" ||
		first === "souls" ||
		first === "stars" ||
		first === "u" ||
		first === "upload"
	) {
		return url.toString();
	}

	const downloadUrl = new URL(CLAWHUB_DOWNLOAD_BASE);
	downloadUrl.searchParams.set("slug", second);
	return downloadUrl.toString();
}

export function normalizeSkillUrl(inputUrl: string): string {
	let url: URL;
	try {
		url = new URL(inputUrl);
	} catch {
		return inputUrl;
	}

	if (url.hostname === CLAWHUB_HOST) return normalizeClawHubUrl(url);
	if (url.hostname === "github.com") return normalizeGithubUrl(url);
	return url.toString();
}

function isZipResponse(contentType: string | null, url: string): boolean {
	if (contentType?.toLowerCase().includes("application/zip")) return true;
	try {
		const parsed = new URL(url);
		return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
	} catch {
		return false;
	}
}

function pickSkillMdPath(filePaths: readonly string[]): string | null {
	const candidates = filePaths.filter((p) => p.toLowerCase().endsWith("skill.md"));
	if (candidates.length === 0) return null;

	const rank = (p: string): number => {
		const lower = p.toLowerCase();
		if (lower === "skill.md") return 0;
		if (lower.endsWith("/skill.md")) return 1;
		return 2;
	};

	return (
		[...candidates].sort((a, b) => rank(a) - rank(b) || a.length - b.length || a.localeCompare(b))[0] ??
		null
	);
}

function formatHttpErrorBodySnippet(text: string): string {
	const cleaned = text.replace(/\s+/g, " ").trim();
	if (!cleaned) return "";
	return cleaned.length > 200 ? `${cleaned.slice(0, 200)}...` : cleaned;
}

export async function fetchSkillContentFromUrl(
	inputUrl: string,
	options?: ScanOptions,
): Promise<{ readonly content: string; readonly sourceUrl: string }> {
	const sourceUrl = normalizeSkillUrl(inputUrl);

	const response = await fetch(sourceUrl, {
		headers: DEFAULT_HEADERS,
		signal: options?.timeout ? AbortSignal.timeout(options.timeout) : undefined,
	});

	if (!response.ok) {
		let snippet = "";
		try {
			snippet = formatHttpErrorBodySnippet(await response.text());
		} catch {
			// Ignore body read failures.
		}
		throw new Error(
			`Failed to fetch skill from ${sourceUrl}: ${response.status} ${response.statusText}${snippet ? ` — ${snippet}` : ""}`,
		);
	}

	const contentType = response.headers.get("content-type");
	if (isZipResponse(contentType, sourceUrl)) {
		const zipBytes = new Uint8Array(await response.arrayBuffer());
		const files = unzipSync(zipBytes);
		const paths = Object.keys(files);
		const skillMdPath = pickSkillMdPath(paths);
		if (!skillMdPath) {
			const preview = paths.sort().slice(0, 20).join(", ");
			throw new Error(
				`Zip did not contain SKILL.md (found ${paths.length} files). First files: ${preview}`,
			);
		}

		const decoder = new TextDecoder("utf-8");
		return { content: decoder.decode(files[skillMdPath]), sourceUrl };
	}

	return { content: await response.text(), sourceUrl };
}
