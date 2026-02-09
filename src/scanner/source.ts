import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import { unzipSync } from "fflate";

import type { ScanOptions } from "./types.js";
import { SCANNER_VERSION } from "./types.js";

const DEFAULT_HEADERS: Readonly<Record<string, string>> = {
	Accept: "text/plain,text/markdown,text/html;q=0.9,application/zip;q=0.8,*/*;q=0.7",
	"User-Agent": `AgentVerusScanner/${SCANNER_VERSION}`,
};

const CLAWHUB_HOST = "clawhub.ai";
const CLAWHUB_DOWNLOAD_BASE = "https://auth.clawdhub.com/api/v1/download";

// Fetch hardening: keep downloads bounded and prevent SSRF when this library is embedded
// (e.g., exposed via the MCP wrapper).
const MAX_REDIRECTS = 5;
const MAX_TEXT_BYTES = 2_000_000; // 2MB
const MAX_ZIP_BYTES = 25_000_000; // 25MB
const MAX_ZIP_ENTRIES = 2_000;
const MAX_ZIP_SKILL_CANDIDATES = 10;
const MAX_SKILL_MD_BYTES = 2_000_000; // 2MB
const MAX_TOTAL_UNZIPPED_BYTES = 5_000_000; // 5MB across extracted candidates

function normalizeGithubUrl(url: URL): string {
	if (url.hostname !== "github.com") return url.toString();

	const parts = url.pathname.split("/").filter(Boolean);

	// Convert GitHub "blob" URLs to raw content URLs.
	// https://github.com/<owner>/<repo>/blob/<branch>/<path>
	if (parts.length >= 5 && parts[2] === "blob") {
		const owner = parts[0] as string;
		const repo = parts[1] as string;
		const branch = parts[3] as string;
		const path = parts.slice(4).join("/");
		return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
	}

	// Convert GitHub "tree" (directory) URLs — append SKILL.md and fetch raw.
	// https://github.com/<owner>/<repo>/tree/<branch>/<path>
	if (parts.length >= 4 && parts[2] === "tree") {
		const owner = parts[0] as string;
		const repo = parts[1] as string;
		const branch = parts[3] as string;
		const dirPath = parts.slice(4).join("/");
		const skillPath = dirPath ? `${dirPath}/SKILL.md` : "SKILL.md";
		return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${skillPath}`;
	}

	// Bare repo URL: https://github.com/<owner>/<repo>
	// Try to fetch SKILL.md from root of default branch.
	if (parts.length === 2) {
		const owner = parts[0] as string;
		const repo = parts[1] as string;
		return `https://raw.githubusercontent.com/${owner}/${repo}/main/SKILL.md`;
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

function isClawHubDownloadUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
	} catch {
		return false;
	}
}

function pickSkillMdPath(filePaths: readonly string[]): string | null {
	const candidates = filePaths.filter((p) => {
		const base = p.split("/").pop() ?? p;
		const lower = base.toLowerCase();
		return lower === "skill.md" || lower === "skills.md";
	});
	if (candidates.length === 0) return null;

	const rank = (p: string): number => {
		const base = p.split("/").pop() ?? p;
		const lowerBase = base.toLowerCase();
		const lower = p.toLowerCase();

		// Prefer the conventional "SKILL.md" file; fall back to "SKILLS.md" which
		// appears in some bundles. Prefer shallower paths.
		if (lowerBase === "skill.md" && lower === "skill.md") return 0;
		if (lowerBase === "skill.md") return 1;
		if (lowerBase === "skills.md" && lower === "skills.md") return 2;
		if (lowerBase === "skills.md") return 3;
		return 4;
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

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableStatus(status: number): boolean {
	return status === 429 || (status >= 500 && status <= 599);
}

function parseRetryAfterMs(value: string | null): number | null {
	if (!value) return null;
	const seconds = Number.parseInt(value, 10);
	if (!Number.isNaN(seconds)) return Math.max(0, seconds * 1000);
	const dateMs = Date.parse(value);
	if (!Number.isNaN(dateMs)) return Math.max(0, dateMs - Date.now());
	return null;
}

function isRetryableError(error: unknown): boolean {
	if (!(error instanceof Error)) return false;

	if (error.name === "AbortError" || /aborted due to timeout/i.test(error.message)) return true;
	if (/fetch failed/i.test(error.message)) return true;
	if (/Zip did not contain/i.test(error.message)) return false;

	return false;
}

function stripIpv6Zone(ip: string): string {
	const idx = ip.indexOf("%");
	return idx === -1 ? ip : ip.slice(0, idx);
}

function isBlockedIpv4(ip: string): boolean {
	const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
	if (parts.length !== 4) return true;
	if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;

	const a = parts[0];
	const b = parts[1];
	if (a === undefined || b === undefined) return true;

	// Loopback, private, link-local, CGNAT, multicast, reserved.
	if (a === 0) return true;
	if (a === 10) return true;
	if (a === 127) return true;
	if (a === 169 && b === 254) return true;
	if (a === 172 && b >= 16 && b <= 31) return true;
	if (a === 192 && b === 168) return true;
	if (a === 100 && b >= 64 && b <= 127) return true;
	if (a === 198 && (b === 18 || b === 19)) return true;
	if (a >= 224) return true;

	return false;
}

function isBlockedIpv6(ipRaw: string): boolean {
	const ip = stripIpv6Zone(ipRaw).toLowerCase();
	if (!ip) return true;

	// Loopback / unspecified
	if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return true;
	if (ip === "::" || ip === "0:0:0:0:0:0:0:0") return true;

	const compact = ip.replace(/:/g, "");
	// Link-local fe80::/10 => fe8, fe9, fea, feb
	if (/^fe[89ab]/.test(compact)) return true;
	// Unique local fc00::/7 => fc, fd
	if (/^f[cd]/.test(compact)) return true;
	// Multicast ff00::/8
	if (/^ff/.test(compact)) return true;

	return false;
}

function isBlockedIp(ipRaw: string): boolean {
	const ip = stripIpv6Zone(ipRaw);
	const family = isIP(ip);
	if (family === 4) return isBlockedIpv4(ip);
	if (family === 6) return isBlockedIpv6(ip);
	// Unknown/invalid => block
	return true;
}

async function assertUrlAllowed(url: URL): Promise<void> {
	const protocol = url.protocol.toLowerCase();
	// Allow data: URLs for offline/test usage; they are non-network.
	if (protocol === "data:") return;

	if (protocol !== "https:") {
		throw new Error(`Only https (or data:) URLs are allowed (got ${protocol || "unknown"}).`);
	}

	// Avoid leaking credentials into logs and prevent credentialed SSRF.
	if (url.username || url.password) {
		throw new Error("URLs with embedded credentials are not allowed.");
	}

	// Disallow non-standard ports to reduce SSRF surface.
	if (url.port && url.port !== "443") {
		throw new Error(`Non-standard ports are not allowed (got :${url.port}).`);
	}

	const hostname = url.hostname.replace(/\.$/, "").toLowerCase();
	if (!hostname) throw new Error("URL hostname is missing.");

	// Common SSRF targets.
	if (
		hostname === "localhost" ||
		hostname.endsWith(".localhost") ||
		hostname.endsWith(".local") ||
		hostname === "metadata.google.internal"
	) {
		throw new Error(`Blocked hostname for security reasons: ${hostname}`);
	}

	// Literal IPs (v4/v6).
	if (isIP(hostname)) {
		if (isBlockedIp(hostname)) {
			throw new Error(`Blocked IP address for security reasons: ${hostname}`);
		}
		return;
	}

	// DNS resolution check: block hostnames that resolve to private/link-local/etc.
	// This is best-effort; if lookup fails, fail closed (treat as unsafe) to avoid SSRF.
	let records: Array<{ address: string; family: number }>;
	try {
		records = (await lookup(hostname, { all: true, verbatim: true })) as Array<{
			address: string;
			family: number;
		}>;
	} catch {
		throw new Error(`Unable to resolve hostname: ${hostname}`);
	}

	for (const rec of records) {
		if (isBlockedIp(rec.address)) {
			throw new Error(
				`Blocked hostname for security reasons: ${hostname} (resolves to ${rec.address})`,
			);
		}
	}
}

async function fetchWithRedirectValidation(
	input: string,
	init: Readonly<{
		readonly headers: Readonly<Record<string, string>>;
		readonly signal?: AbortSignal;
	}>,
): Promise<{ readonly response: Response; readonly finalUrl: string }> {
	let current = new URL(input);

	for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
		await assertUrlAllowed(current);

		const response = await fetch(current.toString(), {
			headers: init.headers,
			signal: init.signal,
			redirect: "manual",
		});

		if (response.status >= 300 && response.status < 400) {
			const location = response.headers.get("location");
			if (!location) return { response, finalUrl: current.toString() };
			if (i === MAX_REDIRECTS) {
				throw new Error(`Too many redirects (>${MAX_REDIRECTS}).`);
			}

			// Ensure we don't keep the previous response body around.
			try {
				await response.body?.cancel();
			} catch {
				// Ignore cancellation failures.
			}

			current = new URL(location, current);
			continue;
		}

		return { response, finalUrl: current.toString() };
	}

	throw new Error(`Too many redirects (>${MAX_REDIRECTS}).`);
}

async function readResponseBytesWithLimit(response: Response, maxBytes: number): Promise<Uint8Array> {
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const declared = Number.parseInt(contentLength, 10);
		if (!Number.isNaN(declared) && declared > maxBytes) {
			throw new Error(`Response too large (${declared} bytes > ${maxBytes} bytes).`);
		}
	}

	// Stream to enforce the cap even when Content-Length is missing or wrong.
	const reader = response.body?.getReader();
	if (!reader) {
		const bytes = new Uint8Array(await response.arrayBuffer());
		if (bytes.length > maxBytes) {
			throw new Error(`Response too large (${bytes.length} bytes > ${maxBytes} bytes).`);
		}
		return bytes;
	}

	const chunks: Uint8Array[] = [];
	let total = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		if (!value) continue;
		total += value.length;
		if (total > maxBytes) {
			// Ensure the underlying stream is torn down promptly under heavy concurrency.
			await reader.cancel().catch(() => {});
			throw new Error(`Response too large (>${maxBytes} bytes).`);
		}
		chunks.push(value);
	}

	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.length;
	}
	return out;
}

function extractSkillMdFromZip(zipBytes: Uint8Array): { readonly content: string; readonly path: string } {
	let entryCount = 0;
	let candidateCount = 0;
	let totalUnzipped = 0;
	const seen: string[] = [];

	const files = unzipSync(zipBytes, {
		filter: (file) => {
			entryCount += 1;
			if (seen.length < 20) seen.push(file.name);
			if (entryCount > MAX_ZIP_ENTRIES) {
				throw new Error(`Zip contains too many entries (> ${MAX_ZIP_ENTRIES}).`);
			}

			const base = file.name.split("/").pop() ?? file.name;
			const lower = base.toLowerCase();
			const isCandidate = lower === "skill.md" || lower === "skills.md";
			if (!isCandidate) return false;

			candidateCount += 1;
			if (candidateCount > MAX_ZIP_SKILL_CANDIDATES) {
				throw new Error(
					`Zip contains too many SKILL.md candidates (> ${MAX_ZIP_SKILL_CANDIDATES}).`,
				);
			}

			// fflate provides both compressed size (`size`) and declared originalSize.
			if (file.originalSize > MAX_SKILL_MD_BYTES) {
				throw new Error(
					`SKILL.md is too large (${file.originalSize} bytes > ${MAX_SKILL_MD_BYTES} bytes).`,
				);
			}

			totalUnzipped += file.originalSize;
			if (totalUnzipped > MAX_TOTAL_UNZIPPED_BYTES) {
				throw new Error(
					`Zip expands too large (> ${MAX_TOTAL_UNZIPPED_BYTES} bytes across candidates).`,
				);
			}

			return true;
		},
	});

	const paths = Object.keys(files);
	const skillMdPath = pickSkillMdPath(paths);
	if (!skillMdPath) {
		const preview = seen.sort().slice(0, 20).join(", ");
		throw new Error(
			`Zip did not contain SKILL.md (found ${entryCount} entries). First entries: ${preview}`,
		);
	}

	const decoder = new TextDecoder("utf-8");
	return { content: decoder.decode(files[skillMdPath]), path: skillMdPath };
}

export async function fetchSkillContentFromUrl(
	inputUrl: string,
	options?: ScanOptions,
): Promise<{ readonly content: string; readonly sourceUrl: string }> {
	const sourceUrl = normalizeSkillUrl(inputUrl);

	const retries = Math.max(0, options?.retries ?? 2);
	const baseDelayMs = Math.max(0, options?.retryDelayMs ?? 750);
	const defaultTimeoutMs = isClawHubDownloadUrl(sourceUrl) ? 45_000 : 30_000;
	const timeoutMsRaw = options?.timeout;
	const timeoutMs = timeoutMsRaw === undefined ? defaultTimeoutMs : timeoutMsRaw;

	let lastError: unknown;

	for (let attempt = 0; attempt <= retries; attempt += 1) {
		try {
			const { response, finalUrl } = await fetchWithRedirectValidation(sourceUrl, {
				headers: DEFAULT_HEADERS,
				signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
			});

			if (!response.ok) {
				if (attempt < retries && isRetryableStatus(response.status)) {
					const retryAfter = parseRetryAfterMs(response.headers.get("retry-after"));
					const backoffMs =
						retryAfter ??
						Math.min(30_000, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
					await sleep(backoffMs);
					continue;
				}

				let snippet = "";
				try {
					const bytes = await readResponseBytesWithLimit(response, 8_000);
					const text = new TextDecoder("utf-8").decode(bytes);
					snippet = formatHttpErrorBodySnippet(text);
				} catch {
					// Ignore body read failures (or oversize bodies).
				}

				throw new Error(
					`Failed to fetch skill from ${finalUrl}: ${response.status} ${response.statusText}${snippet ? ` — ${snippet}` : ""}`,
				);
			}

			const contentType = response.headers.get("content-type");
			if (isZipResponse(contentType, finalUrl)) {
				const zipBytes = await readResponseBytesWithLimit(response, MAX_ZIP_BYTES);
				const extracted = extractSkillMdFromZip(zipBytes);
				return { content: extracted.content, sourceUrl: finalUrl };
			}

			const bytes = await readResponseBytesWithLimit(response, MAX_TEXT_BYTES);
			const text = new TextDecoder("utf-8").decode(bytes);
			return { content: text, sourceUrl: finalUrl };
		} catch (err) {
			lastError = err;
			if (attempt < retries && isRetryableError(err)) {
				const backoffMs = Math.min(30_000, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
				await sleep(backoffMs);
				continue;
			}
			throw err;
		}
	}

	throw lastError instanceof Error ? lastError : new Error("Failed to fetch skill content");
}
