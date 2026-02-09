import type { DeclaredPermission, Finding } from "../types.js";

/**
 * Keyword mapping from declared permission kinds to finding pattern keywords.
 * If a declared permission's `kind` contains any key, and a finding's title/evidence
 * contains any of the corresponding values, it's considered a match.
 */
const DECLARED_KIND_MATCHERS: ReadonlyArray<{
	readonly kindKeywords: readonly string[];
	readonly findingKeywords: readonly string[];
}> = [
	{
		kindKeywords: ["credential_access", "credential"],
		findingKeywords: [
			"credential",
			"api_key",
			"api-key",
			"secret_key",
			"secret-key",
			"access_token",
			"access-token",
			"private_key",
			"private-key",
			"password",
			"env_access",
			".env",
			".ssh",
			"id_rsa",
			"id_ed25519",
		],
	},
	{
		kindKeywords: ["network"],
		findingKeywords: [
			"network",
			"url",
			"http",
			"https",
			"fetch",
			"download",
			"external",
			"domain",
			"endpoint",
		],
	},
	{
		kindKeywords: ["file_write", "file_modify"],
		findingKeywords: [
			"file_write",
			"file-write",
			"file_modify",
			"file-modify",
			"write",
			"state persistence",
			"save",
			"store",
			"persist",
		],
	},
	{
		kindKeywords: ["system_modification", "system"],
		findingKeywords: [
			"system modification",
			"system_modification",
			"install",
			"modify system",
			"config",
			"chmod",
			"chown",
		],
	},
	{
		kindKeywords: ["exec", "shell"],
		findingKeywords: ["exec", "shell", "execute", "run", "spawn", "process", "command"],
	},
];

/**
 * Check if a finding matches any declared permission.
 * Returns the matching DeclaredPermission if found, or undefined.
 */
export function findMatchingDeclaration(
	finding: Finding,
	declaredPermissions: readonly DeclaredPermission[],
): DeclaredPermission | undefined {
	if (declaredPermissions.length === 0) return undefined;

	const findingText = `${finding.title} ${finding.evidence} ${finding.description}`.toLowerCase();

	for (const declared of declaredPermissions) {
		const kind = declared.kind.toLowerCase();

		for (const matcher of DECLARED_KIND_MATCHERS) {
			const kindMatches = matcher.kindKeywords.some((kw) => kind.includes(kw));
			if (!kindMatches) continue;

			const findingMatches = matcher.findingKeywords.some((fw) => findingText.includes(fw));
			if (findingMatches) return declared;
		}
	}

	return undefined;
}

/**
 * Apply declared permission matching to a list of findings.
 *
 * SECURITY NOTE:
 * Declared permissions are untrusted, author-controlled input. They can provide useful context,
 * but must never be used to suppress/downgrade real findings (otherwise a malicious author can
 * self-declare broad kinds like "network" or "credential_access" to neutralize critical alerts).
 *
 * We only annotate matching findings with the declaration + justification.
 */
export function applyDeclaredPermissions(
	findings: readonly Finding[],
	declaredPermissions: readonly DeclaredPermission[],
): Finding[] {
	if (declaredPermissions.length === 0) return [...findings];

	return findings.map((finding) => {
		const match = findMatchingDeclaration(finding, declaredPermissions);
		if (!match) return finding;

		return {
			...finding,
			title: `${finding.title} (declared: ${match.kind})`,
			description: `${finding.description}\n\nDeclared permission: ${match.kind} — ${match.justification}`,
		};
	});
}
