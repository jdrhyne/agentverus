import type { CategoryScore, Finding, ParsedSkill } from "../types.js";

/** Permission risk tiers */
const CRITICAL_PERMISSIONS = ["exec", "shell", "sudo", "admin"] as const;
const HIGH_PERMISSIONS = ["write", "delete", "network_unrestricted", "env_access"] as const;
const MEDIUM_PERMISSIONS = ["network_restricted", "file_write", "api_access"] as const;
const LOW_PERMISSIONS = ["read", "file_read", "search"] as const;

/** Deduction amounts per tier */
const DEDUCTIONS = {
	critical: 30,
	high: 15,
	medium: 8,
	low: 2,
} as const;

/** Keywords suggesting limited-scope skills */
const LIMITED_SCOPE_KEYWORDS = [
	"calculator",
	"spell",
	"check",
	"format",
	"lint",
	"simple",
	"basic",
	"math",
	"text",
	"convert",
	"translate",
	"weather",
	"time",
	"date",
	"clock",
	"counter",
	"hello",
	"greeting",
] as const;

/** Permissions that suggest purpose mismatch for limited-scope skills */
const SUSPICIOUS_FOR_LIMITED = [
	"exec",
	"shell",
	"sudo",
	"admin",
	"network_unrestricted",
	"env_access",
	"delete",
	"file_write",
] as const;

function getPermissionTier(
	perm: string,
): "critical" | "high" | "medium" | "low" | null {
	const lower = perm.toLowerCase();
	if (CRITICAL_PERMISSIONS.some((p) => lower.includes(p))) return "critical";
	if (HIGH_PERMISSIONS.some((p) => lower.includes(p))) return "high";
	if (MEDIUM_PERMISSIONS.some((p) => lower.includes(p))) return "medium";
	if (LOW_PERMISSIONS.some((p) => lower.includes(p))) return "low";
	return null;
}

function isLimitedScopeSkill(skill: ParsedSkill): boolean {
	const combined = `${skill.name} ${skill.description}`.toLowerCase();
	return LIMITED_SCOPE_KEYWORDS.some((kw) => combined.includes(kw));
}

/** Analyze permissions requested by a skill */
export async function analyzePermissions(
	skill: ParsedSkill,
): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;

	const allPermissions = [
		...skill.permissions,
		...skill.tools.filter((t) => getPermissionTier(t) !== null),
	];
	const uniquePerms = [...new Set(allPermissions.map((p) => p.toLowerCase()))];

	// Score each permission
	for (const perm of uniquePerms) {
		const tier = getPermissionTier(perm);
		if (!tier) continue;

		const deduction = DEDUCTIONS[tier];
		score = Math.max(0, score - deduction);

		const severity = tier === "critical" ? "critical" : tier === "high" ? "high" : "medium";

		findings.push({
			id: `PERM-${findings.length + 1}`.padStart(8, "0").slice(-8),
			category: "permissions",
			severity,
			title: `${tier.charAt(0).toUpperCase() + tier.slice(1)}-risk permission: ${perm}`,
			description: `The skill requests the "${perm}" permission which is classified as ${tier} risk.`,
			evidence: `Permission: ${perm}`,
			deduction,
			recommendation:
				tier === "critical"
					? `Remove the "${perm}" permission unless absolutely required. Critical permissions grant extensive system access.`
					: `Consider whether "${perm}" is necessary for the skill's stated functionality.`,
			owaspCategory:
				tier === "critical" || tier === "high" ? "ASST-03" : "ASST-08",
		});
	}

	// Check for permission-purpose mismatch
	if (isLimitedScopeSkill(skill)) {
		for (const perm of uniquePerms) {
			const lower = perm.toLowerCase();
			if (SUSPICIOUS_FOR_LIMITED.some((s) => lower.includes(s))) {
				const deduction = 15;
				score = Math.max(0, score - deduction);

				findings.push({
					id: `PERM-MISMATCH-${findings.length + 1}`,
					category: "permissions",
					severity: "high",
					title: `Permission-purpose mismatch: "${perm}" on limited-scope skill`,
					description: `The skill "${skill.name}" appears to be limited in scope but requests "${perm}" which is unusual for its stated purpose.`,
					evidence: `Skill: "${skill.name}" (${skill.description?.slice(0, 80)}...) requests "${perm}"`,
					deduction,
					recommendation: `Review whether "${perm}" is truly needed for a ${skill.name.toLowerCase()}.`,
					owaspCategory: "ASST-03",
				});
			}
		}
	}

	// Check for excessive total permissions
	if (uniquePerms.length > 5) {
		findings.push({
			id: "PERM-EXCESSIVE",
			category: "permissions",
			severity: "info",
			title: `Excessive number of permissions (${uniquePerms.length})`,
			description: `The skill requests ${uniquePerms.length} distinct permissions. Consider whether all are necessary.`,
			evidence: `Permissions: ${uniquePerms.join(", ")}`,
			deduction: 0,
			recommendation:
				"Apply the principle of least privilege — only request permissions the skill actually needs.",
			owaspCategory: "ASST-08",
		});
	}

	const summary =
		findings.length === 0
			? "No permission concerns detected."
			: `Found ${findings.length} permission-related findings. ${
					findings.some((f) => f.severity === "critical")
						? "CRITICAL: Dangerous permissions detected."
						: findings.some((f) => f.severity === "high")
							? "High-risk permissions detected that may not match the skill's purpose."
							: "Minor permission concerns."
				}`;

	return {
		score: Math.max(0, Math.min(100, score)),
		weight: 0.25,
		findings,
		summary,
	};
}
