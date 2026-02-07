import type { Finding, Severity, TrustReport } from "./types.js";
import { ASST_CATEGORIES, SCANNER_VERSION } from "./types.js";

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifScan {
	readonly target: string;
	readonly report: TrustReport;
}

export interface SarifFailure {
	readonly target: string;
	readonly error: string;
}

export interface SarifLog {
	readonly $schema: string;
	readonly version: "2.1.0";
	readonly runs: readonly SarifRun[];
}

export interface SarifRun {
	readonly tool: {
		readonly driver: SarifToolDriver;
	};
	readonly results: readonly SarifResult[];
}

export interface SarifToolDriver {
	readonly name: string;
	readonly informationUri?: string;
	readonly version?: string;
	readonly rules?: readonly SarifRule[];
}

export interface SarifRule {
	readonly id: string;
	readonly name?: string;
	readonly shortDescription?: { readonly text: string };
	readonly help?: { readonly text: string };
	readonly defaultConfiguration?: { readonly level: SarifLevel };
	readonly properties?: Readonly<Record<string, unknown>>;
}

export interface SarifResult {
	readonly ruleId: string;
	readonly level: SarifLevel;
	readonly message: { readonly text: string };
	readonly locations?: readonly SarifLocation[];
	readonly properties?: Readonly<Record<string, unknown>>;
}

export interface SarifLocation {
	readonly physicalLocation: {
		readonly artifactLocation: { readonly uri: string };
		readonly region?: { readonly startLine: number };
	};
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

function severityToSarifLevel(severity: Severity): SarifLevel {
	switch (severity) {
		case "critical":
		case "high":
			return "error";
		case "medium":
			return "warning";
		case "low":
		case "info":
			return "note";
		default: {
			// Exhaustiveness guard for future values.
			const _exhaustive: never = severity;
			return _exhaustive;
		}
	}
}

function pickRuleLevel(findings: readonly Finding[]): SarifLevel {
	// Choose the "highest" severity observed for this rule.
	let best: Severity = "info";
	for (const f of findings) {
		if ((SEVERITY_RANK[f.severity] ?? 99) < (SEVERITY_RANK[best] ?? 99)) best = f.severity;
	}
	return severityToSarifLevel(best);
}

function formatFindingMessage(finding: Finding): string {
	const parts: string[] = [];
	parts.push(finding.title);
	parts.push("");
	parts.push(finding.description);
	if (finding.evidence) {
		parts.push("");
		parts.push(`Evidence: ${finding.evidence}`);
	}
	parts.push("");
	parts.push(`Recommendation: ${finding.recommendation}`);
	return parts.join("\n");
}

export function buildSarifLog(
	scans: readonly SarifScan[],
	failures?: readonly SarifFailure[],
): SarifLog {
	const findingsByRuleId = new Map<string, Finding[]>();
	for (const scan of scans) {
		for (const finding of scan.report.findings) {
			const ruleId = finding.owaspCategory || "ASST-UNKNOWN";
			const list = findingsByRuleId.get(ruleId);
			if (list) list.push(finding);
			else findingsByRuleId.set(ruleId, [finding]);
		}
	}

	const rules: SarifRule[] = [];
	for (const [ruleId, findings] of [...findingsByRuleId.entries()].sort((a, b) =>
		a[0].localeCompare(b[0]),
	)) {
		const title = (ASST_CATEGORIES as Record<string, string>)[ruleId] ?? "Agent skill security finding";
		rules.push({
			id: ruleId,
			name: title,
			shortDescription: { text: title },
			help: {
				text: `Category ${ruleId}: ${title}. See the finding message for context and recommended mitigation.`,
			},
			defaultConfiguration: { level: pickRuleLevel(findings) },
			properties: {
				kind: "agent-skill-security",
			},
		});
	}

	const results: SarifResult[] = [];
	for (const scan of scans) {
		for (const finding of scan.report.findings) {
			const ruleId = finding.owaspCategory || "ASST-UNKNOWN";
			const loc: SarifLocation = {
				physicalLocation: {
					artifactLocation: { uri: scan.target },
					region: finding.lineNumber ? { startLine: finding.lineNumber } : undefined,
				},
			};

			results.push({
				ruleId,
				level: severityToSarifLevel(finding.severity),
				message: { text: formatFindingMessage(finding) },
				locations: [loc],
				properties: {
					findingId: finding.id,
					category: finding.category,
					severity: finding.severity,
					deduction: finding.deduction,
					badge: scan.report.badge,
					overall: scan.report.overall,
					skillName: scan.report.metadata.skillName,
					skillFormat: scan.report.metadata.skillFormat,
				},
			});
		}
	}

	if (failures && failures.length > 0) {
		rules.push({
			id: "AGENTVERUS-SCAN-ERROR",
			name: "Skill scan failed",
			shortDescription: { text: "Failed to fetch or read a target for scanning." },
			help: {
				text: "The scanner could not read a file or fetch a URL. Fix the error and re-run the scan to avoid missing results.",
			},
			defaultConfiguration: { level: "error" },
			properties: { kind: "scan-error" },
		});

		for (const failure of failures) {
			results.push({
				ruleId: "AGENTVERUS-SCAN-ERROR",
				level: "error",
				message: { text: `Failed to scan target: ${failure.target}\n\n${failure.error}` },
				locations: [
					{
						physicalLocation: {
							artifactLocation: { uri: failure.target },
						},
					},
				],
			});
		}
	}

	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "AgentVerus Scanner",
						informationUri: "https://github.com/agentverus/agentverus-scanner",
						version: SCANNER_VERSION,
						rules,
					},
				},
				results,
			},
		],
	};
}
