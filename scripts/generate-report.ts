#!/usr/bin/env node
/**
 * Generate aggregate statistics from scan results.
 * Usage: pnpm tsx scripts/generate-report.ts <scan-results-dir>
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

// This script is designed to process the output of bulk-scan
// For now, it generates a template report

const DATA_DIR = join(process.cwd(), "data");

function main(): void {
	mkdirSync(DATA_DIR, { recursive: true });

	// Generate template statistics (to be filled after bulk scanning)
	const stats = {
		generatedAt: new Date().toISOString(),
		totalScanned: 0,
		scoreDistribution: {
			"0-10": 0, "11-20": 0, "21-30": 0, "31-40": 0, "41-50": 0,
			"51-60": 0, "61-70": 0, "71-80": 0, "81-90": 0, "91-100": 0,
		},
		badgeDistribution: {
			certified: 0,
			conditional: 0,
			suspicious: 0,
			rejected: 0,
		},
		averageScores: {
			overall: 0,
			permissions: 0,
			injection: 0,
			dependencies: 0,
			behavioral: 0,
			content: 0,
		},
		criticalFindings: 0,
		highFindings: 0,
		topFindingTypes: [] as Array<{ id: string; count: number }>,
		asstDistribution: {
			"ASST-01": 0, "ASST-02": 0, "ASST-03": 0, "ASST-04": 0,
			"ASST-05": 0, "ASST-06": 0, "ASST-07": 0, "ASST-08": 0,
			"ASST-09": 0, "ASST-10": 0,
		},
		formatDistribution: {
			openclaw: 0,
			claude: 0,
			generic: 0,
		},
	};

	writeFileSync(
		join(DATA_DIR, "aggregate-stats.json"),
		JSON.stringify(stats, null, 2),
	);

	// Generate markdown report template
	const report = `# State of Agent Skill Security

*Generated: ${new Date().toISOString()}*

## Executive Summary

We scanned **${stats.totalScanned}** AI agent skill files from public repositories.

Key findings:
- **${stats.badgeDistribution.rejected}** skills (${pct(stats.badgeDistribution.rejected, stats.totalScanned)}%) were REJECTED for critical security issues
- **${stats.criticalFindings}** critical-severity findings detected
- Average trust score: **${stats.averageScores.overall}/100**
- ${stats.badgeDistribution.certified} skills (${pct(stats.badgeDistribution.certified, stats.totalScanned)}%) achieved CERTIFIED status

## Methodology

AgentVerus uses the **ASST** (Agent Skill Security Threats) taxonomy — an OWASP-style categorization of 10 threat categories specific to AI agent skills.

Each skill is analyzed across 5 categories:
1. **Permissions** (25%) — Are the requested permissions appropriate?
2. **Injection** (30%) — Does the skill contain hidden instructions or prompt injection?
3. **Dependencies** (20%) — Are external URLs and dependencies trustworthy?
4. **Behavioral** (15%) — Does the skill exhibit risky behavioral patterns?
5. **Content** (10%) — Are safety boundaries and documentation adequate?

## Badge Distribution

| Badge | Count | Percentage |
|-------|-------|-----------|
| ✅ CERTIFIED (90-100) | ${stats.badgeDistribution.certified} | ${pct(stats.badgeDistribution.certified, stats.totalScanned)}% |
| 🟡 CONDITIONAL (75-89) | ${stats.badgeDistribution.conditional} | ${pct(stats.badgeDistribution.conditional, stats.totalScanned)}% |
| 🟠 SUSPICIOUS (50-74) | ${stats.badgeDistribution.suspicious} | ${pct(stats.badgeDistribution.suspicious, stats.totalScanned)}% |
| 🔴 REJECTED (<50/Critical) | ${stats.badgeDistribution.rejected} | ${pct(stats.badgeDistribution.rejected, stats.totalScanned)}% |

## ASST Category Analysis

| Category | Findings |
|----------|---------|
| ASST-01: Instruction Injection | ${stats.asstDistribution["ASST-01"]} |
| ASST-02: Data Exfiltration | ${stats.asstDistribution["ASST-02"]} |
| ASST-03: Privilege Escalation | ${stats.asstDistribution["ASST-03"]} |
| ASST-04: Dependency Hijacking | ${stats.asstDistribution["ASST-04"]} |
| ASST-05: Credential Harvesting | ${stats.asstDistribution["ASST-05"]} |
| ASST-06: Prompt Injection Relay | ${stats.asstDistribution["ASST-06"]} |
| ASST-07: Deceptive Functionality | ${stats.asstDistribution["ASST-07"]} |
| ASST-08: Excessive Permissions | ${stats.asstDistribution["ASST-08"]} |
| ASST-09: Missing Safety Boundaries | ${stats.asstDistribution["ASST-09"]} |
| ASST-10: Obfuscation | ${stats.asstDistribution["ASST-10"]} |

## Comparison to Gen Digital's Findings

Gen Digital reported that 15% of OpenClaw skills contain malicious instructions.

Our analysis found **${pct(stats.badgeDistribution.rejected + stats.badgeDistribution.suspicious, stats.totalScanned)}%** of skills scored SUSPICIOUS or REJECTED.

## Recommendations

### For Skill Publishers
1. Add explicit safety boundaries (what the skill should NOT do)
2. Request only the permissions actually needed
3. Document all external dependencies
4. Include error handling instructions
5. Submit for AgentVerus certification at [agentverus.ai](https://agentverus.ai)

### For Skill Consumers
1. Check the AgentVerus badge before installing any skill
2. Review permissions requested vs. stated purpose
3. Avoid skills with REJECTED or SUSPICIOUS ratings
4. Report suspicious skills to the community

---

*Scan, audit, and certify AI agent skills at [agentverus.ai](https://agentverus.ai)*
`;

	writeFileSync(join(DATA_DIR, "report.md"), report);

	console.log(`\n📊 Reports generated:`);
	console.log(`  → ${join(DATA_DIR, "aggregate-stats.json")}`);
	console.log(`  → ${join(DATA_DIR, "report.md")}\n`);
}

function pct(n: number, total: number): string {
	if (total === 0) return "0";
	return ((n / total) * 100).toFixed(1);
}

main();
