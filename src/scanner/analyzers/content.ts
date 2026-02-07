import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Harmful content patterns */
const HARMFUL_PATTERNS = [
	{
		pattern: /(?:generate|create|write|produce)\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|keylogger|rootkit)/i,
		title: "Malware generation instructions",
		deduction: 40,
	},
	{
		pattern: /(?:bypass|circumvent|disable)\s+(?:security|firewall|antivirus|protection|authentication)/i,
		title: "Security bypass instructions",
		deduction: 40,
	},
	{
		pattern: /(?:create|build|make)\s+(?:a\s+)?(?:weapon|explosive|bomb|poison)/i,
		title: "Weapons/dangerous materials instructions",
		deduction: 40,
	},
	{
		pattern: /(?:hack|exploit|attack|crack)\s+(?:into|passwords?|systems?|servers?|accounts?)/i,
		title: "Hacking/exploitation instructions",
		deduction: 40,
	},
] as const;

/** Deception patterns */
const DECEPTION_PATTERNS = [
	/(?:pretend|claim|say)\s+(?:to\s+be|you\s+are)\s+(?:human|real\s+person)/i,
	/(?:deceive|mislead|trick)\s+(?:the\s+)?user/i,
	/(?:fake|fabricate|invent)\s+(?:data|results|evidence|citations)/i,
	/(?:impersonate|pose\s+as)\s+(?:a\s+)?(?:human|person|authority)/i,
] as const;

/** Safety boundary keywords */
const SAFETY_BOUNDARY_PATTERNS = [
	/(?:should\s+not|must\s+not|do\s+not|never|don't|won't)\s+(?:access|modify|delete|send|share|execute)/i,
	/safety\s+boundaries?/i,
	/(?:prohibited|forbidden|restricted)\s+actions?/i,
	/limitations?\s+(?:and\s+)?(?:restrictions?|boundaries?|constraints?)/i,
	/(?:will\s+not|cannot|must\s+not)\s+/i,
] as const;

/** Output constraint keywords */
const OUTPUT_CONSTRAINT_PATTERNS = [
	/(?:output|response)\s+(?:format|constraints?|limitations?)/i,
	/(?:maximum|max)\s+(?:\d+\s+)?(?:words?|characters?|lines?|tokens?)/i,
	/(?:format|respond|output)\s+(?:as|in|with)\s+(?:json|markdown|plain\s+text|structured)/i,
] as const;

/** Error handling keywords */
const ERROR_HANDLING_PATTERNS = [
	/error\s+handling/i,
	/(?:if|when)\s+(?:an?\s+)?error\s+occurs?/i,
	/(?:gracefully|properly)\s+(?:handle|catch|manage)\s+errors?/i,
	/(?:return|display|show)\s+(?:an?\s+)?(?:error|warning)\s+message/i,
] as const;

/** Analyze content quality and safety boundaries */
export async function analyzeContent(
	skill: ParsedSkill,
): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 80; // Start at 80, skills must earn the top 20
	const content = skill.rawContent;

	// Award bonus points for good practices
	const hasSafetyBoundaries = SAFETY_BOUNDARY_PATTERNS.some((p) =>
		p.test(content),
	);
	if (hasSafetyBoundaries) {
		score = Math.min(100, score + 10);
		findings.push({
			id: "CONT-SAFETY-GOOD",
			category: "content",
			severity: "info",
			title: "Safety boundaries defined",
			description:
				"The skill includes explicit safety boundaries defining what it should NOT do.",
			evidence: "Safety boundary patterns detected in content",
			deduction: 0,
			recommendation: "Keep these safety boundaries. They improve trust.",
			owaspCategory: "ASST-09",
		});
	}

	const hasOutputConstraints = OUTPUT_CONSTRAINT_PATTERNS.some((p) =>
		p.test(content),
	);
	if (hasOutputConstraints) {
		score = Math.min(100, score + 5);
		findings.push({
			id: "CONT-OUTPUT-GOOD",
			category: "content",
			severity: "info",
			title: "Output constraints defined",
			description:
				"The skill includes output format constraints (length limits, format specifications).",
			evidence: "Output constraint patterns detected",
			deduction: 0,
			recommendation: "Keep these output constraints.",
			owaspCategory: "ASST-09",
		});
	}

	const hasErrorHandling = ERROR_HANDLING_PATTERNS.some((p) =>
		p.test(content),
	);
	if (hasErrorHandling) {
		score = Math.min(100, score + 5);
		findings.push({
			id: "CONT-ERROR-GOOD",
			category: "content",
			severity: "info",
			title: "Error handling instructions present",
			description:
				"The skill includes error handling instructions for graceful failure.",
			evidence: "Error handling patterns detected",
			deduction: 0,
			recommendation: "Keep these error handling instructions.",
			owaspCategory: "ASST-09",
		});
	}

	// Check for harmful content
	for (const harmful of HARMFUL_PATTERNS) {
		const match = content.match(harmful.pattern);
		if (match) {
			const lineNumber =
				content.slice(0, content.indexOf(match[0])).split("\n").length;
			score = Math.max(0, score - harmful.deduction);

			findings.push({
				id: `CONT-HARMFUL-${findings.length + 1}`,
				category: "content",
				severity: "critical",
				title: harmful.title,
				description: `The skill contains instructions related to: ${harmful.title.toLowerCase()}.`,
				evidence: match[0].slice(0, 200),
				lineNumber,
				deduction: harmful.deduction,
				recommendation:
					"Remove all harmful content instructions. Skills must not enable dangerous activities.",
				owaspCategory: "ASST-07",
			});
		}
	}

	// Check for deceptive patterns
	for (const pattern of DECEPTION_PATTERNS) {
		const match = content.match(pattern);
		if (match) {
			score = Math.max(0, score - 10);
			findings.push({
				id: `CONT-DECEPTION-${findings.length + 1}`,
				category: "content",
				severity: "medium",
				title: "Deceptive behavior instructions",
				description:
					"The skill contains instructions that encourage deception or impersonation.",
				evidence: match[0].slice(0, 200),
				deduction: 10,
				recommendation:
					"Remove deceptive behavior instructions. Skills should be transparent.",
				owaspCategory: "ASST-07",
			});
		}
	}

	// Check for missing description
	if (!skill.description || skill.description.trim().length < 10) {
		score = Math.max(0, score - 5);
		findings.push({
			id: "CONT-NO-DESC",
			category: "content",
			severity: "low",
			title: "Missing or insufficient description",
			description:
				"The skill lacks a meaningful description, making it difficult to assess its purpose.",
			evidence: skill.description
				? `Description: "${skill.description.slice(0, 100)}"`
				: "No description found",
			deduction: 5,
			recommendation:
				"Add a clear, detailed description of what the skill does and what it needs access to.",
			owaspCategory: "ASST-09",
		});
	}

	// Missing safety boundaries penalty
	if (!hasSafetyBoundaries) {
		findings.push({
			id: "CONT-NO-SAFETY",
			category: "content",
			severity: "low",
			title: "No explicit safety boundaries",
			description:
				"The skill does not include explicit safety boundaries defining what it should NOT do.",
			evidence: "No safety boundary patterns found",
			deduction: 0,
			recommendation:
				"Add a 'Safety Boundaries' section listing what the skill must NOT do (e.g., no file deletion, no network access beyond needed APIs).",
			owaspCategory: "ASST-09",
		});
	}

	// Apply declared permissions — downgrade matching findings
	const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);

	// Recalculate score: start at base, add bonuses, subtract adjusted deductions
	let adjustedScore = 80;
	if (hasSafetyBoundaries) adjustedScore = Math.min(100, adjustedScore + 10);
	if (hasOutputConstraints) adjustedScore = Math.min(100, adjustedScore + 5);
	if (hasErrorHandling) adjustedScore = Math.min(100, adjustedScore + 5);
	for (const f of adjustedFindings) {
		adjustedScore = Math.max(0, adjustedScore - f.deduction);
	}

	const summary =
		adjustedFindings.filter((f) => f.severity !== "info").length === 0
			? "Content quality is good with proper safety boundaries."
			: `Found ${adjustedFindings.filter((f) => f.severity !== "info").length} content-related concerns. ${
					adjustedFindings.some((f) => f.severity === "critical")
						? "CRITICAL: Harmful content detected."
						: "Some content quality improvements recommended."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.1,
		findings: adjustedFindings,
		summary,
	};
}
