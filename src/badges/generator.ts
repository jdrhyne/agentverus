import type { BadgeTier } from "../scanner/types.js";

interface BadgeOptions {
	readonly score: number;
	readonly badge: BadgeTier;
	readonly style?: "flat" | "flat-square" | "plastic";
	readonly label?: string;
	readonly certified?: boolean;
}

/** Badge tier colors */
const BADGE_COLORS: Record<BadgeTier, string> = {
	certified: "#2ECC40",
	conditional: "#DFB317",
	suspicious: "#FE7D37",
	rejected: "#E05D44",
};

/** Badge tier display names */
const BADGE_LABELS: Record<BadgeTier, string> = {
	certified: "CERTIFIED",
	conditional: "CONDITIONAL",
	suspicious: "SUSPICIOUS",
	rejected: "REJECTED",
};

/**
 * Generate a shields.io-style SVG badge.
 */
export function generateBadge(options: BadgeOptions): string {
	const {
		score,
		badge,
		style = "flat",
		label = "AgentTrust",
		certified = false,
	} = options;

	const rightColor = BADGE_COLORS[badge];
	const rightText = `${BADGE_LABELS[badge]} ${score}`;
	const checkmark = certified ? " ✓" : "";

	const leftWidth = label.length * 6.5 + 12;
	const rightWidth = (rightText.length + checkmark.length) * 6.5 + 12;
	const totalWidth = leftWidth + rightWidth;

	const radius = style === "flat-square" ? 0 : 3;
	const leftColor = "#555";

	const gradient =
		style === "plastic"
			? `<linearGradient id="s" x2="0" y2="100%">
				<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
				<stop offset="1" stop-opacity=".1"/>
			</linearGradient>`
			: "";

	const gradientRef = style === "plastic" ? ' fill="url(#s)"' : "";

	return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${rightText}">
	<title>${label}: ${rightText}${checkmark}</title>
	${gradient}
	<clipPath id="r">
		<rect width="${totalWidth}" height="20" rx="${radius}" fill="#fff"/>
	</clipPath>
	<g clip-path="url(#r)">
		<rect width="${leftWidth}" height="20" fill="${leftColor}"/>
		<rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${rightColor}"/>
		<rect width="${totalWidth}" height="20"${gradientRef}/>
	</g>
	<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
		<text aria-hidden="true" x="${leftWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(label)}</text>
		<text x="${leftWidth / 2}" y="14">${escapeXml(label)}</text>
		<text aria-hidden="true" x="${leftWidth + rightWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(rightText)}${checkmark}</text>
		<text x="${leftWidth + rightWidth / 2}" y="14">${escapeXml(rightText)}${checkmark}</text>
	</g>
</svg>`;
}

/** Escape XML special characters */
function escapeXml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}
