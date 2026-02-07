import { Hono } from "hono";
import { z } from "zod/v4";
import { sha256 } from "../../lib/utils.js";
import { scanSkill } from "../../scanner/index.js";
import { fetchSkillContentFromUrl } from "../../scanner/source.js";
import { ValidationError } from "../middleware/errors.js";

const scanApp = new Hono();

const scanRequestSchema = z.object({
	content: z.string().min(1).optional(),
	url: z.url().optional(),
});

/** POST /skill/scan — Submit a skill for scanning */
scanApp.post("/skill/scan", async (c) => {
	const body = await c.req.json();
	const parsed = scanRequestSchema.safeParse(body);

	if (!parsed.success) {
		throw new ValidationError("Invalid request body", z.prettifyError(parsed.error));
	}

	const { content, url } = parsed.data;

	if (!content && !url) {
		throw new ValidationError("Either 'content' or 'url' must be provided");
	}

	if (content && url) {
		throw new ValidationError("Provide either 'content' or 'url', not both");
	}

	let skillContent: string;
	let skillUrl: string | undefined;

	if (url) {
		try {
			const fetched = await fetchSkillContentFromUrl(url);
			skillContent = fetched.content;
			skillUrl = fetched.sourceUrl;
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			throw new ValidationError(`Failed to fetch URL: ${message}`);
		}
	} else {
		skillContent = content as string;
	}

	const report = await scanSkill(skillContent);
	const contentHash = sha256(skillContent);

	// In production, this would upsert into the database
	// For now, return the report directly
	return c.json({
		skillId: crypto.randomUUID(),
		scanResultId: crypto.randomUUID(),
		contentHash,
		url: skillUrl,
		report,
	});
});

export { scanApp };
