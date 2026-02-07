import { Hono } from "hono";
import { z } from "zod/v4";
import { sha256 } from "../../lib/utils.js";
import { scanSkill } from "../../scanner/index.js";
import { NotFoundError, ValidationError } from "../middleware/errors.js";

const certifyApp = new Hono();

const submitSchema = z.object({
	content: z.string().min(1).optional(),
	url: z.url().optional(),
	email: z.email(),
});

/** POST /certify — Submit skill for free certification */
certifyApp.post("/certify", async (c) => {
	const body = await c.req.json();
	const parsed = submitSchema.safeParse(body);

	if (!parsed.success) {
		throw new ValidationError("Invalid request", z.prettifyError(parsed.error));
	}

	const { content, url, email } = parsed.data;

	if (!content && !url) {
		throw new ValidationError("Either 'content' or 'url' must be provided");
	}

	let skillContent: string;
	if (url) {
		const response = await fetch(url);
		if (!response.ok) {
			throw new ValidationError(`Failed to fetch URL: ${response.status}`);
		}
		skillContent = await response.text();
	} else {
		skillContent = content as string;
	}

	const report = await scanSkill(skillContent);
	const contentHash = sha256(skillContent);
	const certificationId = crypto.randomUUID();
	const skillId = crypto.randomUUID();
	const scanResultId = crypto.randomUUID();

	// Generate badge
	const badgeUrl = `/api/v1/skill/${skillId}/badge`;

	// TODO: Store in database and send email notification
	return c.json({
		certificationId,
		skillId,
		scanResultId,
		status: "active",
		tier: "free",
		contentHash,
		email,
		badgeUrl,
		report,
	});
});

/** GET /certify/:id — Check certification status */
certifyApp.get("/certify/:id", async (c) => {
	const certId = c.req.param("id");

	// TODO: Query database
	throw new NotFoundError(`Certification not found: ${certId}`);
});

export { certifyApp };
