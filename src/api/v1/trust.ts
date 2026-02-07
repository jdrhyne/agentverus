import { Hono } from "hono";
import { NotFoundError } from "../middleware/errors.js";

const trustApp = new Hono();

/** GET /skill/:id/trust — Get trust report for a skill */
trustApp.get("/skill/:id/trust", async (c) => {
	const skillId = c.req.param("id");

	// Validate UUID format
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	if (!uuidRegex.test(skillId)) {
		throw new NotFoundError(`Invalid skill ID format: ${skillId}`);
	}

	// TODO: Query database for skill and latest scan result
	// For now, return 404 as no database is connected yet
	throw new NotFoundError(`Skill not found: ${skillId}`);
});

export { trustApp };
