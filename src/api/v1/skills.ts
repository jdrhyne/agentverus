import { Hono } from "hono";
import { z } from "zod/v4";

const skillsApp = new Hono();

const searchParamsSchema = z.object({
	q: z.string().optional(),
	badge: z.enum(["certified", "conditional", "suspicious", "rejected"]).optional(),
	sort: z.enum(["score", "name", "date"]).default("score"),
	order: z.enum(["asc", "desc"]).default("desc"),
	page: z.coerce.number().int().positive().default(1),
	limit: z.coerce.number().int().positive().max(100).default(20),
});

/** GET /skills — Search and list skills */
skillsApp.get("/skills", async (c) => {
	const rawParams = Object.fromEntries(new URL(c.req.url).searchParams.entries());

	const params = searchParamsSchema.parse(rawParams);

	// TODO: Query database with search/filter/sort/pagination
	// For now, return empty results
	return c.json({
		skills: [],
		pagination: {
			page: params.page,
			limit: params.limit,
			total: 0,
			totalPages: 0,
		},
	});
});

export { skillsApp };
