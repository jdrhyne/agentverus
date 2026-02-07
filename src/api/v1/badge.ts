import { Hono } from "hono";
import { generateBadge } from "../../badges/generator.js";

const badgeApp = new Hono();

/** GET /skill/:id/badge — Get SVG badge for a skill */
badgeApp.get("/skill/:id/badge", async (c) => {
	const skillId = c.req.param("id");
	void skillId; // Will be used for DB lookup
	const style = (c.req.query("style") ?? "flat") as "flat" | "flat-square" | "plastic";
	const label = c.req.query("label");

	// TODO: Query database for skill's latest scan result
	// For now, return a "not scanned" badge
	const svg = generateBadge({
		score: 0,
		badge: "rejected",
		style,
		label: label ?? undefined,
	});

	c.header("Content-Type", "image/svg+xml");
	c.header("Cache-Control", "max-age=3600");

	return c.body(svg);
});

export { badgeApp };
