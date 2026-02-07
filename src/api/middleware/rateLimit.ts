import type { Context, Next } from "hono";
import { RateLimitError } from "./errors.js";

interface RateLimitEntry {
	count: number;
	resetAt: number;
}

interface RateLimitOptions {
	readonly windowMs?: number;
	readonly max?: number;
}

const store = new Map<string, RateLimitEntry>();

// Cleanup expired entries every 5 minutes
setInterval(
	() => {
		const now = Date.now();
		for (const [key, entry] of store.entries()) {
			if (entry.resetAt < now) {
				store.delete(key);
			}
		}
	},
	5 * 60 * 1000,
).unref();

/** Create a rate limiting middleware */
export function rateLimit(options: RateLimitOptions = {}) {
	const windowMs = options.windowMs ?? 60_000;
	const max = options.max ?? 60;

	return async (c: Context, next: Next) => {
		// Skip if request has API key (handled by tier limits)
		if (c.get("apiKey")) {
			await next();
			return;
		}

		const ip =
			c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
			c.req.header("x-real-ip") ??
			"unknown";

		const key = `ip:${ip}`;
		const now = Date.now();
		const entry = store.get(key);

		if (!entry || entry.resetAt < now) {
			store.set(key, { count: 1, resetAt: now + windowMs });
			await next();
			return;
		}

		entry.count++;

		if (entry.count > max) {
			const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
			throw new RateLimitError(
				`Rate limit exceeded. Try again in ${retryAfter} seconds.`,
				retryAfter,
			);
		}

		await next();
	};
}
