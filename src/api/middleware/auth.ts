import type { Context, Next } from "hono";
import { createHash, randomBytes } from "node:crypto";
import { AuthError, ForbiddenError, RateLimitError } from "./errors.js";

interface ApiKeyRecord {
	id: string;
	keyHash: string;
	name: string;
	tier: "free" | "pro" | "enterprise" | "admin";
	requestsToday: number;
	requestsMonth: number;
}

/** Daily request limits per tier */
const TIER_LIMITS: Record<string, number> = {
	free: 100,
	pro: 10_000,
	enterprise: 1_000_000,
	admin: 1_000_000,
};

/** Hash an API key for storage/lookup */
export function hashApiKey(key: string): string {
	return createHash("sha256").update(key).digest("hex");
}

/** Generate a new API key */
export function generateApiKey(): string {
	return `at_${randomBytes(32).toString("hex")}`;
}

/** Authentication middleware factory */
export function requireAuth(level: "authenticated" | "admin") {
	return async (c: Context, next: Next) => {
		const authHeader = c.req.header("authorization");
		const apiKeyHeader = c.req.header("x-api-key");

		const rawKey =
			authHeader?.startsWith("Bearer ")
				? authHeader.slice(7)
				: apiKeyHeader;

		if (!rawKey) {
			throw new AuthError("API key required. Pass via Authorization: Bearer <key> or X-API-Key header.");
		}

		const keyHash = hashApiKey(rawKey);

		// For now, check admin key from env
		const adminKey = process.env.ADMIN_API_KEY;
		if (adminKey && rawKey === adminKey) {
			c.set("apiKey", {
				id: "admin",
				keyHash,
				name: "Admin",
				tier: "admin",
				requestsToday: 0,
				requestsMonth: 0,
			} satisfies ApiKeyRecord);
			await next();
			return;
		}

		// In production, this would query the api_keys table
		// For now, accept any key format that starts with "at_"
		if (!rawKey.startsWith("at_")) {
			throw new AuthError("Invalid API key format.");
		}

		// TODO: Look up in database
		const keyRecord: ApiKeyRecord = {
			id: "placeholder",
			keyHash,
			name: "API Key",
			tier: "free",
			requestsToday: 0,
			requestsMonth: 0,
		};

		if (level === "admin" && keyRecord.tier !== "admin") {
			throw new ForbiddenError("Admin access required.");
		}

		const limit = TIER_LIMITS[keyRecord.tier] ?? 100;
		if (keyRecord.requestsToday >= limit) {
			throw new RateLimitError(
				`Daily limit of ${limit} requests exceeded for ${keyRecord.tier} tier.`,
			);
		}

		c.set("apiKey", keyRecord);
		await next();
	};
}
