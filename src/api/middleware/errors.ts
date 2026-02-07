import type { Context } from "hono";

/** Base application error */
export class AppError extends Error {
	readonly statusCode: number;
	readonly code: string;

	constructor(message: string, statusCode: number, code: string) {
		super(message);
		this.name = "AppError";
		this.statusCode = statusCode;
		this.code = code;
	}
}

export class NotFoundError extends AppError {
	constructor(message = "Resource not found") {
		super(message, 404, "NOT_FOUND");
		this.name = "NotFoundError";
	}
}

export class AuthError extends AppError {
	constructor(message = "Authentication required") {
		super(message, 401, "UNAUTHORIZED");
		this.name = "AuthError";
	}
}

export class ForbiddenError extends AppError {
	constructor(message = "Insufficient permissions") {
		super(message, 403, "FORBIDDEN");
		this.name = "ForbiddenError";
	}
}

export class RateLimitError extends AppError {
	constructor(
		message = "Rate limit exceeded",
		public readonly retryAfter?: number,
	) {
		super(message, 429, "RATE_LIMIT_EXCEEDED");
		this.name = "RateLimitError";
	}
}

export class ValidationError extends AppError {
	constructor(
		message = "Validation error",
		public readonly details?: unknown,
	) {
		super(message, 400, "VALIDATION_ERROR");
		this.name = "ValidationError";
	}
}

/** Global error handler for Hono */
export function errorHandler(err: Error, c: Context) {
	console.error(`[ERROR] ${err.message}`, err.stack);

	if (err instanceof AppError) {
		const body: Record<string, unknown> = {
			error: {
				code: err.code,
				message: err.message,
			},
		};

		if (err instanceof ValidationError && err.details) {
			(body.error as Record<string, unknown>).details = err.details;
		}

		if (err instanceof RateLimitError && err.retryAfter) {
			c.header("Retry-After", String(err.retryAfter));
		}

		return c.json(body, err.statusCode as 400);
	}

	// Unknown errors
	return c.json(
		{
			error: {
				code: "INTERNAL_ERROR",
				message: process.env.NODE_ENV === "production" ? "An internal error occurred" : err.message,
			},
		},
		500,
	);
}
