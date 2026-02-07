#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { scanSkill, scanSkillFromUrl } from "../scanner/index.js";
import { normalizeSkillUrl } from "../scanner/source.js";
import { SCANNER_VERSION } from "../scanner/types.js";

function toJsonText(value: unknown): string {
	return JSON.stringify(value, null, 2);
}

async function main(): Promise<void> {
	const server = new McpServer({
		name: "AgentVerus Scanner",
		version: SCANNER_VERSION,
	});

	server.registerTool(
		"normalize_skill_url",
		{
			title: "Normalize skill URL",
			description:
				"Normalize skill URLs (GitHub blob/tree URLs, ClawHub skill pages) into a direct downloadable/scan-ready URL.",
			inputSchema: {
				url: z.string().min(1),
			},
		},
		async ({ url }) => {
			const normalized = normalizeSkillUrl(url);
			return { content: [{ type: "text", text: toJsonText({ url, normalized }) }] };
		},
	);

	server.registerTool(
		"scan_skill",
		{
			title: "Scan a skill",
			description:
				"Scan a SKILL.md (or variant) and return an AgentVerus trust report. Provide exactly one of: content, path, or url.",
			inputSchema: {
				content: z.string().optional(),
				path: z.string().optional(),
				url: z.string().optional(),
				timeout: z.number().int().optional(),
				retries: z.number().int().nonnegative().optional(),
				retryDelayMs: z.number().int().nonnegative().optional(),
			},
		},
		async ({ content, path, url, timeout, retries, retryDelayMs }) => {
			const provided = [content ? "content" : null, path ? "path" : null, url ? "url" : null].filter(
				(v) => v !== null,
			);
			if (provided.length !== 1) {
				return {
					content: [
						{
							type: "text",
							text: toJsonText({
								error:
									"Provide exactly one of: content, path, or url. For URLs, prefer normalize_skill_url first if needed.",
								provided,
							}),
						},
					],
				};
			}

			const options = { timeout, retries, retryDelayMs };

			if (typeof content === "string") {
				const report = await scanSkill(content, options);
				return { content: [{ type: "text", text: toJsonText({ target: "content", report }) }] };
			}

			if (typeof path === "string") {
				const fileContent = await readFile(path, "utf-8");
				const report = await scanSkill(fileContent, options);
				return { content: [{ type: "text", text: toJsonText({ target: path, report }) }] };
			}

			if (typeof url === "string") {
				const report = await scanSkillFromUrl(url, options);
				return { content: [{ type: "text", text: toJsonText({ target: url, report }) }] };
			}

			return {
				content: [
					{
						type: "text",
						text: toJsonText({ error: "Unexpected input state." }),
					},
				],
			};
		},
	);

	const transport = new StdioServerTransport();
	await server.connect(transport);
}

main().catch((err) => {
	const message = err instanceof Error ? err.message : String(err);
	// MCP uses stdio; keep stdout clean for protocol messages.
	console.error(message);
	process.exit(1);
});

