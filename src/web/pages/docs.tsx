import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const docsApp = new Hono();

docsApp.get("/docs", (c) => {
	return c.html(
		<BaseLayout title="API Documentation" description="REST API documentation for AgentTrust.">
			<section class="py-12 px-4">
				<div class="max-w-4xl mx-auto">
					<h1 class="text-3xl font-bold mb-3">API Documentation</h1>
					<p class="text-gray-400 mb-8">
						The AgentTrust REST API. Base URL: <code class="bg-gray-800 px-2 py-1 rounded text-certified">{c.req.url.split("/docs")[0]}/api/v1</code>
					</p>

					{/* Authentication */}
					<div class="mb-12">
						<h2 class="text-2xl font-semibold mb-4">Authentication</h2>
						<p class="text-gray-400 mb-3">
							Some endpoints require an API key. Pass it via header:
						</p>
						<pre class="bg-gray-900 border border-gray-800 rounded-lg p-4 text-sm overflow-x-auto mb-4">
							<code class="text-green-400">Authorization: Bearer at_your_api_key_here</code>
						</pre>
						<p class="text-gray-400">
							Public endpoints (GET) don't require authentication. POST endpoints require a valid API key.
						</p>
					</div>

					{/* Endpoints */}
					{[
						{
							method: "POST",
							path: "/api/v1/skill/scan",
							desc: "Submit a skill for scanning. Returns a complete trust report.",
							auth: "Optional",
							body: `{
  "content": "---\\nname: My Skill\\n---\\n# Instructions...",
  // OR
  "url": "https://raw.githubusercontent.com/.../SKILL.md"
}`,
							response: `{
  "skillId": "uuid",
  "scanResultId": "uuid",
  "contentHash": "sha256...",
  "report": {
    "overall": 95,
    "badge": "certified",
    "categories": { ... },
    "findings": [ ... ],
    "metadata": { ... }
  }
}`,
							curl: `curl -X POST ${c.req.url.split("/docs")[0]}/api/v1/skill/scan \\
  -H "Content-Type: application/json" \\
  -d '{"content": "---\\nname: Test\\n---\\n# My Skill"}'`,
						},
						{
							method: "GET",
							path: "/api/v1/skill/:id/trust",
							desc: "Get the latest trust report for a skill.",
							auth: "None",
							body: null,
							response: `{
  "skill": { "id": "uuid", "name": "...", "url": "..." },
  "report": { "overall": 95, "badge": "certified", ... }
}`,
							curl: `curl ${c.req.url.split("/docs")[0]}/api/v1/skill/SKILL_ID/trust`,
						},
						{
							method: "GET",
							path: "/api/v1/skill/:id/badge",
							desc: "Get an SVG trust badge for embedding. Query params: style (flat|flat-square), label.",
							auth: "None",
							body: null,
							response: "SVG image (Content-Type: image/svg+xml)",
							curl: `# Embed in markdown:
![AgentTrust](${c.req.url.split("/docs")[0]}/api/v1/skill/SKILL_ID/badge)`,
						},
						{
							method: "GET",
							path: "/api/v1/skills",
							desc: "Search and list skills. Query params: q, badge, sort, order, page, limit.",
							auth: "None",
							body: null,
							response: `{
  "skills": [ ... ],
  "pagination": { "page": 1, "limit": 20, "total": 0, "totalPages": 0 }
}`,
							curl: `curl "${c.req.url.split("/docs")[0]}/api/v1/skills?q=weather&badge=certified"`,
						},
						{
							method: "POST",
							path: "/api/v1/certify",
							desc: "Submit a skill for free certification. Runs scan and issues badge.",
							auth: "Optional",
							body: `{
  "content": "...",  // or "url": "..."
  "email": "publisher@example.com"
}`,
							response: `{
  "certificationId": "uuid",
  "skillId": "uuid",
  "status": "active",
  "badgeUrl": "/api/v1/skill/uuid/badge",
  "report": { ... }
}`,
							curl: `curl -X POST ${c.req.url.split("/docs")[0]}/api/v1/certify \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://...", "email": "me@example.com"}'`,
						},
					].map((endpoint) => (
						<div class="mb-10 bg-gray-900 border border-gray-800 rounded-xl p-6">
							<div class="flex items-center gap-3 mb-3">
								<span
									class={`px-3 py-1 rounded text-sm font-bold ${
										endpoint.method === "GET" ? "bg-green-700 text-green-100" : "bg-blue-700 text-blue-100"
									}`}
								>
									{endpoint.method}
								</span>
								<code class="text-lg font-mono">{endpoint.path}</code>
								<span class="text-gray-500 text-sm ml-auto">Auth: {endpoint.auth}</span>
							</div>
							<p class="text-gray-400 mb-4">{endpoint.desc}</p>

							{endpoint.body && (
								<div class="mb-4">
									<p class="text-sm font-medium mb-1">Request Body:</p>
									<pre class="bg-gray-800 rounded-lg p-3 text-sm overflow-x-auto">
										<code class="text-yellow-300">{endpoint.body}</code>
									</pre>
								</div>
							)}

							<div class="mb-4">
								<p class="text-sm font-medium mb-1">Response:</p>
								<pre class="bg-gray-800 rounded-lg p-3 text-sm overflow-x-auto">
									<code class="text-green-300">{endpoint.response}</code>
								</pre>
							</div>

							<div>
								<p class="text-sm font-medium mb-1">Example:</p>
								<pre class="bg-gray-800 rounded-lg p-3 text-sm overflow-x-auto">
									<code class="text-cyan-300">{endpoint.curl}</code>
								</pre>
							</div>
						</div>
					))}

					{/* Rate Limits */}
					<div class="mt-12">
						<h2 class="text-2xl font-semibold mb-4">Rate Limits</h2>
						<div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
							<table class="w-full text-sm">
								<thead>
									<tr class="border-b border-gray-700">
										<th class="text-left py-2">Tier</th>
										<th class="text-left py-2">Limit</th>
										<th class="text-left py-2">Price</th>
									</tr>
								</thead>
								<tbody class="text-gray-400">
									<tr class="border-b border-gray-800">
										<td class="py-2">Unauthenticated</td>
										<td>60 requests/minute</td>
										<td>Free</td>
									</tr>
									<tr class="border-b border-gray-800">
										<td class="py-2">Free API Key</td>
										<td>100 requests/day</td>
										<td>Free</td>
									</tr>
									<tr class="border-b border-gray-800">
										<td class="py-2">Pro</td>
										<td>10,000 requests/day</td>
										<td>Coming soon</td>
									</tr>
									<tr>
										<td class="py-2">Enterprise</td>
										<td>Unlimited</td>
										<td>Contact us</td>
									</tr>
								</tbody>
							</table>
						</div>
					</div>

					{/* Error Codes */}
					<div class="mt-12 mb-12">
						<h2 class="text-2xl font-semibold mb-4">Error Codes</h2>
						<div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
							<table class="w-full text-sm">
								<thead>
									<tr class="border-b border-gray-700">
										<th class="text-left py-2">Code</th>
										<th class="text-left py-2">Status</th>
										<th class="text-left py-2">Description</th>
									</tr>
								</thead>
								<tbody class="text-gray-400">
									<tr class="border-b border-gray-800"><td class="py-2">VALIDATION_ERROR</td><td>400</td><td>Invalid request body or parameters</td></tr>
									<tr class="border-b border-gray-800"><td class="py-2">UNAUTHORIZED</td><td>401</td><td>Missing or invalid API key</td></tr>
									<tr class="border-b border-gray-800"><td class="py-2">FORBIDDEN</td><td>403</td><td>Insufficient permissions</td></tr>
									<tr class="border-b border-gray-800"><td class="py-2">NOT_FOUND</td><td>404</td><td>Resource not found</td></tr>
									<tr class="border-b border-gray-800"><td class="py-2">RATE_LIMIT_EXCEEDED</td><td>429</td><td>Too many requests</td></tr>
									<tr><td class="py-2">INTERNAL_ERROR</td><td>500</td><td>Server error</td></tr>
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { docsApp };
