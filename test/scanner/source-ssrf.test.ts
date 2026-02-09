import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fetchSkillContentFromUrl } from "../../src/scanner/source.js";

describe("fetchSkillContentFromUrl SSRF IPv6 blocking", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		// Default mock: return a tiny valid markdown body.
		const fetchMock = vi.fn(async () => {
			return new Response("# OK\n", {
				status: 200,
				headers: { "content-type": "text/markdown" },
			});
		});
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = fetchMock;
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	it("blocks deprecated site-local fec0::/10", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[fec0::1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks IPv4-mapped IPv6 that maps to loopback", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[::ffff:127.0.0.1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks IPv4-compatible IPv6 that maps to loopback", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[::127.0.0.1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks Teredo 2001:0000::/32", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[2001:0::1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks 6to4 when embedded IPv4 is private", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[2002:0a00:0001::]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("allows global IPv6 literals", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		const { content } = await fetchSkillContentFromUrl("https://[2001:4860:4860::8888]/SKILL.md", {
			retries: 0,
			timeout: 0,
		});
		expect(content).toContain("# OK");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("allows 6to4 when embedded IPv4 is public", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		const { content } = await fetchSkillContentFromUrl("https://[2002:0808:0808::]/SKILL.md", {
			retries: 0,
			timeout: 0,
		});
		expect(content).toContain("# OK");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

