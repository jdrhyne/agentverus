import { describe, expect, it } from "vitest";
import { createAttestation, getOrCreateKeyPair, verifyAttestation } from "../../src/lib/crypto.js";

describe("Cryptographic Attestation", () => {
	it("should create and verify an attestation", () => {
		const keyPair = getOrCreateKeyPair();
		expect(keyPair.privateKey).toBeTruthy();
		expect(keyPair.publicKey).toBeTruthy();

		const data = {
			skillId: "test-skill-id",
			contentHash: "abc123",
			trustScore: 95,
			badge: "certified",
			scanDate: "2026-02-06T00:00:00Z",
			certificationId: "test-cert-id",
			expiresAt: "2027-02-06T00:00:00Z",
			issuer: "AgentVerus",
		};

		const attestation = createAttestation(data);
		expect(attestation).toBeTruthy();
		expect(typeof attestation).toBe("string");

		const valid = verifyAttestation(attestation);
		expect(valid).toBe(true);
	});

	it("should detect tampered attestations", () => {
		const data = {
			skillId: "test-skill-id",
			contentHash: "abc123",
			trustScore: 95,
			badge: "certified",
			scanDate: "2026-02-06T00:00:00Z",
			certificationId: "test-cert-id",
			expiresAt: "2027-02-06T00:00:00Z",
			issuer: "AgentVerus",
		};

		const attestation = createAttestation(data);

		// Tamper with it
		const decoded = JSON.parse(Buffer.from(attestation, "base64url").toString("utf-8"));
		decoded.data.trustScore = 100; // tamper
		const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64url");

		const valid = verifyAttestation(tampered);
		expect(valid).toBe(false);
	});

	it("should return false for invalid attestation strings", () => {
		expect(verifyAttestation("not-valid")).toBe(false);
		expect(verifyAttestation("")).toBe(false);
	});
});
