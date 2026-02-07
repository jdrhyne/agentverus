import {
	createSign,
	createVerify,
	generateKeyPairSync,
} from "node:crypto";

interface AttestationData {
	readonly skillId: string;
	readonly skillUrl?: string;
	readonly contentHash: string;
	readonly trustScore: number;
	readonly badge: string;
	readonly scanDate: string;
	readonly certificationId: string;
	readonly expiresAt: string;
	readonly issuer: string;
}

interface SignedAttestation {
	readonly data: AttestationData;
	readonly signature: string;
	readonly publicKeyId: string;
}

/** Cached key pair */
let cachedKeyPair: { privateKey: string; publicKey: string } | null = null;

/** Get or create ECDSA P-256 key pair */
export function getOrCreateKeyPair(): { privateKey: string; publicKey: string } {
	if (cachedKeyPair) return cachedKeyPair;

	const envKey = process.env.API_SIGNING_KEY;
	if (envKey && envKey.length > 10) {
		// Assume PEM format stored as base64
		try {
			const decoded = Buffer.from(envKey, "base64").toString("utf-8");
			cachedKeyPair = { privateKey: decoded, publicKey: "" };
			return cachedKeyPair;
		} catch {
			// Fall through to generate
		}
	}

	// Generate a new key pair
	const { privateKey, publicKey } = generateKeyPairSync("ec", {
		namedCurve: "P-256",
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});

	cachedKeyPair = { privateKey, publicKey };
	return cachedKeyPair;
}

/** Create a signed attestation document */
export function createAttestation(data: AttestationData): string {
	const keyPair = getOrCreateKeyPair();
	const canonicalJson = JSON.stringify(data, Object.keys(data).sort());

	const sign = createSign("SHA256");
	sign.update(canonicalJson);
	sign.end();

	const signature = sign.sign(keyPair.privateKey, "base64url");

	const attestation: SignedAttestation = {
		data,
		signature,
		publicKeyId: "agentverus-v1",
	};

	return Buffer.from(JSON.stringify(attestation)).toString("base64url");
}

/** Verify a signed attestation document */
export function verifyAttestation(attestationBase64: string): boolean {
	try {
		const decoded = JSON.parse(
			Buffer.from(attestationBase64, "base64url").toString("utf-8"),
		) as SignedAttestation;

		const keyPair = getOrCreateKeyPair();
		if (!keyPair.publicKey) return false;

		const canonicalJson = JSON.stringify(
			decoded.data,
			Object.keys(decoded.data).sort(),
		);

		const verify = createVerify("SHA256");
		verify.update(canonicalJson);
		verify.end();

		return verify.verify(keyPair.publicKey, decoded.signature, "base64url");
	} catch {
		return false;
	}
}

/** Get the public key in PEM format for the well-known endpoint */
export function getPublicKeyPem(): string {
	const keyPair = getOrCreateKeyPair();
	return keyPair.publicKey;
}
