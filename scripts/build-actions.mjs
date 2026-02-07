import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { build } from "esbuild";

const OUTFILE = "actions/scan-skill/dist/index.cjs";

await mkdir(dirname(OUTFILE), { recursive: true });

await build({
	entryPoints: ["actions/scan-skill/src/index.ts"],
	outfile: OUTFILE,
	platform: "node",
	target: "node20",
	format: "cjs",
	bundle: true,
	minify: false,
	sourcemap: false,
	logLevel: "info",
});

