# AgentVerus Scanner

Open-source security and behavioral trust scanner for AI agent skills (`SKILL.md` and variants).

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)

## What It Does

Scans agent skill files and produces structured trust reports covering:

- Permission analysis (filesystem/network/exec access)
- Injection detection (prompt injection, instruction override, relay)
- Dependency analysis (external URLs, suspicious downloads)
- Behavioral risk scoring (exfiltration, escalation, stealth patterns)
- Content analysis (obfuscation, concealment, social engineering)

## Install

```bash
npm install --save-dev agentverus-scanner
```

## CLI Usage

```bash
# Scan a local skill file
npx agentverus-scanner scan ./SKILL.md

# Scan a directory (recursively finds SKILL.md / SKILLS.md)
npx agentverus-scanner scan .

# Scan from URL (GitHub blob/tree/repo URLs + ClawHub pages are normalized)
npx agentverus-scanner scan https://github.com/user/repo/blob/main/SKILL.md
npx agentverus-scanner scan https://github.com/user/repo/tree/main/skills/my-skill
npx agentverus-scanner scan https://github.com/user/repo
npx agentverus-scanner scan https://clawhub.ai/<owner>/<slug>

# JSON output
npx agentverus-scanner scan ./SKILL.md --json

# SARIF output for GitHub Code Scanning (fail the job on high/critical findings)
npx agentverus-scanner scan . --sarif agentverus-scanner.sarif --fail-on-severity high
```

Exit codes:

- `0`: scan passed
- `1`: scan completed but policy failed
- `2`: one or more targets failed to scan (incomplete results)

## GitHub Action

Use the bundled action to scan `SKILL.md` in PRs and upload SARIF to GitHub Code Scanning:

```yaml
name: Skill Trust Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: agentverus/agentverus-scanner/actions/scan-skill@main
        with:
          target: .
          fail_on_severity: high
          upload_sarif: true
```

## MCP Server (Agent Integration)

Starts an MCP server over stdio exposing tools:

- `scan_skill` (scan by `url`, `path`, or raw `content`)
- `normalize_skill_url` (normalize GitHub/ClawHub URLs into scan-ready URLs)

```bash
npx agentverus-scanner-mcp
```

Example Claude Desktop config:

```json
{
  "mcpServers": {
    "agentverus-scanner": {
      "command": "npx",
      "args": ["-y", "agentverus-scanner-mcp"]
    }
  }
}
```

## Programmatic Usage

```ts
import { scanSkill, scanSkillFromUrl } from "agentverus-scanner";

const report1 = await scanSkill("# My Skill\\n...");
console.log(report1.overall, report1.badge);

const report2 = await scanSkillFromUrl("https://raw.githubusercontent.com/user/repo/main/SKILL.md", {
  timeout: 30_000,
  retries: 2,
  retryDelayMs: 750
});
console.log(report2.metadata.skillFormat, report2.findings.length);
```

## Trust Score

Overall score is a weighted average of category scores:

| Category | Weight |
|----------|--------|
| Permissions | 25% |
| Injection | 30% |
| Dependencies | 20% |
| Behavioral | 15% |
| Content | 10% |

## Badge Tiers

Badge tier rules:

- Any **critical** finding: `REJECTED`
- Score `< 50`: `REJECTED`
- Score `50–74`: `SUSPICIOUS`
- Score `75–89` with `<= 2` high findings: `CONDITIONAL`
- Score `>= 90` with `0` high findings: `CERTIFIED`

## ASST Taxonomy

Findings reference the AgentVerus skill security taxonomy:

- **ASST-01**: Instruction Injection
- **ASST-02**: Data Exfiltration
- **ASST-03**: Privilege Escalation
- **ASST-04**: Dependency Hijacking
- **ASST-05**: Credential Harvesting
- **ASST-06**: Prompt Injection Relay
- **ASST-07**: Deceptive Functionality
- **ASST-08**: Excessive Permissions
- **ASST-09**: Missing Safety Boundaries
- **ASST-10**: Obfuscation

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm lint

# Build the action bundle (writes actions/scan-skill/dist/index.cjs)
pnpm build:actions
```

## License

MIT — see [LICENSE.md](./LICENSE.md).

