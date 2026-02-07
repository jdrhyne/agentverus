# AgentVerus Scanner

Open-source security and behavioral trust scanner for AI agent skills.

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)

## What It Does

Scans AI agent skill files (SKILL.md) and produces structured trust reports covering:

- **Permission analysis** — what tools and access the skill requests
- **Injection detection** — prompt injection, jailbreak attempts, instruction override
- **Dependency analysis** — external URLs, CLI tools, supply chain risk
- **Behavioral risk scoring** — data exfiltration, privilege escalation, stealth patterns
- **Content analysis** — obfuscation, concealment, social engineering

## Install

```bash
npm install agentverus-scanner
```

## CLI Usage

```bash
# Scan a local skill file
npx agentverus-scanner scan ./SKILL.md

# Scan from URL
npx agentverus-scanner scan https://raw.githubusercontent.com/user/repo/main/SKILL.md

# JSON output
npx agentverus-scanner scan ./SKILL.md --json
```

## Programmatic Usage

```typescript
import { scanSkill } from "agentverus-scanner";

const report = await scanSkill(skillContent, {
  source: "https://github.com/user/repo",
});

console.log(report.score);        // 0-100
console.log(report.badge);        // "certified" | "conditional" | "suspicious" | "rejected"
console.log(report.findings);     // detailed findings array
```

## Trust Score

Score is 0–100, calculated from weighted category scores:

| Category | Weight | What It Checks |
|----------|--------|----------------|
| Permissions | 25% | Tool access scope, filesystem/network/exec usage |
| Injection | 25% | Prompt injection, jailbreaks, instruction overrides |
| Dependencies | 15% | External URLs, CLI deps, supply chain |
| Behavioral | 20% | Exfiltration, escalation, stealth, obfuscation |
| Content | 15% | Social engineering, concealment, encoding |

## Badge Tiers

| Badge | Score | Meaning |
|-------|-------|---------|
| CERTIFIED | 80–100, no critical findings | Safe to use |
| CONDITIONAL | 60–79, no critical findings | Review recommended |
| SUSPICIOUS | 40–59, or has high-severity findings | Use with caution |
| REJECTED | <40, or has critical findings | Do not use |

## OWASP-Style Taxonomy

Findings reference the AgentVerus skill security taxonomy:

- **ASST-01**: Excessive Permission Requests
- **ASST-02**: Prompt Injection / Instruction Override
- **ASST-03**: Data Exfiltration Patterns
- **ASST-04**: Privilege Escalation
- **ASST-05**: Malicious External Dependencies
- **ASST-06**: Obfuscation / Concealment
- **ASST-07**: Social Engineering
- **ASST-08**: Supply Chain Risk
- **ASST-09**: Undeclared Capabilities

## Development

```bash
pnpm install
pnpm test        # 53 tests
pnpm typecheck
pnpm lint
```

## License

MIT — see [LICENSE.md](./LICENSE.md). Free forever, no restrictions.

The [AgentVerus Trust Registry](https://agentverus.ai) is licensed separately under the AgentVerus Community License.
