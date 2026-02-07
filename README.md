# AgentVerus

**Trust, but verify.** Security certification for AI agent skills.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-72%20passing-brightgreen)](.)

---

## The Problem

Agent skills are the new npm packages — open publishing, dependency chains, and zero vetting. Security researchers have found **341 malicious skills** on ClawHub alone (Koi Security), with attacks ranging from credential theft to reverse shells. Cisco's research shows **26% contain at least one vulnerability**.

Skills are just markdown files with instructions. But a skill isn't a feature — **it's a behavior**. When you install one, you're granting an AI agent new capabilities with access to your files, credentials, and APIs.

## What AgentVerus Does

AgentVerus scans skill files and produces two independent trust signals:

### 🔍 Technical Badge — Is this skill safe?

Static analysis across 5 categories (10 ASST threat types):

| Category | Weight | Detects |
|----------|--------|---------|
| Injection | 30% | Prompt injection, concealment directives, system override attempts |
| Permissions | 25% | Credential access, excessive privileges, undeclared capabilities |
| Dependencies | 20% | Suspicious URLs, remote code downloads, dynamic execution |
| Behavioral | 15% | System modification, autonomous actions, scope violations |
| Content | 10% | Missing safety boundaries, obfuscation, hardcoded secrets |

**Tiers:** 🟢 CERTIFIED (≥90) · 🟡 CONDITIONAL (75-89) · 🟠 SUSPICIOUS (50-74) · 🔴 REJECTED (<50)

### 📈 Adoption Badge — Is this skill real?

Aggregated usage signals from skills.sh, GitHub, and ClawHub:

| Tier | Score | Meaning |
|------|-------|---------|
| 🥇 WIDELY_USED | 70-100 | 10K+ installs, actively maintained |
| 🔵 GAINING_ADOPTION | 40-69 | 1K-10K installs, growing |
| 🟢 EARLY | 10-39 | 100-1K installs, new but present |
| ⬜ NOT_ADOPTED | 0-9 | <100 installs |

**Formula:** Popularity × 0.40 + Freshness × 0.35 + Maturity × 0.25

## Declared Permissions

AgentVerus rewards transparency. Skills can declare what they need in YAML frontmatter:

```yaml
---
name: my-skill
permissions:
  - credential_access: "API_KEY for authentication"
  - network: "HTTPS calls to api.example.com"
  - file_write: "Output files to working directory"
---
```

**Declared + Detected** = info (0 deduction) — you told users what you do.
**Undeclared + Detected** = full penalty — you're hiding something.
**Declared + Not Detected** = low (2pt deduction) — over-declared but honest.

## Quick Start

```bash
# Clone and install
git clone https://github.com/jdrhyne/agentverus.git
cd agentverus && pnpm install

# Scan a skill
pnpm scan path/to/SKILL.md

# Scan with JSON output
pnpm scan path/to/SKILL.md --json

# Bulk scan a directory
pnpm bulk-scan path/to/skills/
```

## ASST Taxonomy

Our OWASP-style classification for agent skill threats:

| ID | Threat | Example |
|----|--------|---------|
| ASST-01 | Instruction Injection | "Ignore previous instructions", concealment directives |
| ASST-02 | Data Exfiltration | Credential harvest → webhook POST |
| ASST-03 | Privilege Escalation | Weather skill requesting exec permissions |
| ASST-04 | Dependency Hijacking | `curl \| sh` from unknown domains |
| ASST-05 | Credential Harvesting | Reading ~/.ssh/id_rsa, hardcoded API keys |
| ASST-06 | Prompt Injection Relay | Injecting instructions into downstream LLMs |
| ASST-07 | Deceptive Functionality | Description doesn't match actual behavior |
| ASST-08 | Excessive Permissions | Spell checker requesting all tool access |
| ASST-09 | Missing Safety Boundaries | No explicit constraints on agent behavior |
| ASST-10 | Obfuscation | Base64/hex encoded payloads, XOR ciphers |

## Example Output

```
AgentVerus Scanner v0.1.0
────────────────────────────────────────────────────────────

Overall Score:  98/100
Badge:          CERTIFIED
Format:         openclaw
Duration:       3ms

Category Scores:
  injection       ██████████████████████████████████████████████████ 100/100 (weight: 30%)
  permissions     ██████████████████████████████████████████████████ 100/100 (weight: 25%)
  dependencies    ██████████████████████████████████████████████████ 100/100 (weight: 20%)
  behavioral      ██████████████████████████████████████████████████ 100/100 (weight: 15%)
  content         ████████████████████████████████████████░░░░░░░░░░  80/100 (weight: 10%)

Findings (1):
  LOW (1)
    ● No explicit safety boundaries
```

## How We Compare

| | AgentVerus | Cisco Skill Scanner | Alice Caterpillar | Koi ClawDex |
|---|---|---|---|---|
| **Type** | Trust platform | Scan tool | Scan tool | Database lookup |
| **Technical scan** | ✅ 5 analyzers | ✅ YAML/YARA + AST | ✅ Pattern-based | ❌ IOC matching |
| **Adoption signals** | ✅ skills.sh + GitHub | ❌ | ❌ | ❌ |
| **Declared permissions** | ✅ Transparency rewarded | ❌ | ❌ | ❌ |
| **Dual badges** | ✅ Technical + Adoption | ❌ | ❌ Letter grade | ❌ |
| **Registry** | ✅ (planned) | ❌ | ❌ | ✅ Malicious only |
| **Cross-platform** | ✅ Any SKILL.md | ✅ Codex/Cursor | ✅ OpenClaw-focused | ❌ ClawHub only |

## Tech Stack

- **TypeScript** / Node.js 22+
- **Hono** — Web framework
- **PostgreSQL** — Neon Serverless
- **Drizzle ORM** — Type-safe DB
- **Vitest** — 72+ tests

## Development

```bash
pnpm install
cp .env.example .env
pnpm dev          # Start dev server
pnpm test         # Run tests
pnpm scan <file>  # Scan a skill
pnpm lint         # Lint
pnpm typecheck    # Type check
```

## Project Structure

```
src/
├── scanner/           # Core scan engine
│   ├── analyzers/     # 5 analyzers + declared permissions matching
│   ├── parser.ts      # Multi-format SKILL.md parser
│   ├── scoring.ts     # Weighted score aggregation
│   └── cli.ts         # CLI interface
├── adoption/          # Adoption signal aggregation
│   ├── skills-sh.ts   # skills.sh scraper
│   ├── github.ts      # GitHub API client
│   └── scoring.ts     # Adoption score calculator
├── badges/            # SVG badge generators
│   ├── generator.ts   # Technical trust badge
│   └── adoption-generator.ts  # Adoption badge
├── api/v1/            # REST API routes
├── web/               # Landing pages (htmx)
├── db/                # Database schema
└── email/             # Notification system
scripts/
├── bulk-scan.ts       # Scan directories of skills
├── collect-skills.ts  # Collect skills from registries
└── generate-report.ts # Generate scan reports
```

## License

MIT

---

Built by [Jonathan Rhyne](https://github.com/jdrhyne). Securing the agentic web, one skill at a time.
