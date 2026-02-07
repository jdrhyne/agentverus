# State of Agent Skill Security: We Scanned {TOTAL_SKILLS} AI Agent Skills. Here's What We Found.

*Published: February 2026 | By AgentTrust Research*

---

## Executive Summary

We built an automated security scanner and ran it against **{TOTAL_SKILLS}** publicly available AI agent skill files from GitHub, OpenClaw, and other sources. The results confirm what security researchers have been warning about: **the AI agent skill ecosystem has a serious trust problem.**

Key findings:
- **{PCT_CRITICAL}%** of skills contain at least one critical security issue
- **{PCT_HIGH}%** have high-severity findings
- The average trust score is just **{AVG_SCORE}/100**
- Only **{PCT_CERTIFIED}%** of skills meet our CERTIFIED standard
- Instruction injection (ASST-01) is the #1 threat

## The Problem

AI agents are the new software. Skills are the new packages. And just like the npm ecosystem learned the hard way with left-pad, event-stream, and ua-parser-js — open publishing without trust verification creates supply chain risk.

Except this time, the stakes are higher. Agent skills can:
- Read your files and environment variables
- Make network requests with your credentials
- Execute arbitrary code on your machine
- Interact with other agents on your behalf

Gen Digital's January 2026 report found that **15% of OpenClaw skills contain malicious instructions.** Our data tells a more nuanced story.

## Methodology

### The ASST Taxonomy

We developed **ASST** (Agent Skill Security Threats), an OWASP-style categorization system for agent skill vulnerabilities:

| ID | Category | Description |
|----|----------|-------------|
| ASST-01 | Instruction Injection | Hidden directives that override agent behavior |
| ASST-02 | Data Exfiltration | Instructions to send user data to external endpoints |
| ASST-03 | Privilege Escalation | Requesting permissions beyond stated purpose |
| ASST-04 | Dependency Hijacking | Suspicious external URL references |
| ASST-05 | Credential Harvesting | Attempts to access secrets and tokens |
| ASST-06 | Prompt Injection Relay | Injecting prompts into downstream LLMs |
| ASST-07 | Deceptive Functionality | Claiming one purpose while doing another |
| ASST-08 | Excessive Permissions | More access than needed |
| ASST-09 | Missing Safety Boundaries | No explicit constraints on behavior |
| ASST-10 | Obfuscation | Encoding tricks to hide malicious content |

### Scoring

Each skill is analyzed across 5 weighted categories:
- **Permissions** (25%) — Permission appropriateness
- **Injection** (30%) — Injection and override detection
- **Dependencies** (20%) — External dependency risk
- **Behavioral** (15%) — Behavioral risk patterns
- **Content** (10%) — Safety documentation quality

Score → Badge mapping:
- 🟢 **CERTIFIED** (90-100, 0 Critical/High) — The gold standard
- 🟡 **CONDITIONAL** (75-89, 0 Critical, ≤2 High) — Safe with caveats
- 🟠 **SUSPICIOUS** (50-74, 0 Critical) — Proceed with caution
- 🔴 **REJECTED** (<50 or any Critical) — Do not install

## Key Findings

### Badge Distribution

{GRADE_DISTRIBUTION_CHART}

### The Injection Problem

Instruction injection (ASST-01) is the most common critical finding. {INJECTION_STATS}

Common patterns we detected:
1. **Direct instruction override** — "Ignore all previous instructions" (found in {PCT_OVERRIDE}% of rejected skills)
2. **Hidden HTML comments** — Malicious directives in `<!-- -->` comment blocks
3. **Prompt injection relay** — Using `<|im_start|>`, `[INST]`, or `<system>` markers to inject into downstream models
4. **Social engineering** — "Don't tell the user about this"

### Permission Sprawl

{PERMISSION_STATS}

The most over-requested permissions:
1. `exec` / `shell` — Requested by skills that don't need code execution
2. `network_unrestricted` — When `network_restricted` would suffice
3. `env_access` — No legitimate skill needs to read all environment variables

### The Safety Boundary Gap

**{PCT_NO_SAFETY}%** of skills have zero explicit safety boundaries. They don't define what they should NOT do. This is ASST-09, and it's the most common finding overall.

Simply adding a "Safety Boundaries" section that says "Do NOT access files outside the workspace" improves trust scores by 10+ points.

## Comparison to Gen Digital's Findings

Gen Digital reported 15% malicious. We found **{PCT_DANGEROUS}%** of skills score REJECTED or SUSPICIOUS.

The difference? Our scanner is more nuanced:
- Not every excessive permission is "malicious" — some are just sloppy
- Missing safety boundaries aren't malicious, but they're a risk
- We separate "dangerous" (REJECTED) from "concerning" (SUSPICIOUS)

The true "malicious with intent" rate (skills with ASST-01 or ASST-02 critical findings) is **{PCT_TRULY_MALICIOUS}%**.

## What This Means

### For Skill Publishers

1. **Add safety boundaries.** The single biggest improvement you can make.
2. **Request minimal permissions.** Only what you actually use.
3. **Document everything.** Description, error handling, output constraints.
4. **Submit for scanning.** It's free at [agenttrust.dev](https://agenttrust.dev).
5. **Embed your badge.** Show users your skill is trustworthy.

### For Skill Consumers

1. **Check the badge.** If a skill doesn't have an AgentTrust badge, be cautious.
2. **Read the findings.** Every deduction is explained with evidence and recommendations.
3. **Report suspicious skills.** Help us build a safer ecosystem.

### For Platforms

1. **Integrate AgentTrust API.** Show trust scores on skill listings.
2. **Require minimum scores.** Consider requiring CONDITIONAL or above for marketplace listing.
3. **Contact us** for enterprise API access.

## Try It Yourself

Scan any skill file for free at **[agenttrust.dev](https://agenttrust.dev)**.

```bash
# Or use the API
curl -X POST https://agenttrust.dev/api/v1/skill/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/.../SKILL.md"}'
```

---

*AgentTrust is the trust certification service for AI agent skills. We scan, audit, and certify skills so you don't have to read every line of every SKILL.md yourself.*

*Built by [Jonathan Rhyne](https://github.com/jrhyne). Data and methodology are open.*
