# Changelog

All notable changes to the AgentVerus Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-08

### Added

- **Universal pre-install gate** (`agentverus check`): Accept any skill source — not just ClawHub slugs. Supported formats:
  - ClawHub slug: `agentverus check web-search` (backward compatible)
  - GitHub shorthand: `agentverus check owner/repo`
  - GitHub multi-skill: `agentverus check owner/repo/skill-name`
  - GitHub URL: `agentverus check https://github.com/owner/repo`
  - skills.sh URL: `agentverus check https://skills.sh/owner/repo/skill`
  - Local file: `agentverus check ./SKILL.md`
- **Multi-skill repo discovery**: For `owner/repo` inputs, auto-discovers all SKILL.md files via GitHub tree API. Tries `main` then `master` branch. Reports on each skill independently.
- **`--install` flag**: Scan → verdict → confirmation prompt → `npx skills add <source>`. Security warning shown if scan doesn't pass.
- **`--yes` flag**: Skip confirmation prompts for CI/non-interactive pipelines. TTY detection prevents accidental installs in scripts.
- **`--help` flag**: Detailed usage text with examples for the check command.
- **`resolveSkillsShUrl()`**: New exported function to resolve a single skills.sh URL to a raw GitHub SKILL.md URL (previously only batch resolution was supported).
- **skills.sh scanner** (`agentverus registry skillssh`): Resolve and scan 2,300+ GitHub-hosted skills from the skills.sh sitemap. Generates the same JSON/CSV/report/site outputs as the ClawHub registry scanner.
- **AGENTS.md**: Comprehensive guide for AI coding agents working on the codebase — covers architecture, ASST taxonomy, analyzer rules, scoring weights, CLI usage, GitHub Action, zero-dependency philosophy, and relationship to the web repo.

### Fixed

- **False positive reduction**: Self-referencing URLs (e.g., a skill's own GitHub repo URL) and API documentation URLs no longer trigger suspicious external URL findings.
- **Deep context analysis**: Eliminated false positive rejections caused by over-aggressive pattern matching. Improved context-aware analysis for educational/security skills that discuss attack patterns in documentation.
- **Adversarial evasion tests**: Added new tests covering over-correction bugs where legitimate security documentation was being penalized.

### Changed

- **Check command signature**: `agentverus check <slug...>` → `agentverus check <source...>`. Old slug-only usage still works — fully backward compatible.
- **JSON output**: Single-source, single-result checks preserve the flat report shape. Multi-source or multi-result checks use `{ results: [...], failures: [...] }`.
- **CLI help text**: Updated usage, command descriptions, and examples to reflect universal check capabilities.
- **Re-scanned registries**: Both ClawHub and skills.sh registries re-scanned with fixed scanner, all artifacts regenerated.

## [0.1.1] - 2026-01-27

### Added

- **`agentverus check` command**: Check any ClawHub skill by slug — downloads the skill ZIP, extracts SKILL.md, scans it, and prints a formatted trust report with category bars, findings, and a verdict. Supports `--json` output and multiple slugs.
- **Registry batch scanner** (`src/registry/batch-scanner.ts`): Scans the entire ClawHub registry at scale with configurable concurrency (default 25, tested at 50). Outputs JSON results, CSV spreadsheet, summary statistics, and error log. 4,929 skills scanned in ~100 seconds.
- **Registry report generator** (`src/registry/report-generator.ts`): Generates a comprehensive markdown analysis report from scan results — "We Analyzed N AI Agent Skills — Here's What We Found" — with executive summary, badge distribution, VT gap analysis, top findings, and methodology.
- **Registry static site generator** (`src/registry/site-generator.ts`): Produces a single-page interactive HTML dashboard with search, badge filtering, sortable columns, category bar charts, finding pills, and pagination. Includes OpenGraph meta tags.
- **Registry CLI commands**: `agentverus registry scan`, `agentverus registry report`, `agentverus registry site` for the full pipeline.
- **VT gap detection**: The batch scanner identifies skills with critical/high-severity text-based threats (prompt injection, credential exfiltration, deceptive functionality) that fall outside VirusTotal's detection capabilities.
- **`agentverus` bin alias**: The CLI is now available as both `agentverus` and `agentverus-scanner`.
- **Context-aware analysis** (`src/scanner/analyzers/context.ts`): New shared utility that all analyzers use to understand _where_ a pattern match occurs:
  - **Code block detection**: Patterns inside fenced code blocks (` ``` `) or inline code spans are downgraded (severity reduced, deduction at 30%).
  - **Safety section detection**: Patterns inside safety boundary sections (e.g., `## Safety Boundaries`, `## Limitations`) are fully neutralized (zero deduction) — these are positive declarations, not threats.
  - **Negation detection**: Patterns preceded by "do not", "never", "must not", "should not", etc. on the same line are fully neutralized.
- **LLM-assisted semantic analyzer** (`src/scanner/analyzers/semantic.ts`): Optional analyzer that uses an OpenAI-compatible API to detect threats regex patterns miss:
  - Catches rephrased jailbreaks, indirect multi-step exfiltration, and subtle manipulation.
  - Activated via `--semantic` CLI flag or `{ semantic: true }` in `ScanOptions`.
  - Requires `AGENTVERUS_LLM_API_KEY` environment variable (or explicit options).
  - Findings merge into the injection category — they supplement but never replace regex analysis.
  - Gracefully degrades: API failures are silently ignored, never breaking the scan.
- **Adversarial test suite** (`test/scanner/adversarial.test.ts`): 11 tests covering evasion techniques:
  - Security/educational skills with attack examples in code blocks (should NOT be rejected).
  - Skills with safety boundary negations (should NOT be penalized).
  - Genuine prose-level attacks (should still be caught despite context awareness).
  - Indirect exfiltration via URL parameter encoding.
  - Rephrased jailbreak attempts.
- **Context utility tests** (`test/scanner/context.test.ts`): 12 unit tests for code block, safety section, and negation detection.
- **Semantic analyzer tests** (`test/scanner/semantic.test.ts`): 3 tests covering graceful degradation when no API key is configured.
- **5 new adversarial test fixtures**: `evasion-context-safe.md`, `evasion-negation-safe.md`, `evasion-hidden-in-codeblock.md`, `evasion-indirect-exfiltration.md`, `evasion-rephrased-jailbreak.md`.

### Fixed

- **Injection analyzer**: Removed bare `.env` / `.ssh` / `.credentials` / `.secrets` substring match from the data exfiltration pattern — was producing critical findings on skills that merely reference `.env.example` or document environment variable setup.
- **Injection analyzer**: Tightened credential access patterns to require an action verb (`read`, `cat`, `dump`, `steal`, etc.) before sensitive paths. Bare mentions of `API_KEY`, `SECRET_KEY`, `PASSWORD`, etc. in setup documentation no longer trigger high-severity findings.
- **Injection analyzer**: Narrowed data exfiltration regex to require a directive form ("send/post X to URL") rather than matching HTTP method keywords near any URL, which was flagging API authentication code examples.
- **Dependencies analyzer**: Localhost and private IP addresses (`127.0.0.1`, `10.x`, `172.16–31.x`, `192.168.x`) are no longer flagged as suspicious external IPs.
- **Dependencies analyzer**: Expanded the trusted domains list with ~40 additional well-known domains (Google, Microsoft, AWS, Supabase, Stripe, LinkedIn, npm registry, example.com, etc.).
- **Dependencies analyzer**: Capped cumulative deduction from unknown (non-dangerous) URLs at 15 points, preventing skills with extensive API endpoint documentation from being unfairly penalized.
- **Dependencies analyzer**: Download-and-execute detection is now context-aware — patterns inside code blocks or safety sections are skipped.
- **Behavioral analyzer**: `npm install` and `pip install` without `--global` / `-g` flags are no longer flagged as system modification. Only global installs and system package managers (`apt`, `yum`, `dnf`, `pacman`) are flagged.
- **Behavioral analyzer**: Tightened the combined exfiltration flow heuristic to require active credential reading patterns **and** suspicious POST/exfiltration patterns. Previously, any skill mentioning an API key alongside any URL would trigger a high-severity finding.
- **Behavioral analyzer**: Prerequisite trap detection (curl-pipe-to-shell) is now context-aware.

### Changed

- **Test fixtures**: Updated `suspicious-urls.md` to use public IP addresses instead of private IPs for the IP-flagging test.
- **Test fixtures**: Updated `undeclared-permissions.md` to contain genuinely suspicious credential access patterns (e.g. `cat ~/.ssh/id_rsa`) rather than plain keyword mentions.

## [0.1.0] - 2026-01-15

### Added

- Initial release of the AgentVerus Scanner.
- Permission analysis with tiered risk classification (critical/high/medium/low).
- Injection detection covering instruction overrides, exfiltration directives, credential access, prompt injection relay, social engineering, concealment, and unrestricted mode activation.
- Dependency analysis with URL risk classification, download-and-execute detection, and trusted domain allowlisting.
- Behavioral risk scoring for unrestricted scope, system modification, autonomous actions, sub-agent spawning, state persistence, unbounded loops, and financial actions.
- Content analysis with harmful content detection, deception detection, obfuscation detection, hardcoded secret detection, and bonus scoring for safety boundaries, output constraints, and error handling.
- Declared permission matching system that downgrades findings when permissions are explicitly declared and justified.
- Weighted scoring across five categories (permissions 25%, injection 30%, dependencies 20%, behavioral 15%, content 10%).
- Badge tier system: CERTIFIED / CONDITIONAL / SUSPICIOUS / REJECTED.
- ASST taxonomy (ASST-01 through ASST-10) for finding classification.
- CLI with local file, directory, and URL scanning support.
- JSON and SARIF output formats.
- GitHub Action for CI/CD integration with Code Scanning upload.
- MCP server companion package for agent/framework integration.
- OpenClaw, Claude Code, and generic skill format auto-detection.
- ClawHub zip download support and GitHub URL normalization.

[Unreleased]: https://github.com/agentverus/agentverus-scanner/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/agentverus/agentverus-scanner/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/agentverus/agentverus-scanner/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/agentverus/agentverus-scanner/releases/tag/v0.1.0
