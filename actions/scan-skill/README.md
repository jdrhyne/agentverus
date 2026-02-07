# AgentVerus Skill Scan (GitHub Action)

Scans `SKILL.md` (and `SKILLS.md`) files in your repository and uploads results to GitHub Code Scanning as SARIF.

## Example Workflow

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

## Inputs

- `target`: file, URL, or directory to scan. Multi-line supported. Default: `.`
- `sarif`: output path. Default: `agentverus-scanner.sarif`
- `fail_on_severity`: `critical|high|medium|low|info|none`. Default: `high`
- `timeout`: URL fetch timeout (ms). Optional.
- `retries`: URL fetch retries. Optional.
- `retry_delay_ms`: base retry delay (ms). Optional.
- `upload_sarif`: `true|false`. Default: `true`

## Outputs

- `sarif_path`
- `targets_scanned`
- `failures`

