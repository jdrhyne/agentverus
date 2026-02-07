# agentverus-scanner-mcp

MCP server wrapper for [`agentverus-scanner`](https://github.com/agentverus/agentverus-scanner).

Exposes MCP tools:

- `scan_skill` (scan by `url`, `path`, or raw `content`)
- `normalize_skill_url` (normalize GitHub/ClawHub URLs into scan-ready URLs)

## Run

```bash
npx -y agentverus-scanner-mcp
```

## Claude Desktop Config Example

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

