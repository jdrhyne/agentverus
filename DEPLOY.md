# Deployment Guide

## Prerequisites

- Node.js 22+
- pnpm 10+
- A Neon PostgreSQL database
- (Optional) Resend API key for email notifications

## Environment Setup

1. Copy `.env.example` to `.env` and fill in values:
   ```bash
   cp .env.example .env
   ```

2. Required environment variables:
   - `DATABASE_URL` — Neon Postgres connection string
   - `NODE_ENV` — `production` for deployed environments
   - `BASE_URL` — Your deployment URL (e.g., `https://agentverus.ai`)

3. Optional:
   - `RESEND_API_KEY` — For email notifications
   - `API_SIGNING_KEY` — For attestation signing (auto-generated if not set)
   - `ADMIN_API_KEY` — For admin API access

## Local Development

```bash
pnpm install
pnpm dev         # Start dev server with hot reload on port 3000
pnpm test        # Run all tests
pnpm typecheck   # TypeScript check
pnpm lint        # Biome lint
```

## Production Build

```bash
pnpm build       # Compile TypeScript to dist/
node dist/index.js  # Start production server
```

## Database Setup

```bash
# Push schema to database (creates tables)
pnpm db:push

# Or run migrations
pnpm db:migrate
```

## Cloudflare Workers Deployment

1. Install Wrangler:
   ```bash
   pnpm add -D wrangler
   ```

2. Configure `wrangler.toml` (create if needed):
   ```toml
   name = "agent-verus"
   main = "src/index.ts"
   compatibility_date = "2026-02-06"
   node_compat = true
   ```

3. Set secrets:
   ```bash
   wrangler secret put DATABASE_URL
   wrangler secret put RESEND_API_KEY
   wrangler secret put API_SIGNING_KEY
   ```

4. Deploy:
   ```bash
   wrangler deploy
   ```

## Custom Domain (agentverus.ai)

1. Add domain to Cloudflare dashboard
2. Update DNS records to point to Workers
3. Configure custom domain in Workers settings

## Alternative: Node.js Deployment

Deploy as a standard Node.js application on any platform:

- **Railway:** Connect GitHub repo, set env vars, auto-deploys
- **Fly.io:** `fly launch`, configure Dockerfile
- **Render:** Connect repo, set env vars
- **Docker:**
  ```dockerfile
  FROM node:22-alpine
  WORKDIR /app
  COPY . .
  RUN corepack enable && pnpm install --frozen-lockfile && pnpm build
  EXPOSE 3000
  CMD ["node", "dist/index.js"]
  ```

## CLI Usage

```bash
# Scan a local skill file
pnpm scan test/fixtures/skills/safe-basic.md

# Scan with JSON output
pnpm scan test/fixtures/skills/safe-basic.md --json

# Scan from URL
pnpm scan --url https://raw.githubusercontent.com/.../SKILL.md

# Bulk scan
pnpm bulk-scan data/skill-urls.txt
```
