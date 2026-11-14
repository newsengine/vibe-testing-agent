# VibeTesting Agent (hosted)

**https://vibetestingagent.com**

Hosted continuous security scanning for vibe-coded apps. Powered by the open-source
[`vibetesting-agent`](https://github.com/newsengine/vibe-testing-agent) engine.

## Plans

| Plan | Price | Cadence |
|---|---|---|
| Lite (public) | $0 | Homepage lite scan (secrets, exposure, headers, DNS) |
| Weekly | **$25/mo** | 1 full scan / week · 1 verified project |
| Daily | **$100/mo** | Daily full scans · deploy hooks |
| Every commit | **$250/mo** | Scan on every push/deploy |

**Ownership required** for all paid full scans:
1. **Domain email** — sign in with an address on the app domain, then click the one-time inbox verify link we email you, **or**
2. **DNS TXT** — `vibetesting-verify=<token>` on the host or `_vta.<host>`.

## Stack

- Next.js App Router dashboard + API
- WorkOS AuthKit (preferred) + GitHub OAuth fallback
- Stripe Checkout + Customer Portal
- SQLite (Drizzle) locally; swap to D1/Postgres in prod
- Scanner: monorepo parent `vibetesting-agent` / `dist/cli.js`

## Local dev

```bash
cd vibetesting-agent
cp .env.example .env
# ALLOW_DEV_LOGIN=1 for local
npm install
cd .. && npm run build && cd vibetesting-agent
npm run dev
```

Open http://localhost:3000 — free lite scan on the homepage.

## Env

See [`.env.example`](./.env.example).

### WorkOS

1. Create AuthKit app at workos.com  
2. Redirect URI: `https://vibetestingagent.com/api/auth/workos/callback`  
3. Set `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`

### Stripe

Create three recurring prices and set:

- `STRIPE_PRICE_WEEKLY` → $25  
- `STRIPE_PRICE_DAILY` → $100  
- `STRIPE_PRICE_COMMIT` → $250  

Webhook: `/api/webhooks/stripe`

## DNS (Cloudflare)

Zone: `vibetestingagent.com` (id `777bc52b38dc71ffb4def93cd58ed92b`)

Recommended records after deploy:

| Type | Name | Content |
|---|---|---|
| CNAME | `@` | `<your-pages-or-worker-host>` (proxied) |
| CNAME | `www` | `vibetestingagent.com` (proxied) |

Use a token with **Zone DNS Edit** (current account token may be read-only for DNS writes).  
Helper: `scripts/configure-dns.sh`

## Open source

- Scanner engine: https://github.com/newsengine/vibe-testing-agent (Apache-2.0)  
- Brand / docs entry: https://github.com/newsengine/vibe-testing-agent  

Hosted multi-tenant billing remains proprietary configuration; the scan engine is OSS.
