# Cloudflare Workers deploy

VibeTesting Agent runs on **Cloudflare Workers** via OpenNext + **D1**.

## Live URL (now)

**https://vibetestingagent.com** (plus the account `*.workers.dev` URL for the `vibetesting-agent` Worker)

## Architecture

| Piece | Cloudflare resource |
|---|---|
| App | Worker `vibetesting-agent` (OpenNext) |
| Database | D1 `vibetesting-agent` (`ecb9fca5-9769-49e1-b284-04ba7a5d3f2a`) |
| Scans | Workers-safe fetch scanner (headers, exposure, secrets, DNS) |
| Secrets | Wrangler secrets (WorkOS, Stripe, session) |

## Commands

```bash
cd vibetesting-agent

# D1 migrations
npm run db:migrate:remote

# Deploy
npm run deploy

# Local Workers runtime preview
npm run preview
```

## Custom domain `vibetestingagent.com`

In Cloudflare Dashboard → **Workers & Pages** → **vibetesting-agent** → **Settings** → **Domains & Routes** → **Add** → `vibetestingagent.com` and `www`.

Or DNS (zone already exists):

| Type | Name | Content | Proxy |
|---|---|---|---|
| CNAME | `@` | `vibetesting-agent.<account-subdomain>.workers.dev` | Proxied* |
| CNAME | `www` | `vibetesting-agent.<account-subdomain>.workers.dev` | Proxied |

\*Apex CNAME works on Cloudflare when proxied (CNAME flattening).

Also add Worker custom domain so TLS + routing attach correctly.

## WorkOS

Redirect URIs:

```
https://vibetesting-agent.<account-subdomain>.workers.dev/api/auth/workos/callback
https://vibetestingagent.com/api/auth/workos/callback
http://localhost:3000/api/auth/workos/callback
```

## Redeploy after env/code changes

```bash
npm run deploy
```

## Why this works on Workers

- No `better-sqlite3` on the edge — **D1** instead  
- Scans use **fetch** (no child_process / Playwright)  
- OpenNext bundles Next.js App Router for Workers + Assets  
