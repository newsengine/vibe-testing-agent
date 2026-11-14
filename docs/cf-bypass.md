# Cloudflare bot / Access bypass

For probing your own sites behind Cloudflare Bot Fight Mode / WAF or Cloudflare Access.
Secrets are only attached to hosts you list; both allowlists are empty by default.

| Env var | Header | Scope |
|---|---|---|
| `CF_SMOKE_KEY` / `X_SMOKE_KEY` | `x-smoke-key` | hosts in `VTA_SMOKE_KEY_HOSTS` (legacy alias: `SMOKE_KEY`) |
| `CF_ACCESS_CLIENT_ID` | `CF-Access-Client-Id` | hosts in `VTA_CF_ACCESS_HOSTS` |
| `CF_ACCESS_CLIENT_SECRET` | `CF-Access-Client-Secret` | hosts in `VTA_CF_ACCESS_HOSTS` |

Allowlist syntax: comma- or space-separated hostnames. `example.com` matches that exact host;
`*.example.com` matches any subdomain (list the apex separately if you want it too).

Implementation: [`src/cf-bypass-headers.ts`](../src/cf-bypass-headers.ts).

- **HTTP / CLI scan:** merges into same-origin `extraHeaders` via `withCfBypassHeaders(url)` (per target URL).
- **Browser (`browse`):** uses `installCfBypassRoute(context)`, host-filtered per request. Never puts Access/smoke secrets on context-global `extraHTTPHeaders` (those would leak to third-party fonts/CDNs).

```bash
set -a; source ./cf-bot.env; set +a   # chmod 600, outside git
VTA_SMOKE_KEY_HOSTS='example.com,*.example.com' VTA_CF_ACCESS_HOSTS='staging.example.com' \
  npx vibetesting-agent https://staging.example.com --only security
```

CI: pass the secrets into `.github/workflows/probe.yml`, and the host lists via its `smoke_key_hosts` /
`cf_access_hosts` inputs.
