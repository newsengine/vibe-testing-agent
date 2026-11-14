# Generic access-control suite

Config-driven security checks generalized from a large app-specific Playwright suite into checks that run against **any deployed app** — a URL plus a few auth tokens.
No backend, no test server, no browser: plain `fetch` over the shipped `vibetesting-agent` testkit.

## What it checks

| Check | Generalized from | Asserts |
|-------|------------------|---------|
| Auth enforcement + RBAC | batch-07/13/14/15-rbac, issue-32, admin-lockdown | anon→401, wrong-role→403, allowed role→not-denied, per endpoint |
| Owner-scoped data isolation | batch-12-data-isolation, batch-17-user-isolation-deep | two users' list responses share no resource ids |
| Mass assignment / privilege escalation | batch-13/14/17 mass-assignment, status-escalation | server ignores client-forged `author_id`/`status`/… |
| Sensitive-field leakage | batch-10 auth-debug secrets | responses don't return `password`/`access_token`/`service_role`/… |

Cross-tenant (multi-tenant) isolation has its own browser recipe in `../tenant-isolation/`.
The scanner itself (`vibetesting-agent <url>`) still covers headers/TLS/CORS/cookies/open-redirect/exposure/
secrets/DNS/SEO/a11y/perf/agent-readiness — and now **auth-debug endpoint secret leakage**.

## Use

```bash
npm run build
cp examples/security-suite/config.example.json examples/security-suite/config.json
# edit config.json: your baseURL, endpoints, and which role should be allowed on each
export USER_TOKEN=…  EDITOR_TOKEN=…  ADMIN_TOKEN=…   # config references ${VAR}, so no secrets committed
node examples/security-suite/run.mjs examples/security-suite/config.json
```

Exit code is non-zero if any check fails, so it drops straight into CI. `config.json` is git-ignored.

**Framework presets:** `presets/` has starter configs per stack (`nextjs.json`, `rails.json`,
`laravel.json`) with the endpoints/fields those frameworks typically expose. Copy one, adapt the paths
and roles to your app, and set tokens via env:

```bash
export USER_TOKEN=…  ADMIN_TOKEN=…
node examples/security-suite/run.mjs examples/security-suite/presets/rails.json
```

## What was deliberately dropped (app-specific, not generalizable)

Audit-log schema/filtering, session-persistence UI flows, health-endpoint schema, OAuth-callback origin
logic, and all editor/ads/articles/AI feature tests — these assert on one app's routes/DOM/schema and
belong in that app's own repo. Active XSS/SQLi fuzzing is also intentionally out of scope to keep the
tool safe to run against production without sending attack payloads.
