# vibetesting-agent

[![npm](https://img.shields.io/npm/v/vibetesting-agent)](https://www.npmjs.com/package/vibetesting-agent)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Point it at any deployed app and it tells you everything wrong with it** — leaked API keys in your
JS bundle, an exposed `.env`/`.git`, broken links, missing security headers, SEO/accessibility/perf
gaps. One command, **zero install**, no source access, no headless browser:

```bash
npx vibetesting-agent https://your-app.example.com
```

Free and open source (Apache-2.0). Website: https://vibetestingagent.com

## Install

Requires **Node.js 20+**. Pick one:

```bash
# 1. Zero install (always the latest published version)
npx vibetesting-agent https://your-app.example.com

# 2. Global install: adds the `vibetesting-agent` and `vta` commands
npm install -g vibetesting-agent
vibetesting-agent https://your-app.example.com

# 3. As a dev dependency (CI scripts, or the white-box helpers in your tests)
npm install --save-dev vibetesting-agent
npx vibetesting-agent https://your-app.example.com

# 4. From source
git clone https://github.com/newsengine/vibe-testing-agent.git
cd vibe-testing-agent
npm ci
npm run build
node dist/cli.js https://your-app.example.com
```

### Security review (agent report + Gherkin)
Same shape as a Claude security artifact / `findings-for-agent.md` — ranked **P1/P2** with fix + verify, plus BDD:

```bash
# Every software update / /security-review
npx vibetesting-agent review https://your-app.example.com

# Or flags on any scan:
npx vibetesting-agent https://your-app.example.com \
  --agent-report security-review.md \
  --gherkin features/security/hygiene.feature

# New repo: scaffold suite + CI + baseline
npx vibetesting-agent init https://your-app.example.com --name my-app
```

> ### ⚖️ Authorized use only
> vibetesting-agent is for testing systems **you own or have explicit written permission to test**. The default
> scan is read-only, but it can be run in active modes (port scanning, fuzzing). **Scanning systems you
> don't own may be illegal** (e.g. the US Computer Fraud and Abuse Act, the UK Computer Misuse Act, and
> equivalents elsewhere). You are solely responsible for having authorization for every target. Active
> recon is additionally gated behind an explicit `recon --yes-i-am-authorized` flag.

> ### ⚠️ Beta: no warranty, no support
> vibetesting-agent is **beta software, provided "AS IS", without warranty of any kind and without support**
> (see [`LICENSE`](LICENSE)). Run it as a **review aid**: its findings and alerts are **advisory only**.
> Consider each warning, check it yourself, and decide whether it applies to you. **You are responsible for
> your own security decisions**, including whether to implement or not implement anything it reports.
> It is a hygiene scanner and a first line of defense, **not a substitute for a professional penetration test
> or security audit**, and a clean scan does not mean an application is secure.
>
> There is no support channel. If something needs fixing, [open a GitHub issue](https://github.com/newsengine/vibe-testing-agent/issues).

Built for vibe coders shipping with AI: you don't need to know what to look for — the scanner does, and
every failing finding comes with a one-line **fix**. Exits non-zero so it doubles as a CI gate.

- **Full black-box scan** — 15 categories (below), all from a URL.
- **Numbered & auditable**: every check has a stable `VTA-NNNN` number; `--ledger <file>` records each run
  and its sub-tests to a ledger, and `--priority` prints a Priority-Status cover page.
- **AI-aware (MITRE ATLAS)**: detects an AI/LLM surface and runs ATLAS-mapped checks (model-artifact
  exposure, open inference, prompt-injection, cost/DoS) — each citing its ATLAS technique id.
- **App-type aware**: fingerprints the *business archetype* (e-commerce, SaaS, auth portal, fintech,
  healthcare, marketplace, docs, job board, …20 in all) and runs that type's extra rules — only when
  confidently detected. See the `appstyle` rows in [`docs/CHECKS.md`](docs/CHECKS.md).
- **Every check is catalogued** — [`docs/CHECKS.md`](docs/CHECKS.md) is a generated, always-current list
  of every test the scanner runs (id, category, severity, standards, and whether it's passive / an extra
  GET / an active probe / needs auth). The build fails if a check isn't listed, so coverage is never a
  black box. Regenerate with `npm run catalog`.
- **Framework-aware**: fingerprints the stack (Next.js/WordPress/Laravel/Django/Rails/Spring/ASP.NET) and
  runs targeted checks for its known misconfigs — only when confidently detected.
- **Vulnerable-component detection** (OWASP A06): retire.js-style client-side JS library CVE matching,
  backed by an **auto-updating vuln feed** — `npm run update-vuln-db` refreshes the table from the
  retire.js community feed (currently 12 libraries / 200+ ranges), so it doesn't go stale.
- **Custom plugins**: drop **JSON** check templates in a directory and run `--plugins <dir>` — add your
  own checks (status/header/body matchers, and/or conditions) with **zero code**. See [`plugins/`](plugins/).
- **Host intel** (passive): resolved IPs, reverse DNS, CDN/hosting provider — no scanning.
- **Opt-in aggressive modes** (off by default): `recon` (authorization-gated, CDN-guarded port scan +
  service/version ID + **CVE correlation** via NVD with `--cve` — identify-only, never exploit),
  `browse` (headless-browser functional check), `crawl` (deep browser crawl of every reachable page —
  JS errors, broken images, failed requests + **safe** reflected-input/SQL-error fuzz on search forms;
  GET-only, never submits mutating forms), and `separation` (two-account cross-tenant isolation test).
  All need `playwright-core`.
- **CVE checks**: `audit` covers dependency CVEs (npm advisory DB); `recon --cve` / `vibetesting-agent cve
  <product> <version>` correlate detected service versions against NVD.
- **Standards mapping** (`--compliance`): reports coverage against **OWASP ASVS 4.0.3 Level 1**
  (23/25 black-box requirements), **OWASP Top 10 (2021)**, and **WSTG** — see [docs/compliance.md](docs/compliance.md).
- **White-box helpers** (`idorProbe`, `rbacProbe`, `dataIsolationProbe`, `massAssignmentProbe`,
  `classifyTenantAccess`, `findSensitiveFields`, `checkSecurityHeaders`, `checkCookieFlags`, `scanSecrets`):
  import into your own test suite (jest/vitest/node:test) for RBAC, cross-tenant/IDOR, mass-assignment,
  header/cookie/secret assertions. See `examples/security-suite/` + `examples/tenant-isolation/`.
- **Templates**: `SECURITY.md`, `security.txt`, `CODEOWNERS`.
- **Reusable GitHub Actions workflow**: `.github/workflows/probe.yml` (call it with `uses:`).

## What it checks (black-box, from just a URL)

Scope it with `--only <cats>` / `--skip <cats>` (comma-separated category names).

### 🔑 `secrets` — keys you accidentally shipped to the browser
Fetches the page **and every same-origin script bundle** and scans for real secrets: `sk_live`/`rk_live`
(Stripe), `AKIA…` (AWS), Google/SendGrid/Twilio/Anthropic/OpenAI keys, GitHub & Slack tokens, PEM
private-key blocks, and **Supabase `service_role`** JWTs (decoded + confirmed, not just pattern-matched).
Things that are *meant* to be public (Stripe `pk_live`, Supabase `anon`) are deliberately ignored.
Also flags **publicly downloadable source maps** (your unminified source). Secrets are redacted in output.

### 📂 `exposure` — config & debug surfaces that shouldn't be reachable
`/.env`(+`.local`/`.production`), `/.git/config` + `/.git/HEAD`, `/wrangler.toml`, `/.npmrc`,
`/docker-compose.yml`, `/.DS_Store`, `/backup.sql`, `package.json`. Each one **validates the body**
(not just a 200) so SPA catch-all routes don't false-positive. Plus: **stack-trace/internal-path leakage**
on error pages, and **GraphQL introspection** left enabled.

### 🌐 `dns` — email spoofing & subdomain takeover
**SPF** + **DMARC** (with policy strength — `p=none` is only monitoring), **CAA** (restricts who can
issue TLS certs for you), and a **dangling-CNAME → subdomain-takeover** heuristic (a CNAME pointing at
a target that no longer resolves). All from the hostname, via DNS lookups.

### 🧩 `framework` — stack-specific misconfigs
Fingerprints the platform from headers/cookies/HTML, then (only on a **confident** match) probes that
stack's notorious surfaces: **Next.js** secrets serialized into `__NEXT_DATA__`; **WordPress** REST
user-enumeration + `xmlrpc.php` + `wp-config.php.bak`; **Laravel** `/telescope` + `/_ignition` (RCE);
**Django** `DEBUG=True` error pages; **Rails** `/rails/info` + `/sidekiq`; **Spring Boot**
`/actuator/env` + `/heapdump`; **ASP.NET** `elmah.axd` + `trace.axd`. All safe GETs, body-validated.

### 📦 `components` — vulnerable & outdated client-side libraries (OWASP A06)
A retire.js-style pass over the JavaScript the browser actually loads. Fingerprints library + version from
script/link URLs (cdnjs/jsdelivr/unpkg/local filenames) and inline banners — **no code execution** — then
matches a curated table of known-vulnerable ranges: **jQuery** <3.5 (CVE-2020-11022 XSS), **jQuery UI**,
**Bootstrap** <4.3.1 (CVE-2019-8331), **Lodash** <4.17.21 (RCE/proto-pollution), **AngularJS** (EOL),
**Handlebars**, **Moment**, **axios**, **DOMPurify**, **Vue 2** (EOL), and more. Detects current versions
too (no false positives). Server-side stack CVEs are covered separately by the `cve` mode.

Also in `security`: **JWT hygiene** — any token exposed to the browser is decoded (not verified) and flagged
for `alg:none`, missing `exp`, over-long lifetime, or sitting in a non-HttpOnly cookie. A **host-header
injection** probe (spoofed `X-Forwarded-Host` reflected into URLs → password-reset / cache poisoning). A
**CSRF-protection heuristic** (state-changing POST forms with no token, SameSite-aware). And a high-confidence
**DOM-XSS** check (a URL/`referrer`/`window.name` source flowing straight into an `innerHTML`/`document.write`/
`eval` sink in inline script).

### 🔌 `plugins` — your own checks, no code
Point `--plugins <dir>` at a folder of **JSON** templates and vibetesting-agent runs them as first-class findings —
no fork, no TypeScript. A template is a `request` (GET/HEAD only) plus `matchers` (`status` / `header` /
`body-regex` / `body-contains`, combined with `matchers-condition: and|or`, any matcher invertible with
`negative: true`) and output metadata (`id`/`title`/`severity`/`fix`/`owasp`/`cwe`). Malformed templates are
skipped (not fatal); GET/HEAD-only and a template cap keep it safe. Schema + annotated examples in
[`plugins/`](plugins/). The known-vulnerable-library table (`components`) is itself refreshable via
`npm run update-vuln-db` (pulls the retire.js community feed) so it never goes stale.

### 🔗 `reliability` — is it actually working?
Homepage status, **broken same-origin links & images** (sampled HEAD/GET), and **mixed content**
(`http://` resources on an `https://` page).

### 🔐 `security` — headers / TLS / CORS / cookies
HTTPS + HTTP→HTTPS redirect, **HSTS**, **`nosniff`**, **`Referrer-Policy`**, **clickjacking**
(`X-Frame-Options`/CSP), enforced **CSP** (`--allow-report-only-csp` to accept Report-Only mid-rollout)
**graded for weakness** (`unsafe-inline`/`unsafe-eval`/wildcard sources, missing `object-src`/`base-uri`),
**version-banner disclosure**, **cookie flags** (Secure+HttpOnly+SameSite) + **`__Host-` prefix**,
**`security.txt`** (RFC 9116), **dangerous CORS reflection** (with `--cors-path`: fails only on
reflect-arbitrary-origin **+** `Allow-Credentials: true` — a bare `*` without credentials is fine),
**TLS cert expiry**, **open redirect** (common `?next=`/`?redirect=` params), **Subresource Integrity**
on cross-origin `<script>`/`<link>`, **rate limiting** (opt-in via `--rate-limit-path`), a **CSRF-protection
heuristic** (state-changing POST forms with no anti-CSRF token, SameSite-aware so it won't false-positive),
and a high-confidence **DOM-XSS** check (a URL/`referrer`/`window.name` source flowing straight into an
`innerHTML`/`document.write`/`eval` sink in inline script).

### 🔎 `seo` — will Google show it right?
`<title>`, meta description, Open Graph, canonical, exactly one `<h1>`, `robots.txt`, `sitemap.xml`.

### ♿ `a11y` — basic accessibility
`<html lang>`, viewport meta, images missing `alt`, form inputs without labels.

### ⚡ `performance`
gzip/brotli compression, oversized HTML, script count, long-lived cache headers on static assets.

### White-box helpers (import into your own test suite)
| Helper | What it checks |
|---|---|
| **`idorProbe(attacker, cases)`** | Cross-tenant / **IDOR**: authenticates as tenant B and tries to reach tenant A's resources; each case must be **denied** (401/403/404). A 2xx to the attacker is reported as a cross-tenant leak. |
| **`rbacProbe(request, actors)`** | **Auth enforcement + RBAC**: runs one protected endpoint against several actors (anonymous / wrong-role / admin / cron-secret) and asserts each is allowed or denied as expected. |
| **`dataIsolationProbe(request, a, b, extractIds)`** | Two users' **list** responses must share no resource ids (owner-scoped). |
| **`massAssignmentProbe(request, forgedValue)`** | Server must **ignore a client-forged** auth-derived field (`author_id`/`status`/…). |
| **`classifyTenantAccess({baseline, attack, control})`** + **`setTenantParam`** | Grade a multi-tenant `?tenant_uuid=` swap into isolated / leak / inspect / **inconclusive** (won't false-pass on a stale session). |
| **`findSensitiveFields(body)`** | Response must not return `password`/`access_token`/`service_role`/… |
| **`checkSecurityHeaders(headers, {requireEnforcedCsp?})`** | Returns problems for missing/weak **HSTS**, **`nosniff`**, **`Referrer-Policy`**, and **CSP** (enforced, or Report-Only when not required). |
| **`checkCookieFlags(setCookie)`** | Returns problems if a cookie lacks **`Secure`**, **`HttpOnly`**, or **`SameSite`**. |
| **`scanSecrets(text)`** | Returns redacted hits for any hardcoded secret in a string/blob (the engine the `secrets` category uses). |

### `audit` — dependency vulnerabilities (white-box, runs in the repo)
Wraps `npm audit --json` and gates CI on severity:
```bash
vibetesting-agent audit --level high          # fail on any high/critical advisory (default)
vibetesting-agent audit --prod --level moderate --json
```

> Shipped: SARIF, baseline/diff, CSP linting, DNS/email hygiene, TLS protocol/cipher grading,
> **agent-readiness**, **host intel**, **framework check groups**, **authenticated scan**
> (`--cookie`/`--header`), **multi-page crawl** (`--crawl`), config file + batch (`--urls`), and the
> opt-in **`recon`** (port scan) + **`browse`** (browser-functional) modes.
> Roadmap (PRs welcome): framework preset configs, deeper CVE-informational service ID.

### Cloudflare bot / Access bypass

When probing your own site behind Cloudflare Bot Fight / Access, set env vars (never commit secrets).
Nothing is sent until you list the hosts that may receive each header:

| Env var | Header | When |
|---|---|---|
| `CF_SMOKE_KEY` / `X_SMOKE_KEY` | `x-smoke-key` | host is in `VTA_SMOKE_KEY_HOSTS`. Legacy: `SMOKE_KEY`. |
| `CF_ACCESS_CLIENT_ID` | `CF-Access-Client-Id` | host is in `VTA_CF_ACCESS_HOSTS` |
| `CF_ACCESS_CLIENT_SECRET` | `CF-Access-Client-Secret` | host is in `VTA_CF_ACCESS_HOSTS` |

Host lists are comma-separated; `example.com` is exact and `*.example.com` matches subdomains.
Helper: `src/cf-bypass-headers.ts` (CLI `extraHeaders` per URL; `browse` uses host-filtered `context.route`, never global `extraHTTPHeaders`). Reusable workflow `probe.yml` accepts the same secrets plus `smoke_key_hosts` / `cf_access_hosts` inputs. See [docs/cf-bypass.md](docs/cf-bypass.md).


## Use it in CI across all repos (recommended)
```yaml
# .github/workflows/security.yml in ANY repo
name: security
on: [pull_request, workflow_dispatch]
jobs:
  probe:
    uses: newsengine/vibe-testing-agent/.github/workflows/probe.yml@main
    with:
      url: https://your-deploy.example.com
      cors_path: /api/public/health        # optional
      rate_limit_path: /api/public/health  # optional — burst-test for a 429
      fail_on: high                         # high | medium | any
      allow_report_only_csp: true           # while CSP is still Report-Only
```

> **Prefer a plain step?** Run the published CLI directly (pin the version you tested):
> ```yaml
>   steps:
>     - run: npx --yes vibetesting-agent@0.6.1 https://your-deploy.example.com --fail-on high
> ```

### Findings in the GitHub Security tab (SARIF)
`--sarif` emits SARIF 2.1.0; upload it so each finding becomes a code-scanning alert:
```yaml
  scan:
    runs-on: ubuntu-latest
    permissions: { security-events: write, contents: read }
    steps:
      - run: npx --yes vibetesting-agent@0.6.1 https://your-deploy.example.com --sarif > probe.sarif
        continue-on-error: true          # don't block the upload; gate in a separate step if you want
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: probe.sarif }
```

### Gate on regressions only (baseline)
Snapshot today's debt once, commit it, then fail CI only on *new* findings:
```bash
npx vibetesting-agent https://your-deploy.example.com --write-baseline probe-baseline.json  # once, commit the file
npx vibetesting-agent https://your-deploy.example.com --baseline probe-baseline.json --fail-on medium
```

## Use the CLI locally / ad-hoc
```bash
# full scan (all 13 categories)
npx vibetesting-agent https://app.example.com

# scope it, gate harder, test CORS, machine-readable output
npx vibetesting-agent https://app.example.com \
  --only secrets,exposure,security \
  --cors-path /api/public/health --allow-report-only-csp \
  --fail-on medium --json
```
Flags: `--only <cats>` · `--skip <cats>` · `--cors-path <p>` · `--rate-limit-path <p>` · `--allow-report-only-csp`
· `--max-crawl <n>` (links/scripts to fetch-check, default 25) · `--fail-on high|medium|any` · `--json` · `--sarif`
· `--baseline <file>` · `--write-baseline <file>`.

## Use the white-box helpers in your tests
```ts
import { idorProbe, checkSecurityHeaders } from 'vibetesting-agent';

// Cross-tenant: authenticate as tenant B, try to read tenant A's resources — must be denied.
const results = await idorProbe(tenantB, [
  { name: 'GET /api/forms/:A_id', request: () => ({ url: `${BASE}/api/internal/forms/${A_FORM_ID}` }) },
]);
for (const r of results) expect(r.ok, r.detail).toBe(true);

// Headers on a response:
expect(checkSecurityHeaders(res.headers, { requireEnforcedCsp: true })).toEqual([]);
```

## Develop
```bash
git clone https://github.com/newsengine/vibe-testing-agent.git
cd vibe-testing-agent
npm ci && npm run build && npm test
```

### Releasing to npm (maintainers)
```bash
npm login
npm test
npm publish --access public   # prepublishOnly rebuilds dist/
```

### How we test that the checks work
The suite is **true-positive + true-negative** fixtures, not just “it ran”:

| Layer | What it proves | Command |
|---|---|---|
| Unit / matrix | Each secret rule hits a crafted sample; public-looking strings do not | `npm test` |
| **known-bad fixture** | Required finding IDs *fail* (leaks, missing headers, exposure paths, open redirect) | `npm run test:fixtures` |
| **known-good fixture** | Those same IDs do *not* fail (no false positives on a hardened app) | `npm run test:fixtures` |
| Inventory hygiene | `SECRET_RULES` stays in sync with the coverage list | `npm test` |
| Lint gate | ESLint clean on OSS sources | `npm test` (via `tests/lint.test.ts`) |

Fixtures live under `tests/helpers/` (`startKnownBad` / `startKnownGood`). Required IDs are listed in `tests/helpers/inventory.ts` — add a new check? Add its ID to the inventory and make the fixture trip it.

## What "fail_on" means
- `high` (default): fail CI only on HIGH findings (leaked secret, exposed `.env`/`.git`, missing HSTS/CSP, non-HTTPS, dangerous CORS).
- `medium`: also fail on MEDIUM (nosniff, frame-options, cookie flags, broken links, mixed content, missing `lang`/viewport, exposed source maps, GraphQL introspection).
- `any`: fail on anything not passing (includes SEO/perf nits).

`--allow-report-only-csp` treats a `Content-Security-Policy-Report-Only` header as an acceptable
(info-level) CSP, for apps mid-rollout. Drop it once you enforce CSP.
