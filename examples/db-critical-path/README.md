# Dynamic Business CMS critical-path suite

Persists DB's critical-path E2E coverage into the official vibetesting-agent checklist
(`docs/CHECKS.md`, stable `VTA-NNNN` ids under the **dbcms** category). Extends the existing
auth / fetch / CF-bypass stack — not a parallel framework.

## What it covers

| Check ID | Needs | Asserts |
|----------|-------|---------|
| `db.auth.editor-cms` | `VTA_EDITOR_*` + `VTA_SUPABASE_ANON_KEY` | Editor cookie session loads `/dashboard/editor` HTML; Bearer reaches `/api/editor/posts` |
| `db.auth.superadmin-homepage-config` | `VTA_SUPERADMIN_*` | `GET /api/homepage/config` → 200 |
| `db.auth.superadmin-ad-placements` | `VTA_SUPERADMIN_*` + anon key | Cookie session loads `/dashboard/admin/homepage` (no `/login` bounce) |
| `db.api.uploads-ad` | editor or superadmin | `POST /api/uploads` `type=ad` + tiny PNG → 201 (#1441) |
| `db.api.uploads-empty` | editor or superadmin | empty multipart → 400 `"No file provided"` (#1441) |
| `db.api.profiles-rls` | `VTA_USER_*` | non-staff cannot dump all profiles via REST (#1416) |
| `db.api.ad-track-xss` | (none) | ad-track beacon does not HTML-reflect XSS markers |
| `db.api.unsubscribe-xss` | (none) | unsubscribe page does not reflect raw XSS token (#1452) |
| `db.api.stripe-amount` | `VTA_STRIPE_AMOUNT_PROBE=1` | optional non-destructive pricing dual-path (#1436) |
| `db.editorial.golden-path` | `VTA_UNPUBLISHED_ARTICLE_URL` + editor | unpublished fixture reachable |

**Missing credentials / fixtures → SKIP (pass).** They never false-fail CI.

Mike owns #656 / #1072 elsewhere — those are intentionally out of scope here.

## Run against dynamicbusiness.com

```bash
npm run build
source ~/.config/db-eng/vta-db-critical.env   # your secrets; chmod 600
source ~/.config/db-eng/cf-bot.env            # CF_SMOKE_KEY if probing behind bot fight-mode

npx vibetesting-agent db-critical https://dynamicbusiness.com
# or from this repo:
node --experimental-strip-types src/cli.ts db-critical https://dynamicbusiness.com
node --experimental-strip-types src/cli.ts db-critical https://beta.dynamicbusiness.com --json
```

The suite sends staff session tokens to the target, so it only runs against `dynamicbusiness.com`
and its subdomains. For a local or staging copy on another host, pass `--i-know-the-host`.

Beta (`beta.dynamicbusiness.com`) also needs `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`
(see `.env.cf-bots.example` and `docs/cf-bypass.md`).

## Env reference

See [`.env.example`](./.env.example). Variable names only are committed — never real secrets.
