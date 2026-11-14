# Your remaining clicks (Workers is live)

## Live now

**https://vibetestingagent.com** (plus the account `*.workers.dev` URL for the `vibetesting-agent` Worker)

- OpenNext on **Cloudflare Workers**
- **D1** database migrated
- Secrets uploaded (WorkOS + Stripe)
- Lite scan API verified working

Details: [WORKERS.md](./WORKERS.md)

---

## Done for you

- [x] Workers + OpenNext deploy
- [x] D1 schema
- [x] Stripe test products $25 / $100 / $250
- [x] Stripe portal + webhooks
- [x] WorkOS secrets on Worker
- [x] Product / ownership gates / lite scan

---

## You (≈5–10 minutes)

### 1. WorkOS redirects

Dashboard → AuthKit → Redirects → add:

```
https://vibetesting-agent.<account-subdomain>.workers.dev/api/auth/workos/callback
https://vibetestingagent.com/api/auth/workos/callback
http://localhost:3000/api/auth/workos/callback
```

### 2. Custom domain (optional)

Cloudflare → Workers & Pages → **vibetesting-agent** → Settings → Domains → add  
`vibetestingagent.com` and `www`.

### 3. Smoke test

1. Open the workers.dev URL  
2. Run free lite scan  
3. Login via `/api/auth/workos`  
4. Stripe test card `4242…` when ready  

### 4. Optional later

- Stripe live mode when charges enabled  
- Redeploy: `cd vibetesting-agent && npm run deploy`  
