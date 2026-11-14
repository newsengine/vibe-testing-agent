function req(name: string, fallback = ''): string {
  return process.env[name] || fallback;
}

export const config = {
  appUrl: req('NEXT_PUBLIC_APP_URL', 'https://vibetestingagent.com'),
  appName: 'VibeTesting Agent',
  appDomain: 'vibetestingagent.com',
  sessionSecret: req('SESSION_SECRET', 'dev-only-change-me-to-32-chars-min!!'),
  github: {
    clientId: req('GITHUB_CLIENT_ID'),
    clientSecret: req('GITHUB_CLIENT_SECRET'),
    appId: req('GITHUB_APP_ID'),
    appPrivateKey: req('GITHUB_APP_PRIVATE_KEY').replace(/\\n/g, '\n'),
    appWebhookSecret: req('GITHUB_APP_WEBHOOK_SECRET'),
  },
  workos: {
    apiKey: req('WORKOS_API_KEY'),
    clientId: req('WORKOS_CLIENT_ID'),
    redirectUri: req('WORKOS_REDIRECT_URI', `${req('NEXT_PUBLIC_APP_URL', 'https://vibetestingagent.com')}/api/auth/workos/callback`),
    cookiePassword: req('WORKOS_COOKIE_PASSWORD') || req('SESSION_SECRET', 'dev-only-change-me-to-32-chars-min!!'),
  },
  stripe: {
    secretKey: req('STRIPE_SECRET_KEY'),
    webhookSecret: req('STRIPE_WEBHOOK_SECRET'),
    priceWeekly: req('STRIPE_PRICE_WEEKLY') || req('STRIPE_PRICE_VIBE'),
    priceDaily: req('STRIPE_PRICE_DAILY') || req('STRIPE_PRICE_STUDIO'),
    priceCommit: req('STRIPE_PRICE_COMMIT'),
    publishableKey: req('NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY'),
    /**
     * Comma-separated emails that receive a private Every-commit founder discount.
     * Applied server-side only — never exposed as a public promo field.
     */
    founderBillingEmails: req('FOUNDER_BILLING_EMAILS'),
    /** Stripe coupon id (amount_off) auto-applied for founders on commit checkout */
    founderCommitCouponId: req('FOUNDER_COMMIT_COUPON_ID'),
    /** If true, Checkout shows a public "promotion code" box. Default off (private promos only). */
    allowPromotionCodes: req('STRIPE_ALLOW_PROMOTION_CODES', 'false') === 'true',
  },
  scannerCli: req('ANAL_PROBE_CLI', ''),
  /** Shared secret for OVH full-scan agents (Authorization: Bearer …) */
  scanAgentSecret: req('SCAN_AGENT_SECRET'),
  emailFrom: req('EMAIL_FROM', 'VibeTesting Agent <noreply@vibetestingagent.com>'),
  resendApiKey: req('RESEND_API_KEY'),
  turnstileSecret: req('TURNSTILE_SECRET_KEY'),
  turnstileSiteKey: req('NEXT_PUBLIC_TURNSTILE_SITE_KEY'),
  isDev: process.env.NODE_ENV !== 'production',
  ossRepo: req('OSS_REPO_URL', 'https://github.com/mikenicholls-msv/vibetesting-agent'),
  scannerRepo: req('SCANNER_REPO_URL', 'https://github.com/newsengine/vibe-testing-agent'),
};

export function publicConfig() {
  return {
    appUrl: config.appUrl,
    appName: config.appName,
    appDomain: config.appDomain,
    stripePublishableKey: config.stripe.publishableKey,
    turnstileSiteKey: config.turnstileSiteKey,
    githubEnabled: Boolean(config.github.clientId),
    workosEnabled: Boolean(config.workos.apiKey && config.workos.clientId),
    stripeEnabled: Boolean(
      config.stripe.secretKey &&
        (config.stripe.priceWeekly || config.stripe.priceDaily || config.stripe.priceCommit),
    ),
    ossRepo: config.ossRepo,
    scannerRepo: config.scannerRepo,
  };
}
