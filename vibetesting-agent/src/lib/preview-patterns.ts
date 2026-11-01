/**
 * Allowed preview / staging host patterns for a verified project.
 *
 * Safe model:
 * - A pattern is either an exact host (`staging.example.com`) or a suffix
 *   wildcard (`*.sparkle-forms.pages.dev`).
 * - The *proof host* is the pattern without `*.`. The owner must already have
 *   verified that host, or a parent host they control (the project hostname).
 * - Bare public suffixes and shared platform apexes (`pages.dev`, `vercel.app`,
 *   `netlify.app`, …) are rejected — proving `pages.dev` would let anyone add
 *   `*.pages.dev` and scan tenants they do not own.
 * - `*.sparkle-forms.pages.dev` is allowed only after the owner proves
 *   `sparkle-forms.pages.dev` (or a parent that is not a platform apex).
 */

export const PLATFORM_APEXES = [
  'pages.dev',
  'vercel.app',
  'netlify.app',
  'herokuapp.com',
  'web.app',
  'firebaseapp.com',
  'azurewebsites.net',
  'cloudfront.net',
  'github.io',
  'gitlab.io',
  'workers.dev',
  'r2.dev',
  'trycloudflare.com',
  'ngrok.io',
  'ngrok.app',
  'loca.lt',
] as const;

/** Registrable / public suffixes we never accept as a bare pattern or proof host. */
export const PUBLIC_SUFFIXES = [
  ...PLATFORM_APEXES,
  'com',
  'org',
  'net',
  'io',
  'dev',
  'app',
  'co',
  'ai',
  'xyz',
  'uk',
  'au',
  'us',
  'ca',
  'de',
  'fr',
  'jp',
  'com.au',
  'co.uk',
  'ac.uk',
  'gov.uk',
  'com.br',
  'co.jp',
] as const;

export type PreviewPatternKind = 'exact' | 'wildcard';

export type PreviewPatternCode =
  | 'invalid'
  | 'public_suffix'
  | 'platform_apex'
  | 'unauthorized';

export type PreviewPatternParse =
  | { ok: true; pattern: string; kind: PreviewPatternKind; proofHost: string }
  | { ok: false; error: string; code: PreviewPatternCode };

const HOST_RE = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

export function isPlatformApex(host: string): boolean {
  return (PLATFORM_APEXES as readonly string[]).includes(normalizeHost(host));
}

export function isPublicSuffix(host: string): boolean {
  const h = normalizeHost(host);
  if (!h) return true;
  if ((PUBLIC_SUFFIXES as readonly string[]).includes(h)) return true;
  if (!h.includes('.')) return true;
  return false;
}

export function parsePreviewPattern(raw: string): PreviewPatternParse {
  const trimmed = (raw || '').trim().toLowerCase();
  if (!trimmed) return { ok: false, error: 'Pattern is required', code: 'invalid' };
  if (trimmed.includes('/') || trimmed.includes(':') || trimmed.includes(' ')) {
    return { ok: false, error: 'Pattern must be a hostname or *.hostname', code: 'invalid' };
  }
  const wildcard = trimmed.startsWith('*.');
  const proofHost = wildcard ? trimmed.slice(2) : trimmed;
  if (!proofHost || !HOST_RE.test(trimmed)) {
    return { ok: false, error: 'Pattern must be a hostname or *.hostname', code: 'invalid' };
  }
  if (isPlatformApex(proofHost)) {
    return {
      ok: false,
      error: `Cannot use shared platform apex "${proofHost}" as a preview pattern. Verify a host you control (e.g. *.your-project.pages.dev).`,
      code: 'platform_apex',
    };
  }
  if (isPublicSuffix(proofHost)) {
    return {
      ok: false,
      error: `Cannot use public suffix "${proofHost}" as a preview pattern.`,
      code: 'public_suffix',
    };
  }
  return {
    ok: true,
    pattern: wildcard ? `*.${proofHost}` : proofHost,
    kind: wildcard ? 'wildcard' : 'exact',
    proofHost,
  };
}

/**
 * Does `verifiedHost` prove control of `proofHost`?
 * Yes when they are equal, or proofHost is a subdomain of verifiedHost,
 * and verifiedHost itself is not a public suffix / platform apex.
 */
export function hostAuthorizesProof(verifiedHost: string, proofHost: string): boolean {
  const verified = normalizeHost(verifiedHost);
  const proof = normalizeHost(proofHost);
  if (!verified || !proof) return false;
  if (isPublicSuffix(verified) || isPlatformApex(verified)) return false;
  if (verified === proof) return true;
  return proof.endsWith(`.${verified}`);
}

export function validatePreviewPattern(
  raw: string,
  verifiedHosts: string[],
): PreviewPatternParse | { ok: false; error: string; code: 'unauthorized' } {
  const parsed = parsePreviewPattern(raw);
  if (!parsed.ok) return parsed;
  const authorized = verifiedHosts.some((h) => hostAuthorizesProof(h, parsed.proofHost));
  if (!authorized) {
    return {
      ok: false,
      error: `Verify ${parsed.proofHost} (or a parent domain you control) via DNS TXT, file, or meta tag before adding this pattern.`,
      code: 'unauthorized',
    };
  }
  return parsed;
}

/** `*.example.com` matches `foo.example.com` and `a.b.example.com`, not `example.com`. */
export function hostMatchesPreviewPattern(hostname: string, pattern: string): boolean {
  const parsed = parsePreviewPattern(pattern);
  if (!parsed.ok) return false;
  const host = normalizeHost(hostname);
  if (parsed.kind === 'exact') return host === parsed.proofHost;
  return host !== parsed.proofHost && host.endsWith(`.${parsed.proofHost}`);
}

export function hostMatchesAnyPreviewPattern(hostname: string, patterns: string[] | undefined | null): boolean {
  if (!patterns?.length) return false;
  return patterns.some((p) => hostMatchesPreviewPattern(hostname, p));
}
