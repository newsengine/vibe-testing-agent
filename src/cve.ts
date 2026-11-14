// src/cve.ts
// INFORMATIONAL CVE lookup for a detected product+version, via the NVD keyword API (free, no key). Used
// by `recon --cve` and the `cve` subcommand. This only READS the public vulnerability database — it never
// tests or exploits anything; it tells you which CVEs are associated with a version so you can verify.
// (Dependency CVEs are covered separately by the `audit` subcommand = npm advisory DB.)

export interface CveHit { id: string; summary: string; severity?: string }

/** Pure parser for an NVD 2.0 API response — testable without the network. */
export function parseNvd(data: any, max = 5): CveHit[] {
  const out: CveHit[] = [];
  for (const v of (data?.vulnerabilities ?? []).slice(0, max)) {
    const cve = v?.cve ?? {};
    if (!cve.id) continue;
    const m = cve.metrics ?? {};
    const sev = m.cvssMetricV31?.[0]?.cvssData?.baseSeverity
      ?? m.cvssMetricV30?.[0]?.cvssData?.baseSeverity
      ?? m.cvssMetricV2?.[0]?.baseSeverity;
    const desc = (cve.descriptions ?? []).find((d: any) => d.lang === 'en')?.value ?? '';
    out.push({ id: cve.id, summary: desc.replace(/\s+/g, ' ').slice(0, 150), severity: sev });
  }
  return out;
}

/**
 * Look up CVEs associated with `product version` via NVD keyword search. Fails soft to []. NVD rate-limits
 * to ~5 requests / 30s without a key, so callers should query sequentially and sparingly.
 */
export async function lookupCves(
  product: string,
  version: string,
  opts: { max?: number; timeoutMs?: number } = {},
): Promise<CveHit[]> {
  const max = opts.max ?? 5;
  const q = encodeURIComponent(`${product} ${version}`.trim());
  if (!q) return [];
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${q}&resultsPerPage=${max}`;
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), opts.timeoutMs ?? 12000);
    // NVD sits behind bot protection that 503s a request with no/generic UA — send an explicit one.
    const res = await fetch(url, { signal: ac.signal, headers: { accept: 'application/json', 'user-agent': 'vibetesting-agent (+https://github.com/newsengine/vibe-testing-agent)' } }).finally(() => clearTimeout(t));
    if (!res.ok) return [];
    return parseNvd(await res.json(), max);
  } catch {
    return [];
  }
}
