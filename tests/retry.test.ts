import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isTransientStatus,
  isNonRetryableClientError,
  classifyTransientError,
  transientKindForStatus,
  parseRetryAfter,
  backoffMs,
  decideRetry,
  withRetries,
  inconclusiveFinding,
  gateableFindings,
  DEFAULT_RETRIES,
} from '../src/retry.ts';
import type { Finding } from '../src/types.ts';

test('DEFAULT_RETRIES is 2', () => {
  assert.equal(DEFAULT_RETRIES, 2);
});

test('transient HTTP statuses are 429/502/503/504 only', () => {
  for (const s of [429, 502, 503, 504]) assert.equal(isTransientStatus(s), true);
  for (const s of [200, 301, 400, 401, 403, 404, 418, 500, 501]) {
    assert.equal(isTransientStatus(s), false, `status ${s} must not be transient`);
  }
});

test('4xx other than 429 are never retryable', () => {
  assert.equal(isNonRetryableClientError(400), true);
  assert.equal(isNonRetryableClientError(401), true);
  assert.equal(isNonRetryableClientError(403), true);
  assert.equal(isNonRetryableClientError(404), true);
  assert.equal(isNonRetryableClientError(429), false);
  assert.equal(isNonRetryableClientError(502), false);
});

test('classifyTransientError: network reset, timeout, DNS', () => {
  assert.equal(classifyTransientError({ code: 'ECONNRESET', message: 'socket hang up' }), 'network');
  assert.equal(classifyTransientError({ code: 'ECONNREFUSED' }), 'network');
  assert.equal(classifyTransientError({ name: 'AbortError', message: 'The operation was aborted' }), 'timeout');
  assert.equal(classifyTransientError({ name: 'TimeoutError', message: 'timeout' }), 'timeout');
  assert.equal(classifyTransientError({ code: 'ENOTFOUND', message: 'getaddrinfo ENOTFOUND' }), 'dns');
  assert.equal(classifyTransientError({ code: 'EAI_AGAIN' }), 'dns');
  assert.equal(classifyTransientError({ message: 'fetch failed' }), 'network');
  assert.equal(classifyTransientError({ message: 'real finding: missing CSP' }), null);
  assert.equal(classifyTransientError(new TypeError('Failed to fetch')), 'network');
});

test('transientKindForStatus maps 429/502/503/504', () => {
  assert.equal(transientKindForStatus(429), 'http_429');
  assert.equal(transientKindForStatus(502), 'http_502');
  assert.equal(transientKindForStatus(503), 'http_503');
  assert.equal(transientKindForStatus(504), 'http_504');
  assert.equal(transientKindForStatus(404), null);
  assert.equal(transientKindForStatus(200), null);
});

test('decideRetry: never retry a real 4xx or a 2xx finding-bearing response', () => {
  assert.equal(decideRetry({ status: 200 }).retry, false);
  assert.equal(decideRetry({ status: 404 }).retry, false);
  assert.equal(decideRetry({ status: 401 }).retry, false);
  assert.equal(decideRetry({ status: 429 }).retry, true);
  assert.equal(decideRetry({ status: 503 }).retry, true);
  assert.equal(decideRetry({ error: { code: 'ECONNRESET' } }).retry, true);
});

test('parseRetryAfter honours delta-seconds and HTTP-date within cap', () => {
  assert.equal(parseRetryAfter('2', 10_000), 2000);
  assert.equal(parseRetryAfter('999', 5_000), 5000);
  assert.equal(parseRetryAfter('', 10_000), null);
  assert.equal(parseRetryAfter(null, 10_000), null);
  const future = new Date(Date.now() + 3000).toUTCString();
  const parsed = parseRetryAfter(future, 10_000);
  assert.ok(parsed != null && parsed <= 10_000 && parsed >= 0);
  const far = new Date(Date.now() + 60_000).toUTCString();
  assert.equal(parseRetryAfter(far, 4_000), 4000);
});

test('backoffMs uses Retry-After when present else exponential, both capped', () => {
  assert.equal(backoffMs(0, 1500, 10_000), 1500);
  assert.equal(backoffMs(0, 50_000, 10_000), 10_000);
  assert.equal(backoffMs(0, null, 10_000, 200), 200);
  assert.equal(backoffMs(1, null, 10_000, 200), 400);
  assert.equal(backoffMs(2, null, 10_000, 200), 800);
  assert.equal(backoffMs(20, null, 1_000, 200), 1000);
});

test('withRetries: 0 disables retries', async () => {
  let calls = 0;
  const result = await withRetries(
    async () => {
      calls++;
      return { status: 503 };
    },
    {
      retries: 0,
      isRetryable: (r) => decideRetry({ status: r.status }),
      sleep: async () => {},
    },
  );
  assert.equal(calls, 1);
  assert.equal(result.retries, 0);
  assert.equal(result.exhausted, true);
  assert.equal(result.value?.status, 503);
});

test('withRetries: retries 503 then succeeds, records retry count', async () => {
  let calls = 0;
  const slept: number[] = [];
  const result = await withRetries(
    async () => {
      calls++;
      if (calls < 3) return { status: 503 };
      return { status: 200 };
    },
    {
      retries: 2,
      isRetryable: (r) => decideRetry({ status: r.status }),
      sleep: async (ms) => {
        slept.push(ms);
      },
    },
  );
  assert.equal(calls, 3);
  assert.equal(result.retries, 2);
  assert.equal(result.exhausted, false);
  assert.equal(result.value?.status, 200);
  assert.equal(slept.length, 2);
});

test('withRetries: honours Retry-After within cap', async () => {
  const slept: number[] = [];
  await withRetries(
    async () => ({ status: 429, retryAfter: '3' }),
    {
      retries: 1,
      isRetryable: (r) => decideRetry({ status: r.status, retryAfter: r.retryAfter, capMs: 10_000 }),
      sleep: async (ms) => {
        slept.push(ms);
      },
      capMs: 10_000,
    },
  );
  assert.equal(slept[0], 3000);
});

test('withRetries: does not retry 404', async () => {
  let calls = 0;
  const result = await withRetries(
    async () => {
      calls++;
      return { status: 404 };
    },
    {
      retries: 2,
      isRetryable: (r) => decideRetry({ status: r.status }),
      sleep: async () => {
        throw new Error('should not sleep');
      },
    },
  );
  assert.equal(calls, 1);
  assert.equal(result.retries, 0);
  assert.equal(result.exhausted, false);
});

test('withRetries: retries ECONNRESET then reports exhausted', async () => {
  const result = await withRetries(
    async () => {
      throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
    },
    {
      retries: 2,
      isRetryable: () => ({ retry: false }),
      sleep: async () => {},
    },
  );
  assert.equal(result.retries, 2);
  assert.equal(result.exhausted, true);
  assert.ok(result.error);
  assert.equal(result.lastKind, 'network');
});

test('inconclusiveFinding is pass + inconclusive and does not trip fail-on', () => {
  const f = inconclusiveFinding({
    id: 'reachability',
    category: 'security',
    title: 'Site unreachable after retries',
    detail: 'fetch failed after 2 retries',
    retries: 2,
  });
  assert.equal(f.pass, true);
  assert.equal(f.inconclusive, true);
  assert.equal(f.retries, 2);
  const fail: Finding = {
    id: 'header.csp',
    category: 'security',
    title: 'Missing CSP',
    severity: 'high',
    pass: false,
    detail: 'missing',
  };
  const quarantined: Finding = { ...fail, id: 'flaky.x', quarantined: true };
  assert.deepEqual(
    gateableFindings([f, fail, quarantined]).map((x) => x.id),
    ['header.csp'],
  );
  assert.equal(gateableFindings([f, fail]).length, 1);
});

test('fetchWithRetry: 503 then 200 records retries=1', async () => {
  const { fetchWithRetry } = await import('../dist/core.js');
  const http = await import('node:http');
  let hits = 0;
  const srv = await new Promise<{ url: string; close: () => void }>((resolve) => {
    const s = http.createServer((_req, res) => {
      hits++;
      if (hits === 1) {
        res.writeHead(503, { 'retry-after': '0' });
        res.end('no');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
  const result = await fetchWithRetry(srv.url, { redirect: 'manual' }, 2000, 2);
  srv.close();
  assert.equal(result.response?.status, 200);
  assert.equal(result.retries, 1);
  assert.equal(result.exhausted, false);
});

test('SARIF omits inconclusive findings and records retries on real failures', async () => {
  const { toSarif } = await import('../dist/sarif.js');
  const findings: Finding[] = [
    {
      id: 'reachability',
      category: 'security',
      title: 'unreachable',
      severity: 'info',
      pass: true,
      inconclusive: true,
      retries: 2,
      detail: 'timeout',
    },
    {
      id: 'header.csp',
      category: 'security',
      title: 'Missing CSP',
      severity: 'high',
      pass: false,
      retries: 1,
      detail: 'missing',
    },
  ];
  const sarif = toSarif(findings, { url: 'https://app.example.com' }) as {
    runs: { results: { ruleId: string; properties?: { retries?: number } }[] };
  };
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].ruleId, 'header.csp');
  assert.equal(sarif.runs[0].results[0].properties?.retries, 1);
});
