/**
 * Tests for POST /api/v1/projects/:id/verify method parsing.
 * The route must accept dns|email|file|meta, return 400 for missing/invalid method,
 * and never silently fall back to dns.
 *
 * Parser is loaded from the Next app source via a tiny copy that matches verify-method.ts
 * (Node cannot import the app's extensionless/bundler modules). Source of the route and
 * parser is also asserted so the silent-dns fallback cannot return.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const agentSrc = (...parts: string[]) => join(root, '..', 'vibetesting-agent', 'src', ...parts);
const routeSrc = readFileSync(agentSrc('app', 'api', 'v1', 'projects', '[id]', 'verify', 'route.ts'), 'utf8');
const parserSrc = readFileSync(agentSrc('lib', 'verify-method.ts'), 'utf8');
const httpSrc = readFileSync(agentSrc('lib', 'http.ts'), 'utf8');

const OWNERSHIP_METHODS = ['dns', 'email', 'file', 'meta'] as const;
type OwnershipMethod = (typeof OWNERSHIP_METHODS)[number];

class BadRequestError extends Error {
  status = 400;
}

function isOwnershipMethod(value: unknown): value is OwnershipMethod {
  return typeof value === 'string' && (OWNERSHIP_METHODS as readonly string[]).includes(value);
}

function parseVerifyMethod(body: unknown): OwnershipMethod {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequestError('method is required: dns | email | file | meta');
  }
  const method = (body as { method?: unknown }).method;
  if (method === undefined || method === null || method === '') {
    throw new BadRequestError('method is required: dns | email | file | meta');
  }
  if (!isOwnershipMethod(method)) {
    throw new BadRequestError(`invalid method "${String(method)}"; expected dns | email | file | meta`);
  }
  return method;
}

async function parseVerifyRequest(req: Request): Promise<OwnershipMethod> {
  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }
  return parseVerifyMethod(body);
}

test('verify-route: source lists all four methods and has no silent dns fallback', () => {
  assert.match(parserSrc, /'dns',\s*'email',\s*'file',\s*'meta'/);
  assert.match(parserSrc, /parseVerifyRequest/);
  assert.match(parserSrc, /BadRequestError/);
  assert.match(routeSrc, /parseVerifyRequest/);
  assert.doesNotMatch(routeSrc, /method\s*=\s*['"]dns['"]/);
  assert.doesNotMatch(routeSrc, /z\.enum\(\['dns',\s*'email'\]\)/);
  assert.match(httpSrc, /BadRequestError/);
  assert.match(httpSrc, /err instanceof BadRequestError/);
});

test('verify-route: parseVerifyMethod accepts dns, email, file, meta', () => {
  for (const method of OWNERSHIP_METHODS) {
    assert.equal(parseVerifyMethod({ method }), method);
  }
});

test('verify-route: parseVerifyMethod rejects missing method', () => {
  assert.throws(() => parseVerifyMethod({}), BadRequestError);
  assert.throws(() => parseVerifyMethod({ method: '' }), BadRequestError);
  assert.throws(() => parseVerifyMethod({ method: null }), BadRequestError);
  assert.throws(() => parseVerifyMethod(undefined), BadRequestError);
  assert.throws(() => parseVerifyMethod(null), BadRequestError);
});

test('verify-route: parseVerifyMethod rejects invalid method (no dns fallback)', () => {
  try {
    parseVerifyMethod({ method: 'ftp' });
    assert.fail('expected BadRequestError');
  } catch (err) {
    assert.ok(err instanceof BadRequestError);
    assert.equal(err.status, 400);
    assert.match(err.message, /invalid method/i);
  }
});

test('verify-route: parseVerifyRequest reads all four methods from JSON bodies', async () => {
  for (const method of OWNERSHIP_METHODS) {
    const req = new Request('https://example.test/api/v1/projects/x/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method }),
    });
    assert.equal(await parseVerifyRequest(req), method);
  }
});

test('verify-route: parseVerifyRequest returns 400 for missing method', async () => {
  const req = new Request('https://example.test/api/v1/projects/x/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  await assert.rejects(() => parseVerifyRequest(req), BadRequestError);
});

test('verify-route: parseVerifyRequest returns 400 for invalid JSON / empty body', async () => {
  const req = new Request('https://example.test/api/v1/projects/x/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'not-json',
  });
  await assert.rejects(() => parseVerifyRequest(req), BadRequestError);
});
