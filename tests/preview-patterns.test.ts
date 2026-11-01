import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePreviewPattern,
  validatePreviewPattern,
  hostMatchesPreviewPattern,
  hostAuthorizesProof,
  isPlatformApex,
  isPublicSuffix,
} from '../vibetesting-agent/src/lib/preview-patterns.ts';
import { resolveWebhookTarget } from '../vibetesting-agent/src/lib/webhook-target.ts';
import { metaTagHasToken } from '../vibetesting-agent/src/lib/http-verify.ts';

test('reject bare platform apexes as patterns', () => {
  for (const apex of ['pages.dev', 'vercel.app', 'netlify.app', '*.pages.dev', '*.vercel.app', '*.netlify.app']) {
    const parsed = parsePreviewPattern(apex);
    assert.equal(parsed.ok, false, apex);
    if (!parsed.ok) assert.equal(parsed.code, 'platform_apex', apex);
  }
});

test('reject public suffixes as patterns', () => {
  for (const suf of ['com', '*.com', 'co.uk', '*.co.uk', 'dev', '*.io']) {
    const parsed = parsePreviewPattern(suf);
    assert.equal(parsed.ok, false, suf);
    if (!parsed.ok) assert.ok(parsed.code === 'public_suffix' || parsed.code === 'platform_apex' || parsed.code === 'invalid', suf);
  }
});

test('accept suffix under a host the owner can prove', () => {
  const parsed = parsePreviewPattern('*.sparkle-forms.pages.dev');
  assert.equal(parsed.ok, true);
  if (parsed.ok) {
    assert.equal(parsed.kind, 'wildcard');
    assert.equal(parsed.proofHost, 'sparkle-forms.pages.dev');
  }
  const ok = validatePreviewPattern('*.sparkle-forms.pages.dev', ['sparkle-forms.pages.dev']);
  assert.equal(ok.ok, true);
});

test('accept exact staging host when parent is verified', () => {
  const ok = validatePreviewPattern('staging.example.com', ['example.com']);
  assert.equal(ok.ok, true);
  const sibling = validatePreviewPattern('staging.example.com', ['app.example.com']);
  assert.equal(sibling.ok, false);
  if (!sibling.ok) assert.equal(sibling.code, 'unauthorized');
});

test('wildcard requires a prefix label', () => {
  assert.equal(hostMatchesPreviewPattern('foo.example.com', '*.example.com'), true);
  assert.equal(hostMatchesPreviewPattern('a.b.example.com', '*.example.com'), true);
  assert.equal(hostMatchesPreviewPattern('example.com', '*.example.com'), false);
  assert.equal(hostMatchesPreviewPattern('example.com.evil.com', '*.example.com'), false);
  assert.equal(hostMatchesPreviewPattern('notexample.com', '*.example.com'), false);
  assert.equal(hostMatchesPreviewPattern('staging.example.com', 'staging.example.com'), true);
  assert.equal(hostMatchesPreviewPattern('other.example.com', 'staging.example.com'), false);
});

test('verified parent authorizes subdomain proof hosts, not platform apexes', () => {
  assert.equal(hostAuthorizesProof('example.com', 'preview.example.com'), true);
  assert.equal(hostAuthorizesProof('example.com', 'example.com'), true);
  assert.equal(hostAuthorizesProof('pages.dev', 'sparkle-forms.pages.dev'), false);
  assert.equal(isPlatformApex('pages.dev'), true);
  assert.equal(isPublicSuffix('com'), true);
  assert.equal(isPlatformApex('sparkle-forms.pages.dev'), false);
});

test('resolveWebhookTarget accepts a candidate matching an allowed preview pattern', () => {
  const project = {
    url: 'https://app.example.com',
    previewPatterns: ['*.preview.example.com', 'staging.example.com'],
  };
  const wild = resolveWebhookTarget(project, 'https://pr-12.preview.example.com');
  assert.equal(wild.ok, true);
  if (wild.ok) assert.equal(wild.hostname, 'pr-12.preview.example.com');

  const exact = resolveWebhookTarget(project, 'https://staging.example.com/app');
  assert.equal(exact.ok, true);
  if (exact.ok) assert.equal(exact.hostname, 'staging.example.com');
});

test('resolveWebhookTarget still rejects unmatched hosts with host_mismatch', () => {
  const project = {
    url: 'https://app.example.com',
    previewPatterns: ['*.preview.example.com'],
  };
  const other = resolveWebhookTarget(project, 'https://evil.example.com');
  assert.equal(other.ok, false);
  if (!other.ok) assert.equal(other.code, 'host_mismatch');

  const lookalike = resolveWebhookTarget(project, 'https://preview.example.com.evil.com');
  assert.equal(lookalike.ok, false);
  if (!lookalike.ok) assert.equal(lookalike.code, 'host_mismatch');
});

test('invalid pattern shapes are rejected', () => {
  for (const bad of ['', '*.', 'https://foo.com', 'foo', '*.*.example.com', 'foo/bar']) {
    const parsed = parsePreviewPattern(bad);
    assert.equal(parsed.ok, false, bad);
  }
});

test('meta tag token matcher accepts either attribute order', () => {
  assert.equal(metaTagHasToken('<meta name="vibetesting-verify" content="abc">', 'abc'), true);
  assert.equal(metaTagHasToken('<meta content="abc" name="vibetesting-verify">', 'abc'), true);
  assert.equal(metaTagHasToken('<meta name="description" content="abc">', 'abc'), false);
});

test('unverified / empty pattern list does not widen the exact-host rule', () => {
  const project = { url: 'https://app.example.com' };
  const result = resolveWebhookTarget(project, 'https://preview.app.example.com');
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, 'host_mismatch');
});
