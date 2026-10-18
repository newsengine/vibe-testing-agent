import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveWebhookTarget, webhookHostMismatchSummary } from '../vibetesting-agent/src/lib/webhook-target.ts';

const project = { url: 'https://app.example.com/dashboard' };

test('resolveWebhookTarget: exact hostname match', () => {
  const result = resolveWebhookTarget(project, 'https://app.example.com/preview');
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.hostname, 'app.example.com');
    assert.equal(new URL(result.url).pathname, '/preview');
  }
});

test('resolveWebhookTarget: hostname compare is case-insensitive', () => {
  const result = resolveWebhookTarget(project, 'https://APP.Example.COM/x');
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.hostname, 'app.example.com');
});

test('resolveWebhookTarget: subdomain is not the verified host', () => {
  const result = resolveWebhookTarget(project, 'https://preview.app.example.com');
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, 'host_mismatch');
});

test('resolveWebhookTarget: look-alike suffix is not the verified host', () => {
  const suffix = resolveWebhookTarget(project, 'https://app.example.com.evil.com');
  assert.equal(suffix.ok, false);
  if (!suffix.ok) assert.equal(suffix.code, 'host_mismatch');

  const lookalike = resolveWebhookTarget(project, 'https://not-app.example.com');
  assert.equal(lookalike.ok, false);
  if (!lookalike.ok) assert.equal(lookalike.code, 'host_mismatch');

  const prefix = resolveWebhookTarget(project, 'https://app.example.com.attacker');
  assert.equal(prefix.ok, false);
  if (!prefix.ok) assert.equal(prefix.code, 'host_mismatch');
});

test('resolveWebhookTarget: reject userinfo', () => {
  const result = resolveWebhookTarget(project, 'https://user:pass@app.example.com');
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, 'userinfo');

  const userOnly = resolveWebhookTarget(project, 'https://user@app.example.com');
  assert.equal(userOnly.ok, false);
  if (!userOnly.ok) assert.equal(userOnly.code, 'userinfo');
});

test('resolveWebhookTarget: reject non-default ports', () => {
  const result = resolveWebhookTarget(project, 'https://app.example.com:8443');
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, 'port');
});

function withEnv(vars: { NODE_ENV?: string | undefined; VTA_ENV?: string | undefined }, fn: () => void) {
  const prevNode = process.env.NODE_ENV;
  const prevVta = process.env.VTA_ENV;
  const restore = (key: 'NODE_ENV' | 'VTA_ENV', prev: string | undefined) => {
    if (prev === undefined) delete process.env[key];
    else process.env[key] = prev;
  };
  try {
    if (vars.NODE_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = vars.NODE_ENV;
    if (vars.VTA_ENV === undefined) delete process.env.VTA_ENV;
    else process.env.VTA_ENV = vars.VTA_ENV;
    fn();
  } finally {
    restore('NODE_ENV', prevNode);
    restore('VTA_ENV', prevVta);
  }
}

test('resolveWebhookTarget: reject remote http even in test', () => {
  withEnv({ NODE_ENV: 'test', VTA_ENV: undefined }, () => {
    const remote = resolveWebhookTarget(project, 'http://app.example.com');
    assert.equal(remote.ok, false);
    if (!remote.ok) assert.equal(remote.code, 'insecure_url');
  });
});

test('resolveWebhookTarget: unset NODE_ENV rejects http localhost', () => {
  withEnv({ NODE_ENV: undefined, VTA_ENV: undefined }, () => {
    const result = resolveWebhookTarget({ url: 'http://localhost/' }, 'http://localhost/preview');
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'insecure_url');
  });
});

test('resolveWebhookTarget: allow http localhost only when env is development or test', () => {
  const localProject = { url: 'http://localhost/' };
  withEnv({ NODE_ENV: 'test', VTA_ENV: undefined }, () => {
    const local = resolveWebhookTarget(localProject, 'http://localhost/preview');
    assert.equal(local.ok, true);
  });
  withEnv({ NODE_ENV: undefined, VTA_ENV: 'development' }, () => {
    const local = resolveWebhookTarget(localProject, 'http://localhost/preview');
    assert.equal(local.ok, true);
  });
  withEnv({ NODE_ENV: 'production', VTA_ENV: undefined }, () => {
    const result = resolveWebhookTarget({ url: 'https://localhost/' }, 'http://localhost/');
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'insecure_url');
  });
});

test('resolveWebhookTarget: invalid URL', () => {
  const result = resolveWebhookTarget(project, 'not a url');
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, 'invalid_url');

  const js = resolveWebhookTarget(project, 'javascript:alert(1)');
  assert.equal(js.ok, false);
  if (!js.ok) assert.equal(js.code, 'invalid_url');
});

test('resolveWebhookTarget: scheme-less hostname is treated as https', () => {
  const result = resolveWebhookTarget(project, 'app.example.com/preview');
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.hostname, 'app.example.com');
    assert.equal(new URL(result.url).protocol, 'https:');
  }
});

test('webhookHostMismatchSummary explains reject-not-fallback', () => {
  const summary = webhookHostMismatchSummary({ url: 'https://app.example.com', hostname: 'app.example.com' });
  assert.match(summary, /app\.example\.com/);
  assert.match(summary, /false pass/);
});

test('resolveWebhookTarget: missing candidate uses project.url', () => {
  const missing = resolveWebhookTarget(project, undefined);
  assert.equal(missing.ok, true);
  if (missing.ok) {
    assert.equal(missing.hostname, 'app.example.com');
    assert.equal(new URL(missing.url).pathname, '/dashboard');
  }

  const empty = resolveWebhookTarget(project, '   ');
  assert.equal(empty.ok, true);
  if (empty.ok) assert.equal(empty.hostname, 'app.example.com');

  const nulled = resolveWebhookTarget(project, null);
  assert.equal(nulled.ok, true);
  if (nulled.ok) assert.equal(nulled.hostname, 'app.example.com');
});
