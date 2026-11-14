import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cfBypassHeaders, withCfBypassHeaders, hostMatchesAllowlist, parseHostAllowlist,
} from '../src/cf-bypass-headers.ts';

const KEYS = [
  'CF_SMOKE_KEY', 'X_SMOKE_KEY', 'SMOKE_KEY', 'CF_ACCESS_CLIENT_ID', 'CF_ACCESS_CLIENT_SECRET',
  'VTA_SMOKE_KEY_HOSTS', 'VTA_CF_ACCESS_HOSTS',
];

function withEnv(vars: Record<string, string>, fn: () => void) {
  const prev: Record<string, string | undefined> = {};
  for (const k of KEYS) { prev[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, vars);
  try { fn(); } finally {
    for (const k of KEYS) {
      if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k];
    }
  }
}

test('parseHostAllowlist splits on commas and whitespace', () => {
  assert.deepEqual(parseHostAllowlist(' App.Example.com, *.example.com  staging.example.org. '),
    ['app.example.com', '*.example.com', 'staging.example.org']);
  assert.deepEqual(parseHostAllowlist(undefined), []);
  assert.deepEqual(parseHostAllowlist(''), []);
});

test('hostMatchesAllowlist: exact entries and *. subdomain entries', () => {
  const list = ['example.com', '*.example.com', 'staging.example.org'];
  assert.equal(hostMatchesAllowlist('example.com', list), true);
  assert.equal(hostMatchesAllowlist('www.example.com', list), true);
  assert.equal(hostMatchesAllowlist('a.b.example.com', list), true);
  assert.equal(hostMatchesAllowlist('staging.example.org', list), true);
  assert.equal(hostMatchesAllowlist('example.org', list), false);
  assert.equal(hostMatchesAllowlist('notexample.com', list), false);
  assert.equal(hostMatchesAllowlist('example.com.evil.test', list), false);
  assert.equal(hostMatchesAllowlist('www.example.com', ['example.com']), false);
  assert.equal(hostMatchesAllowlist('example.com', ['*.example.com']), false);
  assert.equal(hostMatchesAllowlist('', list), false);
});

test('cfBypassHeaders sends nothing when no allowlist is configured', () => {
  withEnv({ CF_SMOKE_KEY: 'smk_test', CF_ACCESS_CLIENT_ID: 'id.access', CF_ACCESS_CLIENT_SECRET: 'cfast_test' }, () => {
    assert.deepEqual(cfBypassHeaders('https://app.example.com'), {});
    assert.deepEqual(cfBypassHeaders('https://staging.example.com/path'), {});
  });
});

test('cfBypassHeaders empty without secrets even for allowlisted hosts', () => {
  withEnv({ VTA_SMOKE_KEY_HOSTS: 'example.com,*.example.com', VTA_CF_ACCESS_HOSTS: 'staging.example.com' }, () => {
    assert.deepEqual(cfBypassHeaders('https://staging.example.com'), {});
  });
});

test('cfBypassHeaders smoke key + Access headers follow their allowlists', () => {
  withEnv({
    CF_SMOKE_KEY: 'smk_test',
    CF_ACCESS_CLIENT_ID: 'id.access',
    CF_ACCESS_CLIENT_SECRET: 'cfast_test',
    VTA_SMOKE_KEY_HOSTS: 'example.com, *.example.com',
    VTA_CF_ACCESS_HOSTS: 'staging.example.com',
  }, () => {
    const staging = cfBypassHeaders('https://staging.example.com/path');
    assert.equal(staging['x-smoke-key'], 'smk_test');
    assert.equal(staging['CF-Access-Client-Id'], 'id.access');
    assert.equal(staging['CF-Access-Client-Secret'], 'cfast_test');

    const www = cfBypassHeaders('https://www.example.com');
    assert.equal(www['x-smoke-key'], 'smk_test');
    assert.equal(www['CF-Access-Client-Id'], undefined);
    assert.equal(www['CF-Access-Client-Secret'], undefined);

    const apex = cfBypassHeaders('https://example.com/');
    assert.equal(apex['x-smoke-key'], 'smk_test');
    assert.equal(apex['CF-Access-Client-Id'], undefined);

    const merged = withCfBypassHeaders('https://staging.example.com', { cookie: 'a=b' });
    assert.equal(merged?.cookie, 'a=b');
    assert.equal(merged?.['x-smoke-key'], 'smk_test');
  });
});

test('cfBypassHeaders never sends secrets to third-party or lookalike hosts', () => {
  withEnv({
    CF_SMOKE_KEY: 'smk_test',
    CF_ACCESS_CLIENT_ID: 'id.access',
    CF_ACCESS_CLIENT_SECRET: 'cfast_test',
    VTA_SMOKE_KEY_HOSTS: '*.example.com',
    VTA_CF_ACCESS_HOSTS: 'staging.example.com',
  }, () => {
    assert.deepEqual(cfBypassHeaders('https://fonts.googleapis.com/css?family=Inter'), {});
    assert.deepEqual(cfBypassHeaders('https://cdn.jsdelivr.net/npm/foo'), {});
    assert.deepEqual(cfBypassHeaders('https://example.com.evil.test/'), {});
    assert.deepEqual(cfBypassHeaders('https://notexample.com/'), {});
    assert.deepEqual(cfBypassHeaders('https://my-app.pages.dev/'), {});
  });
});
