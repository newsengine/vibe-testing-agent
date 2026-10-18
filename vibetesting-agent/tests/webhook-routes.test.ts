import { mock, test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const enqueueScanMock = mock.fn(async (input: { url: string; authorized: boolean }) => ({
  id: 'scn_test',
  status: 'completed',
  score: 88,
  grade: 'B',
  url: input.url,
  findingsJson: '[]',
  baselineDiffJson: '{"newFailures":[]}',
}));

const postCheckRunMock = mock.fn(async () => undefined);
const auditMock = mock.fn(async () => undefined);

type ProjectFixture = {
  id: string;
  userId: string;
  url: string;
  hostname: string;
  verified: boolean;
  shipCheckEnabled: boolean;
  policy: string;
};

type UserFixture = {
  id: string;
  plan: string;
};

const state: { project: ProjectFixture | null; user: UserFixture | null } = {
  project: null,
  user: null,
};

const tables = {
  users: { id: 'users' },
  projects: { githubRepo: 'githubRepo', userId: 'userId' },
};

function resetFixtures() {
  enqueueScanMock.mock.resetCalls();
  postCheckRunMock.mock.resetCalls();
  auditMock.mock.resetCalls();
  state.project = {
    id: 'prj_1',
    userId: 'usr_1',
    url: 'https://app.example.com',
    hostname: 'app.example.com',
    verified: true,
    shipCheckEnabled: true,
    policy: 'ship',
  };
  state.user = { id: 'usr_1', plan: 'commit' };
}

mock.module('@/lib/http', {
  namedExports: {
    json(data: unknown, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { 'content-type': 'application/json' },
      });
    },
    errorResponse(err: unknown) {
      const message = err instanceof Error ? err.message : 'Internal error';
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      });
    },
    clientIp() {
      return '127.0.0.1';
    },
  },
});

mock.module('@/lib/projects', {
  namedExports: {
    getProjectByWebhookSecret: async (secret: string) => {
      if (secret === 'missing') return null;
      return state.project;
    },
  },
});

mock.module('@/lib/db', {
  namedExports: {
    schema: tables,
    getDb: async () => ({
      select() {
        return {
          from(table: { id?: string; githubRepo?: string }) {
            return {
              where() {
                return {
                  async limit() {
                    if (table === tables.users) return state.user ? [state.user] : [];
                    if (table === tables.projects) return state.project ? [state.project] : [];
                    return [];
                  },
                };
              },
            };
          },
        };
      },
    }),
  },
});

mock.module('@/lib/scans', {
  namedExports: {
    enqueueScan: enqueueScanMock,
    parseFindings: () => [],
  },
});

mock.module('@/lib/rate-limit', {
  namedExports: {
    rateLimit: async () => ({ ok: true, remaining: 10 }),
  },
});

mock.module('@/lib/audit', {
  namedExports: {
    audit: auditMock,
  },
});

mock.module('@/lib/github-app', {
  namedExports: {
    verifyGithubWebhookSignature: () => true,
    postCheckRun: postCheckRunMock,
    postPrComment: mock.fn(async () => undefined),
    policyConclusion: () => 'success' as const,
  },
});

mock.module('@/lib/plans', {
  namedExports: {
    planOf: (plan: string) => ({
      deployHooks: plan === 'daily' || plan === 'commit',
      commitHooks: plan === 'commit',
      githubApp: plan === 'daily' || plan === 'commit',
    }),
  },
});

mock.module('@/lib/config', {
  namedExports: {
    config: { appUrl: 'https://vibetestingagent.com' },
  },
});

const { POST: deployPOST } = await import('../src/app/api/webhooks/deploy/[secret]/route.ts');
const { POST: githubPOST } = await import('../src/app/api/webhooks/github/route.ts');

beforeEach(() => {
  resetFixtures();
});

async function deploy(body: unknown, secret = 'sec') {
  return deployPOST(
    new Request('http://localhost/api/webhooks/deploy/sec', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ secret }) },
  );
}

async function github(payload: Record<string, unknown>, event = 'deployment_status') {
  return githubPOST(
    new Request('http://localhost/api/webhooks/github', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': event,
        'x-hub-signature-256': 'sha256=test',
      },
      body: JSON.stringify(payload),
    }),
  );
}

function deploymentPayload(url: string, opts?: { installation?: boolean }) {
  return {
    deployment: { sha: 'abc123', payload: { web_url: url }, environment: 'preview' },
    deployment_status: { state: 'success', environment_url: url },
    repository: { full_name: 'acme/app' },
    ...(opts?.installation === false ? {} : { installation: { id: 99 } }),
  };
}

test('deploy hook: host mismatch returns 400 and does not scan', async () => {
  const res = await deploy({ url: 'https://preview.app.example.com' });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error: string; code: string };
  assert.equal(body.code, 'host_mismatch');
  assert.match(body.error, /does not match verified project host/);
  assert.equal(enqueueScanMock.mock.calls.length, 0);
});

test('deploy hook: look-alike suffix does not scan', async () => {
  const res = await deploy({ url: 'https://app.example.com.evil.com' });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { code: string };
  assert.equal(body.code, 'host_mismatch');
  assert.equal(enqueueScanMock.mock.calls.length, 0);
});

test('deploy hook: matching host scans with authorized = project.verified', async () => {
  const res = await deploy({ url: 'https://app.example.com/preview' });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { ok: boolean; scanId: string };
  assert.equal(body.ok, true);
  assert.equal(body.scanId, 'scn_test');
  assert.equal(enqueueScanMock.mock.calls.length, 1);
  const input = enqueueScanMock.mock.calls[0]?.arguments[0] as {
    url: string;
    authorized: boolean;
    trigger: string;
  };
  assert.equal(new URL(input.url).hostname, 'app.example.com');
  assert.equal(input.authorized, true);
  assert.equal(input.trigger, 'deploy');
});

test('deploy hook: userinfo and non-default port are rejected without scanning', async () => {
  const creds = await deploy({ url: 'https://user:pass@app.example.com' });
  assert.equal(creds.status, 400);
  assert.equal(((await creds.json()) as { code: string }).code, 'userinfo');

  const port = await deploy({ url: 'https://app.example.com:8443' });
  assert.equal(port.status, 400);
  assert.equal(((await port.json()) as { code: string }).code, 'port');
  assert.equal(enqueueScanMock.mock.calls.length, 0);
});

test('deploy hook: missing candidate uses project.url', async () => {
  const res = await deploy({});
  assert.equal(res.status, 200);
  const input = enqueueScanMock.mock.calls[0]?.arguments[0] as { url: string };
  assert.equal(new URL(input.url).hostname, 'app.example.com');
});

test('github hook: unverified project is skipped and not scanned', async () => {
  if (state.project) state.project.verified = false;
  const res = await github(deploymentPayload('https://app.example.com'));
  assert.equal(res.status, 200);
  const body = (await res.json()) as { ok: boolean; results: unknown[] };
  assert.equal(body.ok, true);
  assert.deepEqual(body.results, []);
  assert.equal(enqueueScanMock.mock.calls.length, 0);
  assert.equal(postCheckRunMock.mock.calls.length, 0);
});

test('github hook: host mismatch skips scan, records skipped, posts neutral check', async () => {
  const res = await github(deploymentPayload('https://preview.app.example.com'));
  assert.equal(res.status, 200);
  const body = (await res.json()) as {
    ok: boolean;
    results: { projectId: string; skipped: string }[];
  };
  assert.equal(body.ok, true);
  assert.deepEqual(body.results, [{ projectId: 'prj_1', skipped: 'host_mismatch' }]);
  assert.equal(enqueueScanMock.mock.calls.length, 0);
  assert.equal(postCheckRunMock.mock.calls.length, 1);
  const check = postCheckRunMock.mock.calls[0]?.arguments[0] as unknown as {
    conclusion: string;
    summary: string;
    headSha: string;
  };
  assert.equal(check.conclusion, 'neutral');
  assert.match(check.summary, /not the verified project host/);
  assert.equal(check.headSha, 'abc123');
});

test('github hook: matching host scans', async () => {
  const res = await github(deploymentPayload('https://app.example.com/preview'));
  assert.equal(res.status, 200);
  const body = (await res.json()) as { ok: boolean; results: { scanId: string }[] };
  assert.equal(body.ok, true);
  assert.equal(body.results[0]?.scanId, 'scn_test');
  assert.equal(enqueueScanMock.mock.calls.length, 1);
  const input = enqueueScanMock.mock.calls[0]?.arguments[0] as { authorized: boolean; url: string };
  assert.equal(input.authorized, true);
  assert.equal(new URL(input.url).hostname, 'app.example.com');
});

test('github hook: host mismatch without installation still records skip', async () => {
  const res = await github(deploymentPayload('https://evil.example.net', { installation: false }));
  assert.equal(res.status, 200);
  const body = (await res.json()) as { results: { skipped: string }[] };
  assert.equal(body.results[0]?.skipped, 'host_mismatch');
  assert.equal(enqueueScanMock.mock.calls.length, 0);
  assert.equal(postCheckRunMock.mock.calls.length, 0);
});
