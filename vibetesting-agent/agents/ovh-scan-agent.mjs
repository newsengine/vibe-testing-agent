#!/usr/bin/env node
/**
 * Full-suite scan agent for jclaw1 (OVH).
 * - Polls Cloudflare Worker only (outbound)
 * - Blocks private/metadata targets (SSRF)
 * - HMAC-signs completion payloads
 *
 * Env: VTA_API_URL, SCAN_AGENT_SECRET, ANAL_PROBE_CLI, AGENT_ID, POLL_MS
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { promisify } from 'node:util';
import dns from 'node:dns';

const lookup = promisify(dns.lookup);

const API = (process.env.VTA_API_URL || 'https://vibetesting-agent.dynamicbusiness.workers.dev').replace(
  /\/$/,
  '',
);
const SECRET = process.env.SCAN_AGENT_SECRET || '';
const AGENT_ID = process.env.AGENT_ID || 'jclaw1';
const POLL_MS = Number(process.env.POLL_MS || 5000);
const CLI = process.env.ANAL_PROBE_CLI || '/opt/vta/vibetesting-agent/dist/cli.js';

if (!SECRET) {
  console.error('SCAN_AGENT_SECRET required');
  process.exit(1);
}
if (!existsSync(CLI)) {
  console.error('vibetesting-agent CLI not found at', CLI);
  process.exit(1);
}

// --- URL safety (mirror Worker) ---
function isPrivateIpv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b, c, d] = m.slice(1).map(Number);
  if ([a, b, c, d].some((n) => n > 255)) return false;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Tailscale
  if (a >= 224) return true;
  return false;
}

function assertSafeUrl(input) {
  let raw = String(input || '').trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  const u = new URL(raw);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('only http(s)');
  if (u.username || u.password) throw new Error('credentials in URL blocked');
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (['localhost', 'metadata', 'metadata.google.internal'].includes(host)) {
    throw new Error(`blocked host ${host}`);
  }
  if (host.endsWith('.local') || host.endsWith('.internal')) throw new Error(`blocked host ${host}`);
  if (isPrivateIpv4(host)) throw new Error(`private IP ${host}`);
  // Public product hosts (vibetestingagent.com, *.workers.dev) are valid scan targets.
  return u.toString();
}

async function assertPublicDns(hostname) {
  if (isPrivateIpv4(hostname)) throw new Error(`private IP ${hostname}`);
  let ips = [];
  try {
    const r = await lookup(hostname, { all: true, verbatim: true });
    ips = r.map((x) => x.address);
  } catch {
    throw new Error(`DNS failed for ${hostname}`);
  }
  if (!ips.length) throw new Error('no DNS addresses');
  for (const ip of ips) {
    if (ip.includes(':')) {
      const x = ip.toLowerCase();
      if (x === '::1' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe80')) {
        throw new Error(`private IPv6 ${ip}`);
      }
    } else if (isPrivateIpv4(ip)) {
      throw new Error(`resolved private ${ip}`);
    }
  }
}

function canonicalJson(value) {
  return JSON.stringify(sortKeys(value));
}
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v).sort()) o[k] = sortKeys(v[k]);
    return o;
  }
  return v;
}

function signPayload(payload) {
  const mac = createHmac('sha256', SECRET);
  mac.update(canonicalJson(payload));
  return mac.digest('base64url');
}

async function api(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${SECRET}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function runProbe(url, mode, authHeaders) {
  return new Promise((resolve, reject) => {
    const args = [CLI, url, '--json', '--retries', '2'];
    if (mode === 'fast') {
      args.push('--only', 'secrets,exposure,security,dns,framework,host,components');
    }
    if (mode === 'smoke') {
      args.push('--profile', 'smoke');
    }
    // Authenticated same-origin headers from project (test session)
    if (authHeaders && typeof authHeaders === 'object') {
      if (authHeaders.cookie) {
        args.push('--cookie', authHeaders.cookie);
      }
      for (const [k, v] of Object.entries(authHeaders)) {
        if (k === 'cookie' || k === 'user-agent') continue;
        if (v) args.push('--header', `${k}: ${v}`);
      }
    }
    const child = spawn(process.execPath, args, {
      env: { ...process.env, FORCE_COLOR: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('scan timeout 180s'));
    }, 180_000);
    child.on('close', (code) => {
      clearTimeout(t);
      try {
        const parsed = JSON.parse(out);
        const findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
        resolve({ findings });
      } catch {
        reject(new Error(`bad json (exit ${code}): ${err.slice(0, 400) || out.slice(0, 200)}`));
      }
    });
  });
}

function scoreFindings(findings) {
  const failed = findings.filter((f) => !f.pass);
  let score = 100;
  for (const f of failed) {
    if (f.severity === 'high') score -= 12;
    else if (f.severity === 'medium') score -= 6;
    else if (f.severity === 'low') score -= 2;
  }
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  return {
    score,
    grade,
    summary: {
      total: findings.length,
      passed: findings.filter((f) => f.pass).length,
      failed: failed.length,
      failHigh: failed.filter((f) => f.severity === 'high').length,
      failMedium: failed.filter((f) => f.severity === 'medium').length,
      failLow: failed.filter((f) => f.severity === 'low').length,
    },
  };
}

function fixPack(url, findings, score, grade) {
  const fails = findings.filter((f) => !f.pass);
  const lines = [
    `# VibeTesting Agent Fix Pack (full suite · ${AGENT_ID})`,
    ``,
    `Target: ${url}`,
    `Score: ${score}/100 (${grade})`,
    `Runner: vibetesting-agent on ${AGENT_ID}`,
    ``,
  ];
  fails.forEach((f, i) => {
    lines.push(`## P${i + 1}. [${f.severity}] ${f.title}`);
    lines.push(`- id: \`${f.id}\``);
    lines.push(`- ${f.detail}`);
    if (f.fix) lines.push(`- fix: ${f.fix}`);
    lines.push('');
  });
  return lines.join('\n');
}

async function complete(body) {
  const unsigned = { ...body, ts: Date.now() };
  const signature = signPayload(unsigned);
  return api('/api/v1/agent/complete', { ...unsigned, signature });
}

async function tick() {
  const { job } = await api('/api/v1/agent/claim', { agentId: AGENT_ID });
  if (!job) return false;
  console.log(`[agent] claimed ${job.id} ${job.url} mode=${job.mode}`);
  try {
    const safeUrl = assertSafeUrl(job.url);
    const host = new URL(safeUrl).hostname;
    await assertPublicDns(host);
    const { findings } = await runProbe(safeUrl, job.mode, job.authHeaders);
    const { score, grade, summary } = scoreFindings(findings);
    await complete({
      scanId: job.id,
      agentId: AGENT_ID,
      score,
      grade,
      summary,
      findings,
      fixPackMarkdown: fixPack(safeUrl, findings, score, grade),
    });
    console.log(`[agent] completed ${job.id} grade=${grade} score=${score} n=${findings.length}`);
  } catch (e) {
    console.error(`[agent] failed ${job.id}`, e.message);
    await complete({
      scanId: job.id,
      agentId: AGENT_ID,
      error: e.message,
    });
  }
  return true;
}

console.log(`[agent] ${AGENT_ID} → ${API} cli=${CLI} (SSRF filter + HMAC on)`);
for (;;) {
  try {
    const worked = await tick();
    await new Promise((r) => setTimeout(r, worked ? 500 : POLL_MS));
  } catch (e) {
    console.error('[agent] loop error', e.message);
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}
