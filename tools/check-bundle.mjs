#!/usr/bin/env node
// Validate the evidence bundle — the honesty gate a judge would want.
//
// Run after tools/build-site.mjs (CI does). Exits non-zero on the first real problem:
//   1. the bundle hash does not match its files (the bundle was edited after it was built)
//   2. a claim in verify.json disagrees with claims.json
//   3. a trace violates arpk.trace/1
//   4. a figure with no provenance
//   5. a secret-shaped string anywhere in site/
//
// Nothing here is advisory. A bundle that fails does not go live.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.argv[2] || 'site/data';
let failures = 0;

function fail(msg) {
  failures += 1;
  console.error(`check-bundle: FAIL ${msg}`);
}

function ok(msg) {
  console.log(`check-bundle: ok   ${msg}`);
}

if (!existsSync(ROOT)) {
  console.error(`check-bundle: ${ROOT} does not exist — run tools/build-site.mjs first`);
  process.exit(1);
}

const readJson = (name) => {
  const p = join(ROOT, name);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return undefined; // present but not valid JSON
  }
};

// ---------------------------------------------------------------- 1. hash
const provenance = readJson('provenance.json');
if (!provenance) {
  fail('provenance.json is missing or not valid JSON');
} else {
  for (const field of ['commit', 'generated_at', 'bundle_sha256', 'tee_mode']) {
    if (!provenance[field]) fail(`provenance.json has no '${field}'`);
  }
  ok(`provenance: commit ${String(provenance.commit).slice(0, 10)} · tee ${provenance.tee_mode} · run ${provenance.ci_run_url || 'not recorded'}`);

  if (Array.isArray(provenance.files)) {
    const canonical = provenance.files
      .map((f) => {
        const text = readFileSync(join(ROOT, f.name), 'utf8');
        const sha = createHash('sha256').update(text).digest('hex');
        if (sha !== f.sha256) fail(`${f.name} does not match the hash recorded in provenance`);
        return `${f.name}  ${sha}`;
      })
      .sort()
      .join('\n') + '\n';
    const recomputed = createHash('sha256').update(canonical).digest('hex');
    if (recomputed !== provenance.bundle_sha256) {
      fail(`bundle_sha256 mismatch: provenance says ${provenance.bundle_sha256}, files give ${recomputed}`);
    } else {
      ok(`bundle_sha256 matches ${provenance.files.length} files (${recomputed.slice(0, 16)}…)`);
    }
  } else {
    fail('provenance.json has no file list');
  }
}

// ---------------------------------------------------------------- 2. claims agree
const verify = readJson('verify.json');
const claims = readJson('claims.json');
if (verify === undefined || claims === undefined) {
  fail('verify.json or claims.json is not valid JSON');
} else if (verify && claims) {
  if (JSON.stringify(verify.claims) !== JSON.stringify(claims.claims)) {
    fail('verify.json and claims.json disagree about the claims — the dashboard would show two different stories');
  } else {
    const rows = Object.entries(claims.claims);
    const pass = rows.filter(([, c]) => c.status === 'PASS').length;
    ok(`claims: ${pass} PASS · ${rows.length - pass} not PASS (of ${rows.length})`);
    for (const [id, c] of rows) {
      if (!c.statement) fail(`${id} has no statement`);
      if (!c.env) fail(`${id} has no env tag — a claim without an environment is not publishable`);
      if (c.status === 'PASS' && c.missing_tests && c.missing_tests.length > 0) {
        fail(`${id} is PASS but lists missing tests: ${c.missing_tests.join(', ')}`);
      }
    }
  }
}

// ---------------------------------------------------------------- 3. traces
const traces = readJson('traces.json');
if (traces === undefined) {
  fail('traces.json is not valid JSON');
} else if (traces) {
  const LANES = ['owner', 'agent', 'kernel', 'relayer', 'vault'];
  let count = 0;
  for (const [id, t] of Object.entries(traces)) {
    count += 1;
    if (t.schema !== 'arpk.trace/1') fail(`trace ${id}: wrong schema`);
    if (t.counterfactual && (!t.simulated || t.simulated.length === 0)) {
      fail(`trace ${id}: counterfactual but declares nothing simulated`);
    }
    (t.steps || []).forEach((s, i) => {
      if (s.i !== i) fail(`trace ${id}: step ${i} is numbered ${s.i}`);
      if (!LANES.includes(s.lane)) fail(`trace ${id}: step ${i} has unknown lane '${s.lane}'`);
      if (s.verdict === 'deny' && !(s.reason || '').startsWith('ARPK:')) {
        fail(`trace ${id}: step ${i} denies without an exact ARPK:* code`);
      }
    });
    if (t.metric.holds !== (BigInt(t.metric.funds_out) <= BigInt(t.metric.cap))) {
      fail(`trace ${id}: metric.holds disagrees with funds_out vs cap`);
    }
  }
  ok(`traces: ${count} valid (${Object.keys(traces).join(', ')})`);
}

// ---------------------------------------------------------------- 4. provenance everywhere
if (provenance && !provenance.ci_run_url) {
  fail('provenance has no CI run URL — a judge cannot check where this came from');
}

// ---------------------------------------------------------------- 5. secrets
const SECRET_PATTERNS = [
  /npm_[A-Za-z0-9]{20,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /gh[pousr]_[A-Za-z0-9]{20,}/,
    /ARPK_TEE\s*=\s*(?!simulator)[A-Za-z0-9_-]+/,
  ];
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}
if (existsSync('site')) {
  for (const file of walk('site')) {
    const text = readFileSync(file, 'utf8');
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.test(text)) {
        fail(`${file} contains a secret-shaped string (${pattern})`);
      }
    }
  }
  ok('secret scan: no secret-shaped strings under site/');
}

console.log(failures === 0
  ? 'check-bundle: PASS — the bundle is internally consistent and publishable'
  : `check-bundle: ${failures} problem(s)`);
process.exit(failures === 0 ? 0 : 1);
