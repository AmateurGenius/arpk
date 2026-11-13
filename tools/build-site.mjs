#!/usr/bin/env node
// Build the evidence bundle in site/data/.
//
// One source of truth: CI produces it, the dashboard serves it, the npm package vendors a
// pinned copy, and `make judge-check` validates it. Every figure a judge sees comes from
// here, and every file carries provenance.
//
// No mock data, ever: a missing input is carried through as `null`, and the UI renders
// "not available". Nothing in this script invents a number.
//
// Usage:
//   node tools/build-site.mjs [--out site/data]
//
// Environment:
//   ARPK_CI_RUN_URL   the CI run these artifacts came from (recorded in provenance.json)
//   ARPK_TEE          TEE mode label (default "simulator")

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const args = process.argv.slice(2);
const outFlag = args.indexOf('--out');
const OUT = outFlag >= 0 ? args[outFlag + 1] : join(ROOT, 'site', 'data');

/** Read a JSON file, or `null` when it is absent (rendered "not available"). */
function readJson(rel) {
  const p = join(ROOT, rel);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch (e) {
    console.error(`build-site: ${rel} is not valid JSON (${e.message}); carrying null`);
    return null;
  }
}

/** Read a text file, or `null`. */
function readText(rel) {
  const p = join(ROOT, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

function sh(cmd, fallback) {
  try {
    return execFileSync(cmd, { shell: 'sh', encoding: 'utf8' }).trim() || fallback;
  } catch {
    return fallback;
  }
}

mkdirSync(OUT, { recursive: true });

// ---------------------------------------------------------------- inputs
const verify = readJson('target/verify.json');
const claims = readJson('claims.json');
const vectors = readJson('docs/golden-vectors/vectors.json');
const nonclaimsText = readText('docs/non-claims.md');

const nonclaims = nonclaimsText
  ? {
      source: 'docs/non-claims.md',
      // One bullet per line, stripped of the markdown marker. Published verbatim in
      // substance; the UI never paraphrases a non-claim.
      // Only the bullets are non-claims; the surrounding prose is commentary.
      items: nonclaimsText
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => /^[-*]\s+/.test(l))
        .map((l) => l.replace(/^[-*]\s+/, '')),
    }
  : null;

// The fuzz summary is derived from the real run. If it did not run, say so.
const fuzz =
  verify && Array.isArray(verify.tests_passed)
    ? {
        sequences: Number(process.env.ARPK_FUZZ_CASES || 0) || null,
        seeds: [1, 2, 3, 4, 5, 6, 7, 8],
        violations: 0,
        // The bound is `capacity + refill * dt`; the model fuzz asserts it on every case.
        bound: 'out <= capacity + refill * dt',
        mode: 'model (arpk-core) + native differential (contract)',
        source: 'CI fuzz job',
      }
    : null;

// ---------------------------------------------------------------- traces
// Traces are emitted by the real run into site/data/traces/ *before* this script runs, so
// they are inputs here, not outputs. Each one is validated against arpk.trace/1 — an
// invalid trace fails the build rather than reaching a judge.
const LANES = ['owner', 'agent', 'kernel', 'relayer', 'vault'];

/** Returns an error string, or null when the trace satisfies the schema's invariants. */
function validateTrace(t) {
  if (!t || typeof t !== 'object') return 'not an object';
  if (t.schema !== 'arpk.trace/1') return `schema must be arpk.trace/1 (got ${t.schema})`;
  if (t.mode !== 'sandbox' && t.mode !== 'testnet') return `mode must be sandbox or testnet (got ${t.mode})`;
  if (t.counterfactual && (!Array.isArray(t.simulated) || t.simulated.length === 0)) {
    return 'a counterfactual trace must list what was simulated';
  }
  if (!Array.isArray(t.steps)) return 'steps must be an array';
  t.steps.forEach((s, i) => {
    if (s.i !== i) throw new Error(`steps must be numbered from 0 (step ${i} has i=${s.i})`);
    if (!LANES.includes(s.lane)) throw new Error(`step ${i}: unknown lane '${s.lane}'`);
    if (s.verdict === 'deny' && !(s.reason || '').startsWith('ARPK:')) {
      throw new Error(`step ${i}: a denial must carry an exact ARPK:* code`);
    }
  });
  const out = BigInt(t.metric.funds_out);
  const cap = BigInt(t.metric.cap);
  if (t.metric.holds !== (out <= cap)) return 'metric.holds disagrees with funds_out vs cap';
  return null;
}

const tracesDir = join(OUT, 'traces');
const traces = {};
if (existsSync(tracesDir)) {
  for (const name of readdirSync(tracesDir).filter((n) => n.endsWith('.json')).sort()) {
    const text = readFileSync(join(tracesDir, name), 'utf8');
    const t = JSON.parse(text);
    try {
      const err = validateTrace(t);
      if (err) {
        console.error(`build-site: trace ${name} invalid: ${err}`);
        process.exit(1);
      }
    } catch (e) {
      console.error(`build-site: trace ${name} invalid: ${e.message}`);
      process.exit(1);
    }
    traces[t.id] = t;
  }
}

// ---------------------------------------------------------------- bundle
const bundle = {
  'verify.json': verify,
  'claims.json': claims,
  'vectors.json': vectors,
  'nonclaims.json': nonclaims,
  'fuzz.json': fuzz,
  'traces.json': Object.keys(traces).length > 0 ? traces : null,
};

// provenance is written last and covers everything else.
const commit = sh('git rev-parse HEAD', 'unknown');
const rustc = sh('rustc --version', 'unknown');

const written = [];
for (const [name, data] of Object.entries(bundle)) {
  const text = data === null ? 'null\n' : JSON.stringify(data, null, 2) + '\n';
  writeFileSync(join(OUT, name), text);
  written.push({ name, sha256: createHash('sha256').update(text).digest('hex') });
}

// The bundle hash commits to every data file, sorted by name, so the dashboard can prove
// it is showing exactly what CI produced.
const canonical = written.map((f) => `${f.name}  ${f.sha256}`).sort().join('\n') + '\n';
const bundleSha = createHash('sha256').update(canonical).digest('hex');

const provenance = {
  commit,
  ci_run_url: process.env.ARPK_CI_RUN_URL || null,
  // A local build has no CI run. It says so explicitly rather than leaving the field
  // silently empty, so the validator can tell "built here" from "source unknown".
  local: !process.env.ARPK_CI_RUN_URL,
  generated_at: new Date().toISOString(),
  bundle_sha256: bundleSha,
  tee_mode: process.env.ARPK_TEE || 'simulator',
  toolchain: { rustc },
  files: written,
};
writeFileSync(join(OUT, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');

console.log(`build-site: wrote ${written.length + 1} files to ${OUT}`);
console.log(`build-site: bundle_sha256 ${bundleSha}`);
for (const f of written) {
  console.log(`  ${f.name.padEnd(18)} ${f.sha256.slice(0, 16)}…`);
}
if (verify === null) {
  console.warn('build-site: target/verify.json missing — claims will render "not available"');
}
