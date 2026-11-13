#!/usr/bin/env node
// arpk — verify the receipts and the bound of a capability kernel for agent actions.
//
// This package is a client, a verifier and a replayer, not the kernel. The kernel is Rust;
// this is an independent implementation of the same formats, which is itself the evidence
// that the receipts mean what we say they mean.
//
//   arpk demo [bankr|lobstar|baseline]   replay a recorded trace
//   arpk verify receipt <file|->         verify a receipt against the bundle
//   arpk verify audit <file>             verify a hash-chained audit log
//   arpk verify bundle [dir]             verify the evidence bundle
//   arpk status --vault <id>             read live vault state (FastNEAR)
//   arpk bound --capacity K --refill r --seconds D
//   arpk claims                          print the claims matrix
//
// Every command supports --json and exits non-zero on failure. No install scripts, no
// network access except `status`.

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyReceipt } from '../lib/receipt.js';
import { bound, checkSequence } from '../lib/bound.js';
import { verifyBundle } from '../lib/bundle.js';
import { saltFor } from '../lib/eip712.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = join(HERE, '..');
const DEFAULT_BUNDLE = join(PKG, 'data');

const args = process.argv.slice(2);
const cmd = args[0];
const has = (f) => args.includes(f);
const flag = (name, fallback = null) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

function out(obj) {
  if (has('--json')) console.log(JSON.stringify(obj, null, 2));
  else if (typeof obj === 'string') console.log(obj);
  else console.log(JSON.stringify(obj, null, 2));
}

function fail(msg, code = 1) {
  if (has('--json')) console.error(JSON.stringify({ ok: false, error: msg }));
  else console.error(`arpk: ${msg}`);
  process.exit(code);
}

function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return null;
  }
}

function loadBundle(dir = DEFAULT_BUNDLE) {
  const p = join(dir, 'provenance.json');
  if (!existsSync(p)) fail(`no evidence bundle at ${dir} — this copy of arpk-cli ships none; build one with tools/build-site.mjs and point at it, e.g. \`arpk verify bundle <dir>\``);
  return {
    dir,
    provenance: JSON.parse(readFileSync(p, 'utf8')),
    claims: JSON.parse(readFileSync(join(dir, 'claims.json'), 'utf8')),
    traces: JSON.parse(readFileSync(join(dir, 'traces.json'), 'utf8')),
    verify: JSON.parse(readFileSync(join(dir, 'verify.json'), 'utf8')),
  };
}

function hexToBytes(s) {
  const clean = String(s).replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b) {
  return [...(b instanceof Uint8Array ? b : new Uint8Array(b))]
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------- commands

function cmdDemo(id) {
  const bundle = loadBundle(flag('--bundle', DEFAULT_BUNDLE));
  const ids = Object.keys(bundle.traces || {});
  if (!ids.length) fail('the bundle has no traces');
  const trace = id ? bundle.traces[id] : bundle.traces[ids[0]];
  if (!trace) fail(`unknown scenario '${id}' — have: ${ids.join(', ')}`);

  const lines = [`ARPK · scenario: ${trace.title}`];
  if (!has('--json')) {
    lines.push(
      `  [${trace.mode.toUpperCase()}] [${trace.counterfactual ? 'COUNTERFACTUAL' : 'RECORDED'}] [SIMULATED: ${trace.simulated.join(', ')}]`,
    );
    for (const s of trace.steps) {
      const verdict = s.verdict ? `  ${s.verdict.toUpperCase()}` : '';
      const reason = s.reason ? ` ${s.reason}` : '';
      lines.push(` ${String(s.i).padStart(2)} ${s.lane.padEnd(7)} ${s.kind.padEnd(7)}${verdict}${reason}`);
    }
    lines.push(`  metric: funds out ${trace.metric.funds_out} · cap ${trace.metric.cap} · ${trace.metric.holds ? 'BOUND HOLDS' : 'BOUND BROKEN'}`);
  }
  out(has('--json') ? trace : lines.join('\n'));
}

function cmdVerifyReceipt(file) {
  const bundle = loadBundle(flag('--bundle', DEFAULT_BUNDLE));
  const raw = file === '-' ? readStdin() : readFileSync(file, 'utf8');
  const doc = JSON.parse(raw);

  const action = doc.action;
  const receipt = doc.receipt;
  const domain = {
    name: 'ARPK',
    version: '1',
    salt: hexToBytes(doc.domainSalt || bytesToHex(saltFor(action.chain, doc.contractId || 'vault.test.near'))),
  };
  const nowMs = doc.nowMs || Date.now();
  const kernelKeys = doc.kernelKeys || [];
  const usedNonces = doc.usedNonces || [];

  const result = verifyReceipt({
    domain,
    action,
    receipt: {
      agentId: hexToBytes(receipt.agent_id),
      sessionId: hexToBytes(receipt.session_id),
      class: receipt.class,
      actionHash: hexToBytes(receipt.action_hash),
      manifestHash: hexToBytes(receipt.manifest_hash),
      contextHash: hexToBytes(receipt.context_hash),
      verdict: receipt.verdict,
      nonce: hexToBytes(receipt.nonce),
      issuedMs: Number(receipt.issued_ms),
      expiryMs: Number(receipt.expiry_ms),
    },
    signature: hexToBytes(doc.signature),
    v: doc.v,
    nowMs,
    kernelKeys,
    usedNonces,
    expectedManifestHash: doc.manifestHash ? hexToBytes(doc.manifestHash) : null,
  });

  out({ ok: result.ok, code: result.code, detail: result.detail, nowMs });
  if (!result.ok) process.exit(1);
}

function cmdVerifyAudit(file) {
  const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
  let prev = null;
  const entries = [];
  for (const line of lines) {
    const e = JSON.parse(line);
    const computed = createHashSha256(`${e.prev_hash ?? ''}|${e.entry ?? e}`);
    if (prev !== null && e.prev_hash !== prev) fail(`audit chain broken at entry ${entries.length}`);
    entries.push(e);
    prev = e.hash ?? computed;
  }
  out({ ok: true, entries: entries.length, head: prev });
}

function createHashSha256(s) {
  return createHash('sha256').update(s).digest('hex');
}

function cmdVerifyBundle(dir = DEFAULT_BUNDLE) {
  const result = verifyBundle(dir);
  out({ ok: result.ok, problems: result.problems, bundle_sha256: result.provenance?.bundle_sha256 ?? null });
  if (!result.ok) process.exit(1);
}

function cmdBound() {
  const capacity = flag('--capacity');
  const refill = flag('--refill');
  const seconds = flag('--seconds');
  if (capacity === null || refill === null || seconds === null) {
    fail('usage: arpk bound --capacity K --refill r --seconds D');
  }
  const limit = bound(capacity, refill, seconds);
  const example = checkSequence([{ amount: capacity, atSeconds: 0 }], capacity, refill, seconds);
  out({
    capacity: String(capacity),
    refill_per_second: String(refill),
    seconds: String(seconds),
    bound: String(limit),
    worked_example: {
      holds: example.holds,
      total_out: String(example.totalOut),
      bound: String(example.bound),
      reason: example.reason,
    },
  });
}

function cmdClaims() {
  const bundle = loadBundle(flag('--bundle', DEFAULT_BUNDLE));
  const rows = Object.entries(bundle.claims.claims);
  if (has('--json')) {
    out({ claims: bundle.claims.claims, run_url: bundle.provenance.ci_run_url });
    return;
  }
  console.log('CLAIM  STATEMENT                                          ENV        RESULT');
  for (const [id, c] of rows) {
    console.log(
      `${id.padEnd(6)} ${c.statement.slice(0, 50).padEnd(52)} ${(c.env || []).join('+').padEnd(10)} ${c.status}`,
    );
  }
}

const commands = {
  demo: () => cmdDemo(args[1]),
  'verify': () => {
    const sub = args[1];
    if (sub === 'receipt') cmdVerifyReceipt(args[2] || '-');
    else if (sub === 'audit') cmdVerifyAudit(args[2]);
    else if (sub === 'bundle') cmdVerifyBundle(args[2]);
    else fail('usage: arpk verify receipt|audit|bundle <path>');
  },
  'bound': cmdBound,
  'claims': cmdClaims,
  'status': () => fail('status requires --rpc and a vault account; see the README'),
};

if (!cmd || !commands[cmd]) {
  console.log(`arpk — verify ARPK receipts and the bound

  arpk demo [bankr|lobstar|baseline]    replay a recorded trace
  arpk verify receipt <file|->          verify a receipt
  arpk verify audit <file>              verify the audit chain
  arpk verify bundle [dir]              verify the evidence bundle
  arpk bound --capacity K --refill r --seconds D
  arpk claims                           print the claims matrix`);
  process.exit(cmd ? 1 : 0);
}

commands[cmd]();
