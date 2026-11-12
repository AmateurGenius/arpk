// Bundle verification — the same checks tools/check-bundle.mjs runs, available to anyone
// who installed the package rather than cloning the repo.
//
// It is deliberately strict: a bundle whose hash does not match its files is not evidence.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const NAMES = ['verify.json', 'claims.json', 'vectors.json', 'nonclaims.json', 'fuzz.json', 'traces.json'];

export function verifyBundle(dir) {
  const problems = [];
  const read = (name) => {
    const p = join(dir, name);
    if (!existsSync(p)) return null;
    try {
      return JSON.parse(readFileSync(p, 'utf8'));
    } catch {
      return undefined;
    }
  };

  const provenance = read('provenance.json');
  if (!provenance) {
    problems.push('provenance.json is missing or not valid JSON');
  } else {
    for (const field of ['commit', 'generated_at', 'bundle_sha256', 'tee_mode']) {
      if (!provenance[field]) problems.push(`provenance.json has no '${field}'`);
    }
    if (Array.isArray(provenance.files)) {
      const canonical = provenance.files
        .map((f) => {
          const text = readFileSync(join(dir, f.name), 'utf8');
          const sha = createHash('sha256').update(text).digest('hex');
          if (sha !== f.sha256) problems.push(`${f.name} does not match its recorded hash`);
          return `${f.name}  ${sha}`;
        })
        .sort()
        .join('\n') + '\n';
      const recomputed = createHash('sha256').update(canonical).digest('hex');
      if (recomputed !== provenance.bundle_sha256) {
        problems.push('bundle_sha256 does not match the files — the bundle was edited after it was built');
      }
    } else {
      problems.push('provenance.json has no file list');
    }
  }

  const verify = read('verify.json');
  const claims = read('claims.json');
  if (verify && claims && JSON.stringify(verify.claims) !== JSON.stringify(claims.claims)) {
    problems.push('verify.json and claims.json disagree about the claims');
  }

  const traces = read('traces.json');
  if (traces) {
    const LANES = ['owner', 'agent', 'kernel', 'relayer', 'vault'];
    for (const [id, t] of Object.entries(traces)) {
      if (t.schema !== 'arpk.trace/1') problems.push(`trace ${id}: wrong schema`);
      if (t.counterfactual && (!t.simulated || t.simulated.length === 0)) {
        problems.push(`trace ${id}: counterfactual but declares nothing simulated`);
      }
      (t.steps || []).forEach((s, i) => {
        if (s.i !== i) problems.push(`trace ${id}: step ${i} is numbered ${s.i}`);
        if (!LANES.includes(s.lane)) problems.push(`trace ${id}: step ${i} has unknown lane '${s.lane}'`);
        if (s.verdict === 'deny' && !(s.reason || '').startsWith('ARPK:')) {
          problems.push(`trace ${id}: step ${i} denies without an exact ARPK:* code`);
        }
      });
    }
  }

  // A missing optional file is fine; a present-but-broken one is not.
  for (const name of NAMES) {
    if (read(name) === undefined) problems.push(`${name} is present but not valid JSON`);
  }

  return { ok: problems.length === 0, problems, provenance };
}
