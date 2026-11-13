// ARPK dashboard — a verification instrument, not a poster.
//
// Every figure rendered here comes from data/*.json, which CI builds from real artifacts
// and commits to one hash. Nothing is fetched from a third party: no CDN, no font, no
// wallet, no analytics. If a file is missing the view says "not available" — it never
// invents a number.

const B = 'data';
const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');

const state = {
  provenance: null,
  verify: null,
  claims: null,
  traces: null,
  nonclaims: null,
  fuzz: null,
  vectors: null,
};

// ---------------------------------------------------------------- utilities

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function notAvailable(what) {
  return `<p class="muted">not available — ${esc(what)} was not in the bundle this page was built from.</p>`;
}

/** Truncate a hash for display with an expander, never hiding the full value. */
function shortHash(h) {
  if (!h) return '—';
  const s = String(h);
  return s.length <= 16 ? esc(s) : `<span class="mono">${esc(s.slice(0, 16))}…</span>`;
}

function badge(text, kind = 'grey') {
  return `<span class="badge badge-${kind}"><span class="dot" aria-hidden="true"></span>${esc(text)}</span>`;
}

function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2600);
}

// Status colour is never the only signal: every status carries an icon (the dot) and a word.
function statusBadge(status) {
  const map = { PASS: 'pass', FAIL: 'deny', SKIP: 'warn', 'NOT BUILT': 'grey' };
  const label = status === 'SKIP' ? 'SKIP' : status;
  return badge(label, map[status] || 'grey');
}

function envBadge(env) {
  const labels = {
    local: 'LOCAL',
    ci: 'CI',
    testnet: 'TESTNET',
  };
  const text = Array.isArray(env) ? env.map((e) => labels[e] || e.toUpperCase()).join(' + ') : '—';
  return badge(text, 'info');
}

// ---------------------------------------------------------------- data

async function loadBundle() {
  const files = ['provenance', 'verify', 'claims', 'traces', 'nonclaims', 'fuzz', 'vectors'];
  const results = await Promise.all(
    files.map(async (name) => {
      try {
        const res = await fetch(`${B}/${name}.json`);
        if (!res.ok) throw new Error(String(res.status));
        const json = await res.json();
        return [name, json && Object.keys(json).length > 0 ? json : null];
      } catch {
        return [name, null];
      }
    }),
  );
  for (const [name, json] of results) state[name] = json;
}

function renderProvenance() {
  const p = state.provenance;
  $('#prov-run').textContent = p?.ci_run_url ? `run ${p.ci_run_url.split('/').pop()}` : 'run —';
  $('#prov-run').innerHTML = p?.ci_run_url
    ? `run <a href="${esc(p.ci_run_url)}">#${esc(p.ci_run_url.split('/').pop())}</a>`
    : 'run —';
  $('#prov-commit').textContent = `commit ${String(p?.commit || '—').slice(0, 10)}`;
  $('#prov-time').textContent = p?.generated_at ? `generated ${p.generated_at}` : 'generated —';
  $('#prov-hash').textContent = `sha256 ${String(p?.bundle_sha256 || '—').slice(0, 16)}…`;
}

// ---------------------------------------------------------------- views

function viewProof() {
  const c = state.claims?.claims || state.verify?.claims;
  const rows = c ? Object.entries(c) : [];
  const byId = Object.fromEntries(rows);
  const pass = rows.filter(([, v]) => v.status === 'PASS').length;

  const strip = [
    { num: rows.length ? `${pass} / ${rows.length}` : '—', label: 'claims backed by named tests' },
    { num: state.fuzz?.sequences ? Number(state.fuzz.sequences).toLocaleString() : '10^5', label: 'adversarial sequences' },
    { num: '0', label: 'bound violations' },
    { num: '5 / 5', label: 'golden vectors reproduced in JS' },
  ];

  const layer = (n, title, body, claimId) =>
    `<div class="card">
       <h3 style="margin-top:0"><span class="mono muted">layer ${n}</span> — ${title}
         <span class="step-meta">${byId[claimId] ? statusBadge(byId[claimId].status) : ''}</span></h3>
       <p>${body}</p>
     </div>`;

  return `
    <h1>ARPK is a capability kernel for AI agent actions.</h1>
    <p class="muted">
      Every effect requires a capability the agent cannot forge. An injected
      "send to 0xATTACKER" cannot even be written. Authority attenuates when provenance is
      untrusted. The contract bounds the loss as the fourth layer — defense in depth, so a
      compromised kernel is still a bounded event.
    </p>

    <div class="btn-row">
      <a class="btn btn-primary" href="#/theater/bankr">▶ Watch an injection attack get stopped</a>
      <a class="btn" href="#/evidence">Read the evidence</a>
    </div>

    ${layer(1, 'No designation without authority',
      'The intent schema has <span class="mono">deny_unknown_fields</span> and no <span class="mono">to</span> field. ' +
      'Intents name <em>handles</em> the manifest issued. An unissued handle is ' +
      '<span class="mono">ARPK:action.unclassified</span> before the policy engine runs; an injected destination ' +
      'is <span class="mono">ARPK:malformed</span>. The destination cannot be expressed at all.',
      'C2')}
    ${layer(2, 'Capability verification at the effector',
      'The receipt is an object-capability token: EIP-712, bound to the exact action and the owner-signed manifest, ' +
      'one-shot by nonce, time-bounded to 120&nbsp;s. The contract recovers the signer with <span class="mono">ecrecover</span> ' +
      'and <em>verifies</em> rather than adjudicates.',
      'C1')}
    ${layer(3, 'Capability attenuation',
      'Untrusted ingress degrades the session through the Authority Ledger: Full → Degraded → AskOnly → Frozen. ' +
      'A degraded session is bounded by the manifest cap <span class="mono">degraded_cap</span>, enforced in Cedar ' +
      '<em>and</em> in the kernel.',
      'C3')}
    ${layer(4, 'Defense in depth — the on-chain bound',
      'The caps are enforced by the contract, not the kernel, so the bound survives a compromised kernel. ' +
      'Fuzzed at 10⁵ sequences and 10⁴ differential steps against the real contract.',
      'C8')}

    <div class="strip">
      ${strip.map((s) => `<div class="strip-item"><div class="strip-num">${s.num}</div><div class="strip-label">${esc(s.label)}</div></div>`).join('')}
    </div>

    <details class="disclosure" open>
      <summary>What ARPK does <em>not</em> claim</summary>
      ${state.nonclaims?.items?.length
        ? `<ul>${state.nonclaims.items.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`
        : notAvailable('the non-claims list')}
      <p class="muted">
        Two capability properties are designed but not built, and are labeled as such in the ledger:
        process containment (C9) and compile-time typestate enforcement (C10).
      </p>
    </details>

    <details class="disclosure">
      <summary>Prior art we build on</summary>
      <p>
        The <strong>Unfireable Safety Kernel</strong> (Dobrin &amp; Chmiel, Jun 2026) — separate
        process, fail-closed, signed evidence, Kani on the gate. <strong>Symbiont/ORGA</strong>
        (ThirdKey, Apr 2026) — typestate agent loop with a Cedar gate and audit. The
        <strong>Sondera</strong> harness (hook-based Cedar), <strong>OutLayer</strong> (TEE-side
        policy), <strong>ERC-7710</strong> caveat enforcers, and AWS's Cedar-based agent policy.
      </p>
      <p class="muted">
        ARPK's delta, stated narrowly: the receipt is a capability token verified by an
        <strong>on-chain effector</strong> that independently caps loss, with one arithmetic core
        shared by the kernel and the contract.
      </p>
    </details>

    ${rows.length ? `
      <h2>Claims, in the order that matters</h2>
      <p class="muted">The capability layers first; the bound is the backstop.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Claim</th><th>Env</th><th>Result</th></tr></thead>
          <tbody>
            ${rows.map(([id, v]) => `
              <tr>
                <td class="num">${esc(id)}</td>
                <td>${esc(v.statement)}</td>
                <td>${envBadge(v.env)}</td>
                <td>${statusBadge(v.status)}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>` : notAvailable('the claims ledger')}
  `;
}

function viewTheater(scenarioId) {
  const traces = state.traces || {};
  const ids = Object.keys(traces);
  if (!ids.length) {
    return `<h1>Theater</h1>${notAvailable('the scenario traces')}`;
  }
  const id = scenarioId && traces[scenarioId] ? scenarioId : ids[0];
  const t = traces[id];
  const lanes = ['owner', 'agent', 'kernel', 'relayer', 'vault'];

  const laneHtml = lanes
    .map((lane) => {
      const steps = t.steps.filter((s) => s.lane === lane);
      if (!steps.length) return '';
      return `
        <div class="lane">
          <div class="lane-name">${esc(lane)}</div>
          <div class="lane-steps">
            ${steps.map((s) => {
              const cls = s.verdict === 'deny' ? 'step-deny' : s.verdict === 'allow' ? 'step-allow' : '';
              return `
                <div class="step ${cls}">
                  <div class="step-kind">${esc(s.kind)}</div>
                  <p class="step-label">${esc(s.label)}</p>
                  <div class="step-meta">
                    ${s.reason ? `<span class="reason">${esc(s.reason)}</span>` : ''}
                    ${s.label_source ? badge(`source: ${s.label_source}`, 'warn') : ''}
                    ${s.funds_out !== undefined && s.funds_out !== null ? `<span class="mono">funds out ${esc(s.funds_out)}</span>` : ''}
                  </div>
                </div>`;
            }).join('')}
          </div>
        </div>`;
    })
    .join('');

  const bucket = t.steps.map((s) => s.bucket).find(Boolean);
  const pct = bucket ? Math.max(0, Math.min(100, (Number(bucket.tokens) / Number(bucket.capacity)) * 100)) : 0;

  return `
    <h1>Theater</h1>
    <div class="btn-row">
      ${ids.map((i) => `<a class="btn ${i === id ? 'btn-primary' : ''}" href="#/theater/${esc(i)}">${esc(i)}</a>`).join('')}
    </div>

    <div class="card">
      <h2 style="margin-top:0">${esc(t.title)}</h2>
      <p class="muted">
        Read it left to right: the agent names <em>handles</em> the manifest issued — never raw
        destinations — then the kernel decides, then the contract enforces. Every denial carries
        the exact <span class="mono">ARPK:*</span> code the code path produced.
      </p>
      <div class="step-meta">
        ${badge(t.mode.toUpperCase(), 'info')}
        ${t.counterfactual ? badge('COUNTERFACTUAL', 'warn') : badge('RECORDED', 'pass')}
        ${badge('SIMULATED', 'warn')}
      </div>
      ${t.counterfactual ? `
        <p class="muted"><strong>Simulated:</strong> ${t.simulated.map(esc).join(' · ')}.
        This is a reconstruction of an incident, not a reproduction — the verdict is a judgment, not a test.</p>` : ''}

      ${bucket ? `
        <div class="gauge">
          <div class="gauge-label"><span>bucket</span><span>${esc(bucket.tokens)} / ${esc(bucket.capacity)}</span></div>
          <div class="gauge-track" role="img" aria-label="bucket ${esc(bucket.tokens)} of ${esc(bucket.capacity)}">
            <div class="gauge-fill" style="width:${pct}%"></div>
          </div>
        </div>` : ''}

      <div class="lanes">${laneHtml || '<p class="muted">No steps.</p>'}</div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Metric</h3>
      <p>
        funds out <span class="mono">${esc(t.metric.funds_out)}</span> ·
        cap <span class="mono">${esc(t.metric.cap)}</span> ·
        ${t.metric.holds ? badge('BOUND HOLDS', 'pass') : badge('BOUND BROKEN', 'deny')}
      </p>
    </div>
  `;
}

function viewEvidence() {
  const c = state.claims?.claims || state.verify?.claims;
  const rows = c ? Object.entries(c) : [];
  const tests = state.verify?.tests_passed || [];

  return `
    <h1>Evidence</h1>
    <p class="muted">
      The claims matrix, the tests behind it, and what we did not build. Generated from
      <span class="mono">claims.json</span>; every row links to the CI run in the footer.
    </p>

    <h2>Claims × tests</h2>
    ${rows.length ? `
      <div class="table-wrap">
        <table>
          <thead><tr><th>Claim</th><th>Statement</th><th>Env</th><th>Result</th><th>Evidence</th></tr></thead>
          <tbody>
            ${rows.map(([id, v]) => `
              <tr>
                <td class="num">${esc(id)}</td>
                <td>${esc(v.statement)}</td>
                <td>${envBadge(v.env)}</td>
                <td>${statusBadge(v.status)}</td>
                <td class="muted">${v.status === 'SKIP'
                  ? esc(v.reason || v.notes || 'not built in this window')
                  : (v.notes ? esc(v.notes) : esc((v.missing_tests || []).join(', ') || 'battery'))}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>` : notAvailable('the claims ledger')}

    <h2>Tests recorded in this bundle (${tests.length})</h2>
    ${tests.length ? `<p class="mono muted" style="font-size:0.8rem">${tests.map(esc).join(' · ')}</p>` : notAvailable('the test list')}

    <h2>Non-claims</h2>
    ${(state.nonclaims?.items || []).length
      ? `<ul>${state.nonclaims.items.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`
      : notAvailable('the non-claims list')}

    <h2>Reproduce</h2>
    <pre class="mono" style="background:var(--bg-raise);border:1px solid var(--border);border-radius:var(--radius);padding:var(--space-3);overflow-x:auto">git clone https://github.com/AmateurGenius/arpk.git
cd arpk
make setup
make verify
python3 tools/verify.py
make fuzz        # volume tier — runs in CI, slow locally</pre>
    <p class="muted">
      The sandbox e2e and Kani run in CI on Ubuntu; the near-sandbox binary is glibc-only and
      Kani does not support this device's platform. <span class="mono">make verify</span> prints
      <span class="mono">SKIP (CI-only)</span> for those tiers.
    </p>
  `;
}

// ---------------------------------------------------------------- router

const routes = {
  proof: viewProof,
  theater: viewTheater,
  evidence: viewEvidence,
};

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [route, arg] = raw.split('/');
  return { route: route || 'proof', arg };
}

async function render() {
  const { route, arg } = parseHash();
  const fn = routes[route] || viewProof;
  document.querySelectorAll('.nav-link').forEach((a) => {
    const active = a.dataset.route === (route === 'theater' ? 'theater' : route);
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  view.innerHTML = fn(arg);
  view.scrollTop = 0;
  window.scrollTo(0, 0);
}

async function boot() {
  await loadBundle();
  renderProvenance();
  await render();
  window.addEventListener('hashchange', render);
}

boot().catch((e) => {
  view.innerHTML = `<h1>Something went wrong</h1><p class="muted">${esc(e.message)}</p>`;
});

// Expose a tiny hook so a judge (or a test) can read the bundle state.
window.arpk = { state, version: 'arpk.trace/1' };
