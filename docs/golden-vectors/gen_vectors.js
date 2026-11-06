// Independent EIP-712 reference implementation for ARPK golden vectors.
// Uses @noble/hashes keccak_256 -- a completely separate implementation from the Rust
// code under test, so agreement is real evidence and not a tautology.
const { keccak_256 } = require('/data/data/com.termux/files/home/node_modules/@noble/hashes/sha3.js');

const RECEIPT_TYPE = 'Receipt(bytes32 agentId,bytes16 sessionId,uint8 class,bytes32 actionHash,bytes32 manifestHash,bytes32 contextHash,uint8 verdict,bytes16 nonce,uint64 issuedMs,uint64 expiryMs)';
const DOMAIN_TYPE = 'EIP712Domain(string name,string version,bytes32 salt)';

const enc = (bytes) => Buffer.from(bytes);
const hex = (b) => Buffer.from(b).toString('hex');
const bytes32 = (h) => Uint8Array.from(Buffer.from(h, 'hex').subarray(0, 32));
const bytes16 = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const pad16 = (b) => { const o = new Uint8Array(32); o.set(b, 0); return o; };
const uint256 = (v) => { const o = new Uint8Array(32); const s = BigInt(v).toString(16).padStart(64, '0'); o.set(Buffer.from(s, 'hex'), 0); return o; };
const k = (b) => keccak_256(b);

function domainSeparator(name, version, saltHex) {
  const buf = Buffer.concat([
    k(Buffer.from(DOMAIN_TYPE)),
    k(Buffer.from(name)),
    k(Buffer.from(version)),
    bytes32(saltHex),
  ]);
  return k(buf);
}

function hashReceipt(r) {
  const buf = Buffer.concat([
    k(Buffer.from(RECEIPT_TYPE)),
    bytes32(r.agentId),
    pad16(bytes16(r.sessionId)),
    uint256(r.class),
    bytes32(r.actionHash),
    bytes32(r.manifestHash),
    bytes32(r.contextHash),
    uint256(r.verdict),
    pad16(bytes16(r.nonce)),
    uint256(r.issuedMs),
    uint256(r.expiryMs),
  ]);
  return k(buf);
}

function digest(domain, r) {
  const buf = Buffer.concat([
    Buffer.from([0x19, 0x01]),
    domainSeparator(domain.name, domain.version, domain.salt),
    hashReceipt(r),
  ]);
  return k(buf);
}

// Deterministic pseudo-random byte generation so vectors are reproducible without a RNG.
function detBytes(seed, n) {
  const out = new Uint8Array(n);
  let h = k(Buffer.from('arpk-golden-seed:' + seed));
  for (let i = 0; i < n; i++) {
    if (i % 32 === 0 && i > 0) h = k(h);
    out[i] = h[i % 32];
  }
  return hex(out);
}

const vectors = [];
for (let i = 0; i < 5; i++) {
  const domain = {
    name: 'ARPK',
    version: '1',
    salt: detBytes('salt' + i, 32),
  };
  const r = {
    agentId: detBytes('agent' + i, 32),
    sessionId: detBytes('session' + i, 16),
    class: 1,
    actionHash: detBytes('action' + i, 32),
    manifestHash: detBytes('manifest' + i, 32),
    contextHash: detBytes('context' + i, 32),
    verdict: 1,
    nonce: detBytes('nonce' + i, 16),
    issuedMs: 1762400000000 + i * 1000,
    expiryMs: 1762400120000 + i * 1000,
  };
  vectors.push({ domain, receipt: r, digest: hex(digest(domain, r)) });
}

console.log(JSON.stringify(vectors, null, 2));
