import json

d = json.load(open('/data/data/com.termux/files/home/tmp/vectors.json'))

def arr32(h):
    b = bytes.fromhex(h)
    return '[' + ', '.join(str(x) for x in b) + ']'

def arr16(h):
    b = bytes.fromhex(h)
    return '[' + ', '.join(str(x) for x in b) + ']'

rows = []
for i, v in enumerate(d):
    r = v['receipt']
    rows.append(f'''    Vector {{
        salt: {arr32(v['domain']['salt'])},
        agent_id: {arr32(r['agentId'])},
        session_id: {arr16(r['sessionId'])},
        class: {r['class']},
        action_hash: {arr32(r['actionHash'])},
        manifest_hash: {arr32(r['manifestHash'])},
        context_hash: {arr32(r['contextHash'])},
        verdict: {r['verdict']},
        nonce: {arr16(r['nonce'])},
        issued_ms: {r['issuedMs']},
        expiry_ms: {r['expiryMs']},
        expected: {arr32(v['digest'])},
    }},''')

body = '\n'.join(rows)

rust = f'''//! Golden vectors for the EIP-712 receipt digest.
//!
//! The expected digests were produced by an **independent** implementation
//! (`tmp/gen_vectors.js`, using `@noble/hashes` `keccak_256`), not by the Rust code
//! under test. Agreement is therefore real evidence, not a tautology.

use arpk_core::eip712::{{digest, Domain, Receipt}};
use arpk_core::Keccak;
use sha3::{{Digest, Keccak256}};

struct Sha3Keccak;

impl Keccak for Sha3Keccak {{
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {{
        let mut h = Keccak256::new();
        h.update(data);
        h.finalize().into()
    }}
}}

struct Vector {{
    salt: [u8; 32],
    agent_id: [u8; 32],
    session_id: [u8; 16],
    class: u8,
    action_hash: [u8; 32],
    manifest_hash: [u8; 32],
    context_hash: [u8; 32],
    verdict: u8,
    nonce: [u8; 16],
    issued_ms: u64,
    expiry_ms: u64,
    expected: [u8; 32],
}}

const VECTORS: &[Vector] = &[
{body}
];

#[test]
fn golden_vectors_match_independent_implementation() {{
    let k = Sha3Keccak;
    let domain = Domain {{ name: "ARPK".to_string(), version: "1".to_string(), salt: [0u8; 32] }};
    for (i, v) in VECTORS.iter().enumerate() {{
        let mut domain = domain.clone();
        domain.salt = v.salt;
        let receipt = Receipt {{
            agent_id: v.agent_id,
            session_id: v.session_id,
            class: v.class,
            action_hash: v.action_hash,
            manifest_hash: v.manifest_hash,
            context_hash: v.context_hash,
            verdict: v.verdict,
            nonce: v.nonce,
            issued_ms: v.issued_ms,
            expiry_ms: v.expiry_ms,
        }};
        let got = digest(&k, &domain, &receipt);
        assert_eq!(got, v.expected, "vector {{i}} digest mismatch");
    }}
}}

#[test]
fn domain_separator_depends_on_salt() {{
    let k = Sha3Keccak;
    let mut a = Domain {{ name: "ARPK".to_string(), version: "1".to_string(), salt: [0u8; 32] }};
    let mut b = a.clone();
    b.salt = [1u8; 32];
    let r = Receipt {{
        agent_id: [0u8; 32],
        session_id: [0u8; 16],
        class: 1,
        action_hash: [0u8; 32],
        manifest_hash: [0u8; 32],
        context_hash: [0u8; 32],
        verdict: 1,
        nonce: [0u8; 16],
        issued_ms: 1,
        expiry_ms: 2,
    }};
    assert_ne!(digest(&k, &a, &r), digest(&k, &b, &r));
}}
'''

open('/data/data/com.termux/files/home/arpk/crates/arpk-core/tests/golden_vectors.rs', 'w').write(rust)
print('wrote', len(rust), 'bytes,', len(d), 'vectors')
