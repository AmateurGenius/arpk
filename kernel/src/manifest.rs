//! Compact manifest and its hash.
//!
//! `manifest_hash = keccak256("ARPK-MANIFEST-v3" ‖ canonical_json(manifest))`.
//!
//! The contract stores the hash and never recomputes it, so the canonical form only has
//! to be self-consistent — but it is held to RFC 8785 (JCS) for the subset the manifest
//! uses: ASCII strings, integer numbers, arrays, and objects. Keys are sorted, there is
//! no whitespace, and integers are emitted exactly. The golden test pins a hash that was
//! reproduced by an independent implementation.

use std::collections::BTreeMap;

use arpk_core::Keccak;
use serde::{Deserialize, Serialize};

use crate::receipt::Sha3;

/// Domain separator for the manifest hash.
pub const MANIFEST_DOMAIN: &str = "ARPK-MANIFEST-v3";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub agent_id: String,
    pub owner: String,
    pub expiry_ms: u64,
    pub lease_ttl_s: u64,
    pub permitted_actions: Vec<PermittedAction>,
    pub value: ValueSection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermittedAction {
    pub tool: String,
    pub tier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueSection {
    pub assets: Vec<Asset>,
    pub destinations: Vec<String>,
    pub venues: Vec<Venue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    pub asset: String,
    pub per_call_cap: u128,
    pub bucket: BucketSpec,
    pub pct_of_balance_cap_bps: u128,
    pub approval_threshold: u128,
    pub degraded_cap: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketSpec {
    pub capacity: u128,
    pub refill_per_s: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Venue {
    pub id: String,
    pub exposure_cap: u128,
}

#[derive(Debug)]
pub enum ManifestError {
    Serialize(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Serialize(e) => write!(f, "ARPK:manifest.serialize ({e})"),
        }
    }
}

/// Canonical JSON for the manifest subset: object keys sorted, no whitespace, strings
/// minimally escaped, integers exact. See RFC 8785 §3.2 and §3.2.3.
pub fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Array(a) => {
            let items: Vec<String> = a.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(m) => {
            // BTreeMap iteration is key-sorted; serde_json's Map is already ordered, but
            // sort explicitly so the canonical form does not depend on the map backend.
            let sorted: BTreeMap<&String, &serde_json::Value> = m.iter().collect();
            let items: Vec<String> = sorted
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// The canonical JSON text of a manifest. Exposed so an independent implementation can
/// reproduce it; the hash is only as good as this string.
pub fn canonical_manifest_json(m: &Manifest) -> Result<String, ManifestError> {
    let value = serde_json::to_value(m).map_err(|e| ManifestError::Serialize(e.to_string()))?;
    Ok(canonical_json(&value))
}

/// The on-chain manifest hash: `keccak256("ARPK-MANIFEST-v3" ‖ canonical_json(manifest))`.
pub fn manifest_hash(m: &Manifest) -> Result<[u8; 32], ManifestError> {
    let canonical = canonical_manifest_json(m)?;
    let mut buf = Vec::with_capacity(MANIFEST_DOMAIN.len() + canonical.len());
    buf.extend_from_slice(MANIFEST_DOMAIN.as_bytes());
    buf.extend_from_slice(canonical.as_bytes());
    Ok(Sha3.keccak256(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Manifest {
        Manifest {
            agent_id: "aa".repeat(32),
            owner: "owner.test.near".to_string(),
            expiry_ms: 1_762_400_000_000,
            lease_ttl_s: 3_600,
            permitted_actions: vec![PermittedAction {
                tool: "transfer".to_string(),
                tier: "value".to_string(),
            }],
            value: ValueSection {
                assets: vec![Asset {
                    asset: "near".to_string(),
                    per_call_cap: 1_000,
                    bucket: BucketSpec {
                        capacity: 1_000,
                        refill_per_s: 10,
                    },
                    pct_of_balance_cap_bps: 10_000,
                    approval_threshold: 5_000,
                    degraded_cap: 0,
                }],
                destinations: vec!["dest.test.near".to_string()],
                venues: vec![Venue {
                    id: "venue-a".to_string(),
                    exposure_cap: 10_000,
                }],
            },
        }
    }

    #[test]
    fn canonical_form_sorts_keys_and_omits_whitespace() {
        let a = canonical_json(&json!({"b": 1, "a": 2}));
        assert_eq!(a, r#"{"a":2,"b":1}"#);
        let b = canonical_json(&json!({"a": 2, "b": 1}));
        assert_eq!(a, b, "key order must not affect the canonical form");
    }

    #[test]
    fn canonical_form_is_exact_for_integers_and_strings() {
        assert_eq!(
            canonical_json(&json!(1_000_000_000_000u128)),
            "1000000000000"
        );
        assert_eq!(canonical_json(&json!("a\"b")), r#""a\"b""#);
        assert_eq!(canonical_json(&json!([1, "x", true])), r#"[1,"x",true]"#);
    }

    #[test]
    fn manifest_hash_is_deterministic_and_value_sensitive() {
        let a = manifest_hash(&sample()).unwrap();
        let b = manifest_hash(&sample()).unwrap();
        assert_eq!(a, b, "the same manifest must hash identically");

        let mut changed = sample();
        changed.value.assets[0].per_call_cap = 1_001;
        assert_ne!(
            manifest_hash(&changed).unwrap(),
            a,
            "changing a cap must change the hash"
        );

        let mut reordered = sample();
        reordered.value.destinations.reverse();
        assert_eq!(
            manifest_hash(&reordered).unwrap(),
            a,
            "the manifest has one destination, so a no-op reorder must not change the hash"
        );
    }

    /// Pinned against an independent implementation: `docs/golden-vectors/manifest_canon.mjs`
    /// canonicalizes with plain JS and hashes with `@noble/hashes` keccak_256 — no Rust
    /// code shared with the kernel.
    #[test]
    fn manifest_hash_matches_the_independently_derived_golden_value() {
        let canonical = canonical_manifest_json(&sample()).unwrap();
        assert_eq!(
            canonical,
            r#"{"agent_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expiry_ms":1762400000000,"lease_ttl_s":3600,"owner":"owner.test.near","permitted_actions":[{"tier":"value","tool":"transfer"}],"value":{"assets":[{"approval_threshold":5000,"asset":"near","bucket":{"capacity":1000,"refill_per_s":10},"degraded_cap":0,"pct_of_balance_cap_bps":10000,"per_call_cap":1000}],"destinations":["dest.test.near"],"venues":[{"exposure_cap":10000,"id":"venue-a"}]}}"#
        );
        let h = manifest_hash(&sample()).unwrap();
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex, "42823b03c5367ee2e57c3c29bd894de223b21f23cbf72cc1740dd7870d31e620",
            "if this fails, the canonical form changed — re-derive and re-pin deliberately"
        );
    }
}
