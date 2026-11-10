//! Receipt construction and signing — the kernel's signing path.
//!
//! This is the exact mirror of the contract's verification: same EIP-712 types, same
//! digest, same k256 recoverable signature with `v ∈ {0,1}`. The golden vectors in
//! `docs/golden-vectors/` assert byte-identical digests between this module, the
//! contract, and an independent implementation — so the kernel and the contract
//! cannot drift apart.
//!
//! TEE modes: `ARPK_TEE=simulator` (the only mode in this build) keeps the kernel key
//! under `.local/`, which is gitignored — keys are never committed (AGENTS.md rule 3).

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use arpk_core::eip712::{self, Domain, Receipt as CoreReceipt, ValueAction};
use arpk_core::{class, verdict, Keccak, MAX_RECEIPT_TTL_MS};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// Keccak-256 backed by `sha3` — the kernel's hashing path. The contract uses
/// `env::keccak256`; both must agree, which the golden vectors assert.
pub struct Sha3;

impl Keccak for Sha3 {
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(data);
        h.finalize().into()
    }
}

/// The EIP-712 domain for a vault instance: `ARPK` / `1`, salted with the chain id and
/// the contract account id, so a receipt is bound to one chain and one vault.
pub fn domain(chain_id: &str, contract_id: &str) -> Domain {
    let mut buf = Vec::new();
    buf.extend_from_slice(chain_id.as_bytes());
    buf.extend_from_slice(contract_id.as_bytes());
    Domain {
        name: "ARPK".to_string(),
        version: "1".to_string(),
        salt: Sha3.keccak256(&buf),
    }
}

/// A value action, in the shape the contract recomputes the action hash from.
#[derive(Clone, Debug)]
pub struct ActionInput {
    pub chain: String,
    pub venue: String,
    pub to: String,
    pub asset: String,
    pub amount: u128,
    pub memo_hash: [u8; 32],
}

/// Everything the kernel needs to sign one value receipt.
pub struct ReceiptRequest {
    pub action: ActionInput,
    pub agent_id: [u8; 32],
    pub session_id: [u8; 16],
    pub manifest_hash: [u8; 32],
    pub context_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub issued_ms: u64,
    pub ttl_ms: u64,
}

/// A signed receipt, ready for the relayer to submit.
#[derive(Debug)]
pub struct SignedReceipt {
    pub receipt: CoreReceipt,
    pub action_hash: [u8; 32],
    /// 64 bytes: `r ‖ s`.
    pub signature: Vec<u8>,
    /// Recovery id, `0` or `1` — the `v` NEAR's `ecrecover` expects.
    pub v: u8,
}

/// Signing failures. Each maps to an exact `ARPK:*` code or a key/IO error.
#[derive(Debug)]
pub enum ReceiptError {
    /// The requested TTL exceeds the contract's ceiling; the contract would reject it.
    TtlTooLong { requested: u64, max: u64 },
    /// The issued timestamp plus the TTL overflowed.
    BadWindow { issued_ms: u64, expiry_ms: u64 },
    /// The signing key could not be used.
    Key(String),
    /// `.local/` could not be read or written.
    Io(String),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::TtlTooLong { requested, max } => write!(
                f,
                "ARPK:receipt.ttl_too_long (requested {requested} ms, max {max} ms)"
            ),
            ReceiptError::BadWindow {
                issued_ms,
                expiry_ms,
            } => write!(
                f,
                "ARPK:receipt.expired (issued {issued_ms} ms, expiry {expiry_ms} ms)"
            ),
            ReceiptError::Key(e) => write!(f, "ARPK:kernel.key ({e})"),
            ReceiptError::Io(e) => write!(f, "ARPK:kernel.io ({e})"),
        }
    }
}

/// Signs one value receipt. `expiry_ms` is `issued_ms + ttl_ms`, never more than
/// [`MAX_RECEIPT_TTL_MS`] later, so a kernel-signed receipt can never be rejected for
/// its TTL.
pub fn sign_value(
    key: &SigningKey,
    domain: &Domain,
    req: &ReceiptRequest,
) -> Result<SignedReceipt, ReceiptError> {
    if req.ttl_ms > MAX_RECEIPT_TTL_MS {
        return Err(ReceiptError::TtlTooLong {
            requested: req.ttl_ms,
            max: MAX_RECEIPT_TTL_MS,
        });
    }
    let expiry_ms = req
        .issued_ms
        .checked_add(req.ttl_ms)
        .ok_or(ReceiptError::BadWindow {
            issued_ms: req.issued_ms,
            expiry_ms: u64::MAX,
        })?;

    let action = ValueAction {
        chain: req.action.chain.clone(),
        venue: req.action.venue.clone(),
        to: req.action.to.clone(),
        asset: req.action.asset.clone(),
        amount: req.action.amount,
        memo_hash: req.action.memo_hash,
    };
    let action_hash = eip712::hash_value_action(&Sha3, &action);
    let receipt = CoreReceipt {
        agent_id: req.agent_id,
        session_id: req.session_id,
        class: class::VALUE,
        action_hash,
        manifest_hash: req.manifest_hash,
        context_hash: req.context_hash,
        verdict: verdict::ALLOW,
        nonce: req.nonce,
        issued_ms: req.issued_ms,
        expiry_ms,
    };

    let digest = eip712::digest(&Sha3, domain, &receipt);
    let (sig, recid) = key.sign_prehash_recoverable(&digest);
    Ok(SignedReceipt {
        receipt,
        action_hash,
        signature: sig.to_bytes().to_vec(),
        v: recid.to_byte(),
    })
}

/// The kernel key. In `simulator` mode it lives under `.local/` and is generated on
/// first use.
pub struct KernelKey {
    signing: SigningKey,
    /// 64 bytes, `X ‖ Y` — exactly what `ecrecover` returns, and therefore exactly what
    /// the contract stores as a kernel key.
    public: Vec<u8>,
}

impl KernelKey {
    /// Loads `.local/kernel.key`, generating it on first use.
    pub fn simulator() -> Result<Self, ReceiptError> {
        Self::simulator_in(".local")
    }

    fn simulator_in(dir: &str) -> Result<Self, ReceiptError> {
        let path = Path::new(dir).join("kernel.key");
        let bytes = if path.exists() {
            fs::read(&path).map_err(|e| ReceiptError::Io(e.to_string()))?
        } else {
            fs::create_dir_all(dir).map_err(|e| ReceiptError::Io(e.to_string()))?;
            // The dependency graph exposes no OS RNG, so read the CSPRNG directly.
            // Simulator mode only; the key never leaves `.local/` (gitignored).
            let mut raw = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .map_err(|e| ReceiptError::Io(e.to_string()))?;
            // Re-parse through the same path as a loaded key so both are validated.
            SigningKey::from_slice(&raw).map_err(|e| ReceiptError::Key(e.to_string()))?;
            fs::write(&path, &raw).map_err(|e| ReceiptError::Io(e.to_string()))?;
            raw.to_vec()
        };
        Self::from_bytes(&bytes)
    }

    /// Rebuilds the key and its 64-byte public form from 32 raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let signing =
            SigningKey::from_slice(bytes).map_err(|e| ReceiptError::Key(e.to_string()))?;
        let public = signing.verifying_key().to_sec1_point(false);
        Ok(Self {
            public: public.as_bytes()[1..].to_vec(),
            signing,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    fn hex16(s: &str) -> [u8; 16] {
        let v: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn req(issued_ms: u64, ttl_ms: u64) -> ReceiptRequest {
        ReceiptRequest {
            action: ActionInput {
                chain: "near".to_string(),
                venue: "venue-a".to_string(),
                to: "dest.test.near".to_string(),
                asset: "near".to_string(),
                amount: 100,
                memo_hash: [0u8; 32],
            },
            agent_id: Sha3.keccak256(b"agent-0"),
            session_id: [1u8; 16],
            manifest_hash: Sha3.keccak256(b"manifest-0"),
            context_hash: [0u8; 32],
            nonce: [2u8; 16],
            issued_ms,
            ttl_ms,
        }
    }

    /// The kernel's digest must equal the independent golden vector for the same input
    /// (vector 1 of `docs/golden-vectors/vectors.json`, produced by `@noble/hashes`).
    #[test]
    fn digest_matches_the_golden_vector() {
        let d = Domain {
            name: "ARPK".to_string(),
            version: "1".to_string(),
            salt: hex32("6130ef1f1ead8aa80013c333d7398bb3d3e472498b8822208fa6ba74b21ce166"),
        };
        let receipt = CoreReceipt {
            agent_id: hex32("eeba55baadfe798048bef836ec12e20dd6a8aa4b9f6572e740f30ae14e417f8e"),
            session_id: hex16("39a561f7d32ebdce72ded3ce2ce9d064"),
            class: 1,
            action_hash: hex32("a11df5161c46acf26b79e0251e916cccf29f354ab87adc1e2dc9945feecfe9b8"),
            manifest_hash: hex32(
                "1bd8767b931ea2b41873e65aa2e8650214ecf984b2651b6047c7ab857060d294",
            ),
            context_hash: hex32("6ed2201a8c73b191cae2934170e96fd3708772e28ec65b4b1a458948510a25a5"),
            verdict: 1,
            nonce: hex16("a84b78ac4d9de04a3de292bbb724574e"),
            issued_ms: 1_762_400_000_000,
            expiry_ms: 1_762_400_120_000,
        };
        let digest = eip712::digest(&Sha3, &d, &receipt);
        assert_eq!(
            hex(&digest),
            "5c40552d1c5caed0c16751443d8d6371e2b7b021c4522944363e5bcc5af9c065"
        );
    }

    /// A kernel-signed receipt recovers to the kernel's registered public key.
    #[test]
    fn signed_receipt_recovers_to_the_kernel_key() {
        let k = key();
        let d = domain("near", "vault.test.near");
        let signed = sign_value(&k, &d, &req(1_762_400_000_000, 60_000)).unwrap();

        let digest = eip712::digest(&Sha3, &d, &signed.receipt);
        let sig = Signature::from_slice(&signed.signature).unwrap();
        let recid = RecoveryId::from_byte(signed.v).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recid).unwrap();

        let expected = KernelKey::from_bytes(&[7u8; 32]).unwrap();
        assert_eq!(
            recovered.to_sec1_point(false).as_bytes()[1..].to_vec(),
            expected.public_key().to_vec(),
            "the receipt must recover to the registered kernel key"
        );
    }

    #[test]
    fn recovery_id_is_zero_or_one() {
        let k = key();
        let d = domain("near", "vault.test.near");
        for ttl in [1_u64, 30_000, 60_000, 119_999, 120_000] {
            let signed = sign_value(&k, &d, &req(1_762_400_000_000, ttl)).unwrap();
            assert!(signed.v == 0 || signed.v == 1, "v was {}", signed.v);
            assert_eq!(signed.signature.len(), 64, "sig64 r||s");
            assert_eq!(
                signed.receipt.expiry_ms,
                1_762_400_000_000 + ttl,
                "expiry is issued + ttl"
            );
        }
    }

    /// The kernel refuses to sign a receipt the contract would reject for its TTL.
    #[test]
    fn ttl_over_the_ceiling_is_rejected_with_the_exact_code() {
        let k = key();
        let d = domain("near", "vault.test.near");
        let err = sign_value(&k, &d, &req(1_762_400_000_000, MAX_RECEIPT_TTL_MS + 1)).unwrap_err();
        assert!(matches!(err, ReceiptError::TtlTooLong { .. }));
        assert_eq!(
            err.to_string(),
            "ARPK:receipt.ttl_too_long (requested 120001 ms, max 120000 ms)"
        );
    }

    #[test]
    fn simulator_key_is_stable_and_64_bytes() {
        let dir = "target/test-kernel-key";
        let _ = fs::remove_dir_all(dir);
        let a = KernelKey::simulator_in(dir).unwrap();
        let b = KernelKey::simulator_in(dir).unwrap();
        assert_eq!(
            a.public_key(),
            b.public_key(),
            "the simulator key must be stable across runs"
        );
        assert_eq!(
            a.public_key().len(),
            64,
            "ecrecover returns X||Y (64 bytes)"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
