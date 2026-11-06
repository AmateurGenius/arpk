//! EIP-712 hashing for ARPK receipts, generic over the Keccak implementation.
//!
//! The kernel implements [`Keccak`] with `sha3`; the contract implements it with
//! `near_sdk::env::keccak256`. Both sides must produce byte-identical digests, which
//! is what the golden vectors assert.
//!
//! Encoding follows EIP-712: `uintN` and `uint` are 32-byte big-endian; `bytesN` is
//! N bytes right-padded to 32; `string` is `keccak256(bytes)`.

use crate::Keccak;

pub const EIP712_DOMAIN_TYPE: &str = "EIP712Domain(string name,string version,bytes32 salt)";
pub const VALUE_ACTION_TYPE: &str =
    "ValueAction(string chain,string venue,string to,string asset,uint128 amount,bytes32 memoHash)";
pub const RECEIPT_TYPE: &str = "Receipt(bytes32 agentId,bytes16 sessionId,uint8 class,bytes32 actionHash,bytes32 manifestHash,bytes32 contextHash,uint8 verdict,bytes16 nonce,uint64 issuedMs,uint64 expiryMs)";

pub const CLASS_VALUE: u8 = 1;
pub const VERDICT_ALLOW: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub salt: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueAction {
    pub chain: String,
    pub venue: String,
    pub to: String,
    pub asset: String,
    pub amount: u128,
    pub memo_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub agent_id: [u8; 32],
    pub session_id: [u8; 16],
    pub class: u8,
    pub action_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub context_hash: [u8; 32],
    pub verdict: u8,
    pub nonce: [u8; 16],
    pub issued_ms: u64,
    pub expiry_ms: u64,
}

fn uint256(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&v.to_be_bytes());
    b
}

fn uint256_u64(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

fn pad16(v: &[u8; 16]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(v);
    b
}

fn hash_struct<K: Keccak>(k: &K, ty: &str, fields: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + fields.len() * 32);
    buf.extend_from_slice(&k.keccak256(ty.as_bytes()));
    for f in fields {
        buf.extend_from_slice(f);
    }
    k.keccak256(&buf)
}

pub fn domain_separator<K: Keccak>(k: &K, d: &Domain) -> [u8; 32] {
    hash_struct(
        k,
        EIP712_DOMAIN_TYPE,
        &[
            k.keccak256(d.name.as_bytes()),
            k.keccak256(d.version.as_bytes()),
            d.salt,
        ],
    )
}

pub fn hash_value_action<K: Keccak>(k: &K, a: &ValueAction) -> [u8; 32] {
    hash_struct(
        k,
        VALUE_ACTION_TYPE,
        &[
            k.keccak256(a.chain.as_bytes()),
            k.keccak256(a.venue.as_bytes()),
            k.keccak256(a.to.as_bytes()),
            k.keccak256(a.asset.as_bytes()),
            uint256(a.amount),
            a.memo_hash,
        ],
    )
}

pub fn hash_receipt<K: Keccak>(k: &K, r: &Receipt) -> [u8; 32] {
    hash_struct(
        k,
        RECEIPT_TYPE,
        &[
            r.agent_id,
            pad16(&r.session_id),
            uint256_u64(r.class as u64),
            r.action_hash,
            r.manifest_hash,
            r.context_hash,
            uint256_u64(r.verdict as u64),
            pad16(&r.nonce),
            uint256_u64(r.issued_ms),
            uint256_u64(r.expiry_ms),
        ],
    )
}

/// The final EIP-712 digest that the kernel signs and the contract recovers.
pub fn digest<K: Keccak>(k: &K, d: &Domain, r: &Receipt) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator(k, d));
    buf.extend_from_slice(&hash_receipt(k, r));
    k.keccak256(&buf)
}
