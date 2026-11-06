//! `arpk-core` — the ARPK executable specification.
//!
//! Pure Rust, no `near-sdk` dependency, so the exact same code compiles into the kernel
//! (native) and the vault contract (wasm). The differential test compares the two.
//!
//! Modules:
//! - [`codes`] — the exact reason strings every denial must use
//! - [`bucket`] — the token bucket that makes the bound hold
//! - [`caps`] — per-call / %-of-balance / bucket caps with checked arithmetic
//! - [`eip712`] — receipt and action hashing, generic over [`Keccak`]

pub mod bucket;
pub mod caps;
pub mod codes;
pub mod eip712;

pub use bucket::Bucket;
pub use caps::ValueCaps;
pub use codes::Code;
pub use eip712::{Domain, Receipt, ValueAction};

/// Keccak-256, abstracted so the kernel and the contract can share one hashing code path.
pub trait Keccak {
    fn keccak256(&self, data: &[u8]) -> [u8; 32];
}

/// Receipt classes.
pub mod class {
    pub const VALUE: u8 = 1;
}

/// Receipt verdicts.
pub mod verdict {
    pub const ALLOW: u8 = 1;
}
