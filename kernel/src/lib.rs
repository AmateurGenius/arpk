//! ARPK kernel library — the policy decision point, the receipt signer and the monitors.
//!
//! This crate is the single enforcement path. The `arpkd` binary is a thin CLI over it,
//! and the sandbox e2e tests link it directly so the receipt they submit is the one the
//! kernel actually produces.
//!
//! Modules:
//! - [`pdp`]       — the Cedar policy decision point (`ARPK:policy.eval_error` on any error)
//! - [`receipt`]   — EIP-712 digest and k256 signing (`sign_value` is the only entry point)
//! - [`enforce`]   — PDP + monitors, shared by the CLI and `serve`
//! - [`monitors`]  — lease, venue, approval and the kernel-side spend ledger
//! - [`manifest`]  — canonicalization and the on-chain manifest hash
//! - [`rpc`]       — the NEAR view-call client used by the lease monitor
//! - [`serve`]     — JSON lines over a unix socket

pub mod enforce;
pub mod intent;
pub mod manifest;
pub mod monitors;
pub mod pdp;
pub mod receipt;
pub mod rpc;
pub mod serve;
pub mod trace;
