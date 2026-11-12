//! The kernel's enforcement path, shared by the CLI and `serve`.
//!
//! Cedar PDP first, then the lease/venue/approval monitors. Every denial is an exact
//! `ARPK:*` code. Both entry points must sign exactly the same set of intents, so the
//! logic lives here once.

use arpk_core::codes::Code;
use arpk_core::eip712::{hash_value_action, ValueAction};

use crate::{monitors, pdp, receipt};

/// Everything the kernel needs to authorize one value transfer.
pub struct SignIntent {
    pub agent_id: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub manifest_hash: [u8; 32],
    pub context_hash: [u8; 32],
    pub action: receipt::ActionInput,
    pub authority: String,
    pub agent_tier: String,
    pub venue_paused: bool,
    pub stale: bool,
    pub ttl_ms: u64,
    pub issued_ms: u64,
    pub agent_expiry_ms: u64,
    pub exposure: u128,
    pub exposure_cap: u128,
    pub approval_threshold: u128,
    /// The manifest's per-asset degraded cap. A degraded session may not exceed it.
    pub degraded_cap: u128,
    pub approval_expiry_ms: Option<u64>,
}

/// Evaluates the policy and the monitors. `Ok(())` means the kernel will sign.
pub fn enforce(pdp: &pdp::Pdp, intent: &SignIntent) -> Result<(), Code> {
    let entities = pdp::entities(
        &hex(&intent.agent_id),
        &intent.action.venue,
        intent.venue_paused,
        true,
        &intent.agent_tier,
    );
    // The Authority Ledger bounds a degraded session by the manifest's degraded_cap. This
    // runs *before* the PDP so the denial names the cause exactly, rather than surfacing as
    // a generic "not permitted".
    if intent.authority == "degraded" && intent.action.amount > intent.degraded_cap {
        return Err(Code::AuthorityDegradedCap);
    }

    // Cedar's `Long` is i64; larger amounts are saturated for the policy check only. The
    // contract's caps remain the bound on the real value.
    let cedar_amount = i64::try_from(intent.action.amount).unwrap_or(i64::MAX);
    let cedar_degraded = i64::try_from(intent.degraded_cap).unwrap_or(i64::MAX);
    let request = pdp::request(
        &hex(&intent.agent_id),
        &intent.action.venue,
        &intent.authority,
        intent.stale,
        Some(cedar_amount),
        Some(cedar_degraded),
        Some(pdp.schema()),
    );
    if let pdp::Verdict::Deny(code) = pdp.evaluate(&request, &entities) {
        return Err(code);
    }

    monitors::check_lease(intent.agent_expiry_ms, intent.issued_ms)?;
    monitors::check_venue(
        intent.venue_paused,
        intent.exposure,
        intent.action.amount,
        intent.exposure_cap,
    )?;
    let action_hash = hash_value_action(
        &receipt::Sha3,
        &ValueAction {
            chain: intent.action.chain.clone(),
            venue: intent.action.venue.clone(),
            to: intent.action.to.clone(),
            asset: intent.action.asset.clone(),
            amount: intent.action.amount,
            memo_hash: intent.action.memo_hash,
        },
    );
    let approval = intent
        .approval_expiry_ms
        .map(|expiry_ms| monitors::ApprovalSnapshot {
            action_hash,
            expiry_ms,
            consumed: false,
        });
    monitors::check_approval(
        intent.action.amount >= intent.approval_threshold,
        approval,
        action_hash,
        intent.issued_ms,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
