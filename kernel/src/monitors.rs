//! The four kernel monitors: spend, lease, venue, approval.
//!
//! Each denial returns an exact `ARPK:*` code. The monitors are pure functions over
//! snapshots the kernel reads from the chain, so they are fully testable without RPC.

use arpk_core::codes::Code;

/// An on-chain approval, as read by the approval monitor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalSnapshot {
    pub action_hash: [u8; 32],
    pub expiry_ms: u64,
    pub consumed: bool,
}

/// A kernel-side reservation of value against an outstanding receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub nonce: [u8; 16],
    pub amount: u128,
    pub expiry_ms: u64,
}

/// Tracks outstanding reservations so a receipt cannot be spent twice off-chain.
/// A reservation is released when its receipt expires without being submitted.
#[derive(Clone, Debug, Default)]
pub struct SpendLedger {
    reservations: Vec<Reservation>,
}

impl SpendLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves `amount` against `nonce` until `expiry_ms`.
    pub fn reserve(
        &mut self,
        nonce: [u8; 16],
        amount: u128,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<(), Code> {
        if expiry_ms <= now_ms {
            return Err(Code::ReceiptExpired);
        }
        if self.reservations.iter().any(|r| r.nonce == nonce) {
            return Err(Code::ReceiptReplayed);
        }
        self.reservations.push(Reservation {
            nonce,
            amount,
            expiry_ms,
        });
        Ok(())
    }

    /// Releases reservations that expired at or before `now_ms`. Returns how many.
    pub fn release_expired(&mut self, now_ms: u64) -> usize {
        let before = self.reservations.len();
        self.reservations.retain(|r| r.expiry_ms > now_ms);
        before - self.reservations.len()
    }

    /// Total value currently reserved.
    pub fn outstanding(&self) -> u128 {
        self.reservations
            .iter()
            .fold(0u128, |acc, r| acc.saturating_add(r.amount))
    }

    pub fn len(&self) -> usize {
        self.reservations.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.reservations.is_empty()
    }
}

/// Lease monitor: the agent record must not have expired as of the last poll.
pub fn check_lease(agent_expiry_ms: u64, now_ms: u64) -> Result<(), Code> {
    if agent_expiry_ms < now_ms {
        return Err(Code::LeaseStale);
    }
    Ok(())
}

/// Venue monitor: the venue is not paused, and the exposure cap holds after this amount.
pub fn check_venue(
    paused: bool,
    exposure: u128,
    amount: u128,
    exposure_cap: u128,
) -> Result<(), Code> {
    if paused {
        return Err(Code::VenuePaused);
    }
    if exposure.saturating_add(amount) > exposure_cap {
        return Err(Code::VenueExposureCap);
    }
    Ok(())
}

/// Approval monitor: amounts at or above the threshold need an unexpired, unconsumed
/// approval bound to this exact action hash.
pub fn check_approval(
    required: bool,
    approval: Option<ApprovalSnapshot>,
    action_hash: [u8; 32],
    now_ms: u64,
) -> Result<(), Code> {
    if !required {
        return Ok(());
    }
    match approval {
        Some(a) if a.action_hash == action_hash && !a.consumed && a.expiry_ms >= now_ms => Ok(()),
        _ => Err(Code::ValueApprovalRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_762_400_000_000;

    #[test]
    fn reserve_then_replay_is_rejected() {
        let mut ledger = SpendLedger::new();
        ledger.reserve([1u8; 16], 100, T0 + 60_000, T0).unwrap();
        assert_eq!(ledger.outstanding(), 100);
        assert_eq!(
            ledger.reserve([1u8; 16], 50, T0 + 60_000, T0),
            Err(Code::ReceiptReplayed)
        );
    }

    #[test]
    fn reserve_with_an_expired_window_is_rejected() {
        let mut ledger = SpendLedger::new();
        assert_eq!(
            ledger.reserve([1u8; 16], 100, T0, T0),
            Err(Code::ReceiptExpired)
        );
        assert_eq!(
            ledger.reserve([1u8; 16], 100, T0 - 1, T0),
            Err(Code::ReceiptExpired)
        );
    }

    #[test]
    fn expired_reservations_are_released() {
        let mut ledger = SpendLedger::new();
        ledger.reserve([1u8; 16], 100, T0 + 60_000, T0).unwrap();
        ledger.reserve([2u8; 16], 200, T0 + 120_000, T0).unwrap();
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.release_expired(T0 + 60_000), 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.outstanding(), 200);
        assert_eq!(ledger.release_expired(T0 + 120_000), 1);
        assert!(ledger.is_empty());
    }

    #[test]
    fn lease_goes_stale_after_expiry() {
        assert_eq!(check_lease(T0 + 1, T0), Ok(()));
        assert_eq!(check_lease(T0, T0), Ok(()), "expiry at now is still valid");
        assert_eq!(check_lease(T0 - 1, T0), Err(Code::LeaseStale));
    }

    #[test]
    fn paused_venue_and_exposure_cap_are_enforced() {
        assert_eq!(check_venue(true, 0, 1, 100), Err(Code::VenuePaused));
        assert_eq!(check_venue(false, 99, 2, 100), Err(Code::VenueExposureCap));
        assert_eq!(check_venue(false, 99, 1, 100), Ok(()));
        assert_eq!(
            check_venue(false, 0, 100, 100),
            Ok(()),
            "at the cap is allowed"
        );
    }

    #[test]
    fn approval_is_required_only_above_the_threshold() {
        let hash = [7u8; 32];
        assert_eq!(check_approval(false, None, hash, T0), Ok(()));
        assert_eq!(
            check_approval(true, None, hash, T0),
            Err(Code::ValueApprovalRequired)
        );
    }

    #[test]
    fn approval_must_match_the_action_and_be_live_and_unconsumed() {
        let hash = [7u8; 32];
        let other = [8u8; 32];
        let live = ApprovalSnapshot {
            action_hash: hash,
            expiry_ms: T0 + 60_000,
            consumed: false,
        };
        assert_eq!(check_approval(true, Some(live), hash, T0), Ok(()));
        assert_eq!(
            check_approval(true, Some(live), other, T0),
            Err(Code::ValueApprovalRequired),
            "an approval for a different action must not be reusable"
        );
        assert_eq!(
            check_approval(
                true,
                Some(ApprovalSnapshot {
                    action_hash: hash,
                    expiry_ms: T0 - 1,
                    consumed: false
                }),
                hash,
                T0
            ),
            Err(Code::ValueApprovalRequired)
        );
        assert_eq!(
            check_approval(
                true,
                Some(ApprovalSnapshot {
                    action_hash: hash,
                    expiry_ms: T0 + 60_000,
                    consumed: true
                }),
                hash,
                T0
            ),
            Err(Code::ValueApprovalRequired)
        );
    }
}
