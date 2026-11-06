//! Value caps. Only this module decides whether a transfer is within the owner-chosen
//! bound. It is shared verbatim by the kernel (model) and the contract (enforcement),
//! which is what makes the differential test meaningful.

use crate::bucket::Bucket;
use crate::codes::Code;

pub const BPS_DENOMINATOR: u128 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueCaps {
    pub per_call_cap: u128,
    pub pct_of_balance_cap_bps: u128,
    pub approval_threshold: u128,
    pub bucket: Bucket,
}

impl ValueCaps {
    pub fn new(
        per_call_cap: u128,
        pct_of_balance_cap_bps: u128,
        approval_threshold: u128,
        bucket_capacity: u128,
        bucket_refill_per_s: u128,
    ) -> Self {
        Self {
            per_call_cap,
            pct_of_balance_cap_bps,
            approval_threshold,
            bucket: Bucket::new(bucket_capacity, bucket_refill_per_s),
        }
    }

    /// Apply per-call, %-of-balance and bucket caps in that order.
    ///
    /// The approval check is deliberately not here: it needs an on-chain approval record
    /// for the exact action hash, so the caller performs it separately.
    pub fn check(&mut self, ledger: u128, amount: u128, now_ns: u64) -> Result<(), Code> {
        if amount > self.per_call_cap {
            return Err(Code::ValuePerCallExceeded);
        }
        // amount * 10000 must not overflow; reject rather than wrap.
        let scaled = amount
            .checked_mul(BPS_DENOMINATOR)
            .ok_or(Code::ValueOverflow)?;
        let allowed = self
            .pct_of_balance_cap_bps
            .checked_mul(ledger)
            .ok_or(Code::ValueOverflow)?;
        if scaled > allowed {
            return Err(Code::ValuePctExceeded);
        }
        self.bucket.try_take(amount, now_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_call_cap_is_enforced() {
        let mut c = ValueCaps::new(100, 10_000, u128::MAX, 1_000, 1);
        assert_eq!(c.check(1_000, 100, 1_000_000_000), Ok(()));
        assert_eq!(
            c.check(1_000, 101, 1_000_000_000),
            Err(Code::ValuePerCallExceeded)
        );
    }

    #[test]
    fn pct_cap_is_enforced() {
        // 10% of a 1000 ledger is 100
        let mut c = ValueCaps::new(u128::MAX, 1_000, u128::MAX, 1_000_000, 1);
        assert_eq!(c.check(1_000, 100, 1_000_000_000), Ok(()));
        assert_eq!(
            c.check(1_000, 101, 1_000_000_000),
            Err(Code::ValuePctExceeded)
        );
    }

    #[test]
    fn overflow_is_rejected_not_wrapped() {
        let mut c = ValueCaps::new(u128::MAX, 10_000, u128::MAX, 1_000_000_000, 1);
        // u128::MAX * 10000 overflows
        assert_eq!(
            c.check(1_000, u128::MAX, 1_000_000_000),
            Err(Code::ValueOverflow)
        );
    }

    #[test]
    fn pct_overflow_is_rejected() {
        let mut c = ValueCaps::new(u128::MAX, u128::MAX, u128::MAX, 1_000_000_000, 1);
        assert_eq!(
            c.check(u128::MAX, 2, 1_000_000_000),
            Err(Code::ValueOverflow)
        );
    }
}
