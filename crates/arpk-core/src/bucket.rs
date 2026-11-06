//! Token bucket. The core of claim C0.
//!
//! Invariant: `tokens <= capacity` always. Refill is floored (integer division), so it
//! can never over-refill. Therefore total outflow over any interval of length Δ is
//! bounded by `capacity + refill_per_s * Δ` -- regardless of who is calling.

use crate::codes::Code;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub capacity: u128,
    pub refill_per_s: u128,
    pub tokens: u128,
    pub t_last_ns: u64,
}

impl Bucket {
    pub fn new(capacity: u128, refill_per_s: u128) -> Self {
        Self {
            capacity,
            refill_per_s,
            tokens: capacity,
            t_last_ns: 0,
        }
    }

    /// Saturating refill up to `now_ns`. Rejects time regression.
    pub fn refill(&mut self, now_ns: u64) -> Result<(), Code> {
        if now_ns < self.t_last_ns {
            return Err(Code::TimeRegression);
        }
        let dt = now_ns - self.t_last_ns;
        // dt * refill_per_s cannot overflow u128 for realistic values, but be explicit.
        let refill = (dt as u128).saturating_mul(self.refill_per_s) / 1_000_000_000;
        self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
        self.t_last_ns = now_ns;
        Ok(())
    }

    /// Try to take `amount` tokens at `now_ns`.
    pub fn try_take(&mut self, amount: u128, now_ns: u64) -> Result<(), Code> {
        self.refill(now_ns)?;
        if amount > self.tokens {
            return Err(Code::ValueBucketExceeded);
        }
        self.tokens -= amount;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_never_exceeded() {
        let mut b = Bucket::new(100, 10);
        assert_eq!(b.tokens, 100);
        // burst the whole bucket
        b.try_take(100, 1_000_000_000).unwrap();
        assert_eq!(b.tokens, 0);
        // refill is floored: 1s at 10/s -> exactly 10
        b.try_take(10, 2_000_000_000).unwrap();
        assert_eq!(b.tokens, 0);
        // a further 1s refills 10 more
        assert_eq!(
            b.try_take(11, 3_000_000_000),
            Err(Code::ValueBucketExceeded)
        );
        assert_eq!(b.tokens, 10);
    }

    #[test]
    fn time_regression_is_rejected() {
        let mut b = Bucket::new(10, 1);
        b.try_take(1, 5_000_000_000).unwrap();
        assert_eq!(b.try_take(1, 4_000_000_000), Err(Code::TimeRegression));
    }

    #[test]
    fn saturation_only_raises_to_capacity() {
        let mut b = Bucket::new(100, 1_000_000_000);
        b.try_take(100, 1_000_000_000).unwrap();
        // 100 seconds of refill at 1e9/s would be 1e11 tokens; must clamp to 100
        b.refill(101_000_000_000).unwrap();
        assert_eq!(b.tokens, 100);
    }
}
