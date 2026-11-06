//! Property tests for the bound (claim C0).
//!
//! The property is the same in both modes: whether the kernel is honest or signs
//! everything an attacker asks for, total outflow over any interval is bounded by
//! `capacity + refill_per_s * dt`. The contract is the enforcer; the kernel's honesty
//! is irrelevant to the bound, which is the point.

use arpk_core::bucket::Bucket;
use proptest::prelude::*;

/// A sequence of (amount, elapsed_ns) operations.
fn ops() -> impl Strategy<Value = Vec<(u128, u64)>> {
    prop::collection::vec((1u128..5_000u128, 1u64..1_000_000_000u64), 1..64)
}

proptest! {
    /// Total outflow never exceeds capacity + refill * dt.
    #[test]
    fn bound_holds_for_any_operation_sequence(
        capacity in 1u128..100_000u128,
        refill_per_s in 0u128..1_000u128,
        sequence in ops(),
    ) {
        let mut bucket = Bucket::new(capacity, refill_per_s);
        let mut now_ns: u64 = 0;
        let mut total_out: u128 = 0;
        let mut t_start: u64 = 0;

        for (i, (amount, dt)) in sequence.iter().enumerate() {
            now_ns += dt;
            if i == 0 {
                t_start = now_ns;
            }
            if bucket.try_take(*amount, now_ns).is_ok() {
                total_out += *amount;
            }
            // Invariant: tokens never exceed capacity.
            prop_assert!(bucket.tokens <= capacity);
        }

        let elapsed_s = (now_ns - t_start) as u128;
        let bound = capacity + refill_per_s * elapsed_s;
        prop_assert!(
            total_out <= bound,
            "out={} bound={} capacity={} refill={} elapsed_s={}",
            total_out, bound, capacity, refill_per_s, elapsed_s
        );
    }

    /// Saturation can only raise tokens to capacity, never past it.
    #[test]
    fn saturation_never_exceeds_capacity(
        capacity in 1u128..100_000u128,
        refill_per_s in 0u128..1_000_000u128,
        wait_s in 0u64..10_000u64,
    ) {
        let mut bucket = Bucket::new(capacity, refill_per_s);
        // Empty it first.
        prop_assert!(bucket.try_take(capacity, 1_000_000_000).is_ok());
        prop_assert_eq!(bucket.tokens, 0);

        // Wait `wait_s` seconds; refill is exactly refill_per_s * wait_s, floored.
        bucket
            .refill(1_000_000_000 + wait_s as u64 * 1_000_000_000)
            .unwrap();
        let expected = (refill_per_s * wait_s as u128).min(capacity);
        prop_assert_eq!(bucket.tokens, expected);
        prop_assert!(bucket.tokens <= capacity);
    }

    /// A rejected take must not consume tokens.
    #[test]
    fn rejected_take_consumes_nothing(
        capacity in 1u128..100_000u128,
        amount in 1u128..100_000u128,
    ) {
        let mut bucket = Bucket::new(capacity, 0);
        let before = bucket.tokens;
        if amount > capacity {
            prop_assert!(bucket.try_take(amount, 1_000_000_000).is_err());
            prop_assert_eq!(bucket.tokens, before);
        }
    }

    /// Time regression is always rejected.
    #[test]
    fn time_regression_is_rejected(capacity in 1u128..100_000u128) {
        let mut bucket = Bucket::new(capacity, 1);
        bucket.try_take(1, 10_000_000_000).unwrap();
        prop_assert!(bucket.try_take(1, 9_999_999_999).is_err());
    }
}
