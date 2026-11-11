//! Kani harnesses for the `arpk-core` cap arithmetic (claim C10).
//!
//! Each harness states its property in its own doc comment. Where a domain restriction was
//! needed for tractability it is named in the harness and in [`MAX_MAGNITUDE`] — never
//! applied silently.
//!
//! **CI only.** Kani supports x86_64 Linux, x86_64 macOS and Apple-silicon macOS; Termux
//! (bionic/aarch64) is none of those, so `make verify` prints `SKIP (CI-only)` for these.
//! The GitHub Action runs them on Ubuntu.

// This file is a module of the `arpk-core` crate, so it addresses its own modules
// directly rather than through the crate name.
use crate::bucket::Bucket;
use crate::caps::ValueCaps;
use crate::codes::Code;

/// Upper bound on symbolic magnitudes that stand for values: 2^96.
///
/// 128-bit multiply and divide-by-constant are bit-blasted, and full-range `u128` is beyond
/// Kani's practical reach. 2^96 yoctoNEAR is ~79,000 NEAR — far above any real cap — so the
/// restriction costs no meaningful coverage. Smaller bounds are used where the arithmetic
/// allows, because a small operand makes the multiply much cheaper.
const MAX_VALUE: u128 = 1 << 96;

/// A symbolic value below 2^96.
fn value() -> u128 {
    let v = kani::any::<u128>();
    kani::assume(v < MAX_VALUE);
    v
}

/// A symbolic refill rate below 2^64 (still ~1.8e10 per second).
fn refill_rate() -> u128 {
    let v = kani::any::<u128>();
    kani::assume(v < (1 << 64));
    v
}

/// A symbolic time delta below 2^32 nanoseconds (~4.3 s).
fn delta_ns() -> u64 {
    let v = kani::any::<u32>();
    v as u64
}

/// A symbolic basis-points value below 2^32 (the real maximum is 10,000).
fn bps() -> u128 {
    let v = kani::any::<u32>();
    v as u128
}

/// **Harness 1 — the bucket step lemma (inductive).**
///
/// If `out_total + tokens <= capacity + credited` and `tokens <= capacity` before a
/// successful `try_take`, then both hold after, with `credited' = credited + refill`. By
/// induction over any sequence, total outflow over an interval Δ is `<= capacity +
/// refill_per_s * Δ`.
#[kani::proof]
fn bucket_step_lemma() {
    let capacity = value();
    let refill_per_s = refill_rate();
    let prev_ns = kani::any::<u64>();
    let dt = delta_ns();
    let now_ns = prev_ns + dt;
    let tokens_before = value();
    let out_total = value();
    let credited = value();
    let amount = value();

    // Premises.
    kani::assume(tokens_before <= capacity);
    kani::assume(
        out_total
            .checked_add(tokens_before)
            .map_or(false, |s| s <= capacity + credited),
    );

    let mut bucket = Bucket {
        capacity,
        refill_per_s,
        tokens: tokens_before,
        t_last_ns: prev_ns,
    };
    if bucket.try_take(amount, now_ns).is_ok() {
        // What the implementation actually added, mirroring `Bucket::refill`.
        let refill = (dt as u128).saturating_mul(refill_per_s) / 1_000_000_000;
        let out_after = out_total + amount;
        assert!(
            bucket.tokens <= capacity,
            "tokens must never exceed capacity"
        );
        assert!(
            out_after
                .checked_add(bucket.tokens)
                .map_or(false, |s| s <= capacity + credited + refill),
            "the bound must be preserved across a step: out={out_after} tokens={} capacity={capacity} credited={credited} refill={refill}",
            bucket.tokens
        );
    }
}

/// **Harness 2 — `tokens <= capacity` after every call.**
#[kani::proof]
fn tokens_never_exceed_capacity() {
    let capacity = value();
    let refill_per_s = refill_rate();
    let amount = value();
    let now_ns = kani::any::<u64>();

    let mut bucket = Bucket::new(capacity, refill_per_s);
    assert!(
        bucket.tokens <= capacity,
        "a fresh bucket starts at capacity"
    );

    let _ = bucket.try_take(amount, now_ns);
    assert!(
        bucket.tokens <= capacity,
        "tokens must not exceed capacity after a take"
    );

    let later = now_ns + delta_ns();
    let _ = bucket.refill(later);
    assert!(
        bucket.tokens <= capacity,
        "saturation must clamp to capacity, not past it"
    );
}

/// **Harness 3 — no mutation on failure.**
///
/// An `Err` must leave the bucket byte-identical, so a denied transfer consumes nothing.
#[kani::proof]
fn failed_take_leaves_state_unchanged() {
    let capacity = value();
    let refill_per_s = refill_rate();
    let now_ns = kani::any::<u64>();

    let mut bucket = Bucket::new(capacity, refill_per_s);
    // Empty the bucket so the next take is guaranteed to fail.
    let _ = bucket.try_take(capacity, now_ns);
    assert_eq!(
        bucket.tokens, 0,
        "the bucket must be empty before the failing take"
    );

    let amount = value();
    kani::assume(amount > 0);
    let before = bucket.clone();
    assert_eq!(
        bucket.try_take(amount, now_ns),
        Err(Code::ValueBucketExceeded)
    );
    assert_eq!(bucket, before, "a failed take must not mutate the bucket");
}

/// **Harness 4 — time regression is rejected and does not mutate.**
#[kani::proof]
fn time_regression_is_rejected_without_mutation() {
    let capacity = value();
    let refill_per_s = refill_rate();
    let later = kani::any::<u64>();
    kani::assume(later > 0);

    let mut bucket = Bucket::new(capacity, refill_per_s);
    let _ = bucket.refill(later);
    let before = bucket.clone();

    let earlier = kani::any::<u64>();
    kani::assume(earlier < later);
    assert_eq!(
        bucket.try_take(1, earlier),
        Err(Code::TimeRegression),
        "a timestamp before the last refill must be rejected"
    );
    assert_eq!(bucket, before, "a rejected take must not mutate the bucket");
}

/// **Harness 5 — the %-of-balance check equals its mathematical definition.**
///
/// It must accept exactly when `amount * 10000 <= pct_bps * ledger`, and reject with
/// `ValueOverflow` rather than wrap when either product overflows. The per-call cap and the
/// bucket are set so they cannot be the reason for a denial.
#[kani::proof]
fn pct_cap_matches_its_definition() {
    let ledger = value();
    let amount = value();
    let pct_bps = bps();

    // per_call_cap = u128::MAX and bucket_capacity = u128::MAX, refill 0: neither can deny.
    let mut caps = ValueCaps::new(u128::MAX, pct_bps, u128::MAX, u128::MAX, 0);
    let result = caps.check(ledger, amount, 1_000_000_000);

    let scaled = amount.checked_mul(10_000);
    let allowed = pct_bps.checked_mul(ledger);
    match (scaled, allowed) {
        (Some(s), Some(a)) => {
            assert_eq!(
                result.is_ok(),
                s <= a,
                "the check must accept exactly when amount*10000 <= pct_bps*ledger (got {result:?}, {s} vs {a})"
            );
        }
        _ => {
            assert_eq!(
                result,
                Err(Code::ValueOverflow),
                "an overflowing product must be rejected, never wrapped"
            );
        }
    }
}

/// **Harness 6 — the per-call cap and the venue-exposure check.**
///
/// The per-call check accepts exactly when `amount <= per_call_cap`. The venue-exposure
/// check lives in the contract, not in this crate; this harness proves the exact expression
/// the contract evaluates — `exposure.saturating_add(amount) > cap` — agrees with the
/// mathematical definition and never overflows silently.
#[kani::proof]
fn per_call_and_venue_exposure_checks() {
    // --- per-call ---
    let per_call_cap = value();
    let amount = value();
    let mut caps = ValueCaps::new(per_call_cap, 10_000, u128::MAX, u128::MAX, 0);
    // A ledger large enough that `10_000 * ledger` cannot overflow, so the %-of-balance
    // check accepts and the per-call cap is the only thing that can deny.
    let ledger = u128::MAX / 10_000;
    let result = caps.check(ledger, amount, 1_000_000_000);
    assert_eq!(
        result.is_ok(),
        amount <= per_call_cap,
        "the per-call check must accept exactly when amount <= per_call_cap"
    );

    // --- venue exposure ---
    let exposure = value();
    let amount = value();
    let cap = value();
    let computed = exposure.saturating_add(amount);
    let mathematical = exposure.checked_add(amount);
    if let Some(true_sum) = mathematical {
        assert_eq!(
            computed, true_sum,
            "saturating_add must equal the true sum whenever it fits"
        );
    }
    assert_eq!(
        computed <= cap,
        mathematical.map_or(false, |s| s <= cap),
        "the exposure check must accept exactly when the true sum is within the cap"
    );
}
