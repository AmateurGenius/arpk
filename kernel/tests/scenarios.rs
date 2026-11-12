//! Scenario traces (`arpk.trace/1`) — reconstructions of real incidents.
//!
//! These are counterfactuals, not reproductions: the `simulated` array is mandatory and the
//! `counterfactual` flag is set. What makes them more than a story is that every denial is
//! produced by the *real* code path, not written by hand:
//!
//! - `bankr` runs `enforce` with a session the `AuthorityLedger` degraded on untrusted
//!   ingress, so the refusal is the kernel's own `ARPK:authority.degraded_cap`.
//! - `lobstar` runs `ValueCaps::check` — the same arithmetic the contract links — against a
//!   decimal-error amount, so the refusal is `ARPK:value.per_call_exceeded`.
//!
//! Set `ARPK_SCENARIO_OUT` to a directory to write the traces (CI sets it).

use arpk_core::caps::ValueCaps;
use arpk_core::codes::Code;
use arpk_kernel::authority::AuthorityLedger;
use arpk_kernel::enforce::{self, SignIntent};
use arpk_kernel::manifest::Manifest;
use arpk_kernel::pdp;
use arpk_kernel::receipt::ActionInput;
use arpk_kernel::trace::{BucketSnapshot, Metric, Step, Trace};

const MANIFEST: &str = r#"{
    "agent_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "expiry_ms":1800000000000,
    "lease_ttl_s":3600,
    "owner":"owner.test.near",
    "permitted_actions":[{"tool":"transfer","tier":"value"}],
    "value":{
        "assets":[{"asset":"near","per_call_cap":5000,"bucket":{"capacity":5000,"refill_per_s":10},
                   "pct_of_balance_cap_bps":1000,"approval_threshold":5000,"degraded_cap":0}],
        "destinations":["alice.test.near","bob.test.near"],
        "venues":[{"id":"venue-a","exposure_cap":10000}]
    }
}"#;

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("the scenario manifest must parse")
}

fn step(i: u32, lane: &str, kind: &str, label: &str) -> Step {
    Step {
        i,
        lane: lane.to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
        label_source: None,
        data: None,
        authority: None,
        bucket: None,
        audit_hash: None,
        verdict: None,
        reason: None,
        policy_ids: None,
        funds_out: None,
        tx: None,
    }
}

/// Resolve a relative output path against the repository root, not the crate directory —
/// `cargo test` runs test binaries with the crate as their working directory.
fn resolve_out(dir: std::path::PathBuf) -> std::path::PathBuf {
    if dir.is_absolute() {
        return dir;
    }
    let mut p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    loop {
        if p.join(".git").exists() {
            return p.join(&dir);
        }
        if !p.pop() {
            return dir;
        }
    }
}

/// Writes the trace when `ARPK_SCENARIO_OUT` is set; a local run must not litter the tree.
fn emit(trace: &Trace) {
    let dir = match std::env::var("ARPK_SCENARIO_OUT") {
        Ok(d) if !d.is_empty() => resolve_out(std::path::PathBuf::from(d)),
        _ => return,
    };
    trace.validate().expect("an emitted trace must validate");
    std::fs::create_dir_all(&dir).expect("the scenario output directory must be creatable");
    let path = dir.join(format!("{}.json", trace.id));
    std::fs::write(&path, serde_json::to_string_pretty(trace).unwrap())
        .expect("the trace must be writable");
    eprintln!("scenarios: wrote {} to {}", trace.id, path.display());
}

/// Grok/Bankr (2026-05-04): an encoded instruction escalated NFT permissions and moved
/// value through a chain of model-to-model calls. The mechanism ARPK addresses is the
/// permission escalation after untrusted ingress — simulated here, not reproduced.
#[test]
fn bankr_untrusted_ingress_degrades_and_the_transfer_is_refused() {
    let m = manifest();
    let pdp = pdp::Pdp::load().expect("the policy set must load");

    // The Authority Ledger sees untrusted content and degrades the whole session.
    let mut ledger = AuthorityLedger::new();
    ledger.on_ingress(false);
    assert_eq!(ledger.state(), arpk_kernel::authority::Authority::Degraded);

    // The agent then asks to move value. The kernel refuses, with its own code.
    let intent = SignIntent {
        agent_id: [0xAB; 32],
        session_id: [0x11; 16],
        nonce: [0x22; 16],
        manifest_hash: [0xCD; 32],
        context_hash: [0x33; 32],
        action: ActionInput {
            chain: "sandbox".to_string(),
            venue: "venue-a".to_string(),
            to: "bob.test.near".to_string(),
            asset: "near".to_string(),
            amount: 40,
            memo_hash: [0u8; 32],
        },
        authority: ledger.state().as_str().to_string(),
        agent_tier: "standard".to_string(),
        venue_paused: false,
        stale: false,
        ttl_ms: 120_000,
        issued_ms: 1_762_400_000_000,
        agent_expiry_ms: 1_762_403_600_000,
        exposure: 0,
        exposure_cap: 10_000,
        approval_threshold: 5_000,
        degraded_cap: ledger.degraded_cap(m.value.assets[0].degraded_cap),
        approval_expiry_ms: None,
    };

    let outcome = enforce::enforce(&pdp, &intent);
    assert_eq!(
        outcome,
        Err(Code::AuthorityDegradedCap),
        "a degraded session over the manifest's degraded_cap must be refused"
    );

    // The refusal is what keeps funds_out at zero.
    let funds_out = if outcome.is_ok() { 40 } else { 0 };

    let mut steps = vec![
        step(0, "agent", "ingress", "Reply decoded by an upstream model"),
        {
            let mut s = step(1, "agent", "intent", "send 40 to dest 1");
            s.data = Some(serde_json::json!({"action": 0, "dest": 1, "amount": "40"}));
            s
        },
        {
            let mut s = step(2, "kernel", "verdict", "deny");
            s.verdict = Some("deny".to_string());
            s.reason = Some(Code::AuthorityDegradedCap.as_str().to_string());
            s.policy_ids = Some(vec!["permit-degraded".to_string()]);
            s.authority = Some("Full→Degraded".to_string());
            s.bucket = Some(BucketSnapshot {
                tokens: "5000".to_string(),
                capacity: "5000".to_string(),
            });
            s
        },
        {
            let mut s = step(3, "vault", "outcome", "funds out 0");
            s.funds_out = Some("0".to_string());
            s
        },
    ];
    // Step 0 records the ingress that degraded the session.
    steps[0].label_source = Some("untrusted".to_string());
    steps[0].authority = Some("Full→Degraded".to_string());
    for (i, s) in steps.iter_mut().enumerate() {
        s.i = i as u32;
    }

    emit(&Trace {
        schema: arpk_kernel::trace::SCHEMA.to_string(),
        id: "bankr".to_string(),
        title: "Grok/Bankr reconstruction — untrusted ingress, degraded session, no value moved"
            .to_string(),
        mode: "sandbox".to_string(),
        counterfactual: true,
        simulated: vec![
            "LLM-to-LLM call chain".to_string(),
            "NFT permission escalation".to_string(),
            "the owner's manifest and caps".to_string(),
        ],
        manifest_hash: "0x00".to_string(),
        steps,
        metric: Metric {
            funds_out: funds_out.to_string(),
            cap: "5000".to_string(),
            holds: funds_out <= 5000,
        },
    });
}

/// Lobstar Wilde (2026-02): a decimal error produced an unintended transfer. ARPK's
/// relevant control is the per-call cap and the %-of-balance cap, enforced by the contract
/// on the real value — simulated here with the same arithmetic.
#[test]
fn lobstar_a_decimal_error_is_bounded_by_the_caps() {
    // The intended amount was 52.439 tokens; the decimal error produced 52,439.
    // The manifest's per-call cap is 5,000 and the %-of-balance cap is 10% of a 5,000
    // ledger, i.e. 500.
    let ledger = 5_000u128;
    let mut caps = ValueCaps::new(
        5_000, // per_call_cap
        1_000, // pct_of_balance_cap_bps (10%)
        5_000, // approval_threshold
        5_000, // bucket_capacity
        10,    // bucket_refill_per_s
    );

    let decimal_error_amount = 52_439u128;
    let outcome = caps.check(ledger, decimal_error_amount, 1_762_400_000_000);
    assert_eq!(
        outcome,
        Err(Code::ValuePerCallExceeded),
        "an amount above the per-call cap must be refused by the caps the contract runs"
    );

    let funds_out = if outcome.is_ok() {
        decimal_error_amount
    } else {
        0
    };

    // A smaller amount still runs into the %-of-balance cap.
    let mut caps2 = ValueCaps::new(5_000, 1_000, 5_000, 5_000, 10);
    let pct_case = caps2.check(ledger, 900, 1_762_400_000_000);
    assert_eq!(
        pct_case,
        Err(Code::ValuePctExceeded),
        "10% of a 5,000 ledger is 500, so 900 must be refused"
    );

    let mut steps = vec![
        step(0, "agent", "intent", "send 52439 (decimal error) to dest 0"),
        {
            let mut s = step(
                1,
                "kernel",
                "verdict",
                "allow — the kernel does not bound the per-call cap",
            );
            s.verdict = Some("allow".to_string());
            s
        },
        {
            let mut s = step(
                2,
                "vault",
                "outcome",
                "deny — the contract's caps bound the value",
            );
            s.verdict = Some("deny".to_string());
            s.reason = Some(Code::ValuePerCallExceeded.as_str().to_string());
            s.funds_out = Some("0".to_string());
            s
        },
    ];
    for (i, s) in steps.iter_mut().enumerate() {
        s.i = i as u32;
    }

    emit(&Trace {
        schema: arpk_kernel::trace::SCHEMA.to_string(),
        id: "lobstar".to_string(),
        title: "Lobstar Wilde reconstruction — a decimal error bounded by the per-call cap"
            .to_string(),
        mode: "sandbox".to_string(),
        counterfactual: true,
        simulated: vec![
            "the decimal error".to_string(),
            "the owner's manifest and caps".to_string(),
            "the recipient and the venue".to_string(),
        ],
        manifest_hash: "0x00".to_string(),
        steps,
        metric: Metric {
            funds_out: funds_out.to_string(),
            cap: "5000".to_string(),
            holds: funds_out <= 5000,
        },
    });
}
