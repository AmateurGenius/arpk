//! `arpkd` — the ARPK kernel daemon.
//!
//! WP1b fills in `serve`, the monitors, the Authority Ledger and the relayer, and
//! adds `receipt.rs` (signer + receipt construction). The Cedar PDP is already in
//! place: [`pdp`] embeds and validates the six policies from the build plan and
//! denies on any diagnostics error.

mod pdp;

fn main() {
    match pdp::Pdp::load() {
        Ok(pdp) => eprintln!(
            "arpkd: PDP loaded and validated ({} policies); serve/receipts are WP1b",
            pdp.policy_count()
        ),
        Err(e) => {
            eprintln!("arpkd: fail-closed: {e}");
            std::process::exit(1);
        }
    }
}
