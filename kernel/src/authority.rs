//! Authority Ledger (lite) — untrusted ingress shrinks authority (claim C3, attenuation).
//!
//! The ledger is a *conservative session watermark*, not a per-token taint tracker: any
//! untrusted ingress degrades the whole session. That is deliberate — an LLM's context
//! cannot be tracked per token, so the only sound rule is the coarse one.
//!
//! States change **caps, not logic**: a `Degraded` session is bounded by the manifest's
//! `degraded_cap` instead of the owner's full caps. `AskOnly` refuses everything. `Frozen`
//! is terminal (owner freeze, stale lease, or expiry).
//!
//! The `authority.degraded_cap` code is produced by `enforce`, which runs this check before
//! the PDP so a degraded denial names its cause rather than surfacing as a generic
//! "not permitted".

use arpk_core::codes::Code;

/// How many denials inside a degraded session escalate to `AskOnly`.
pub const DENIALS_TO_ASKONLY: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    Full,
    Degraded,
    AskOnly,
    Frozen,
}

impl Authority {
    pub fn as_str(self) -> &'static str {
        match self {
            Authority::Full => "full",
            Authority::Degraded => "degraded",
            Authority::AskOnly => "askonly",
            Authority::Frozen => "frozen",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "full" => Some(Authority::Full),
            "degraded" => Some(Authority::Degraded),
            "askonly" => Some(Authority::AskOnly),
            "frozen" => Some(Authority::Frozen),
            _ => None,
        }
    }

    /// Whether this state may move value at all. Only `Full` may.
    pub fn permits_value(self) -> bool {
        matches!(self, Authority::Full)
    }
}

/// A conservative session watermark.
#[derive(Clone, Debug)]
pub struct AuthorityLedger {
    state: Authority,
    denials: u32,
}

impl Default for AuthorityLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorityLedger {
    pub fn new() -> Self {
        Self {
            state: Authority::Full,
            denials: 0,
        }
    }

    pub fn state(&self) -> Authority {
        self.state
    }

    pub fn denials(&self) -> u32 {
        self.denials
    }

    /// Record an ingress. Untrusted content degrades a healthy session; trusted content
    /// leaves it alone. `Frozen` and `AskOnly` never improve.
    pub fn on_ingress(&mut self, trusted: bool) {
        if !trusted && self.state == Authority::Full {
            self.state = Authority::Degraded;
            self.denials = 0;
        }
    }

    /// Record a denial. Repeated denials inside a degraded session escalate to `AskOnly`.
    pub fn on_denial(&mut self) {
        if self.state == Authority::Degraded {
            self.denials = self.denials.saturating_add(1);
            if self.denials >= DENIALS_TO_ASKONLY {
                self.state = Authority::AskOnly;
            }
        }
    }

    /// Owner freeze, a stale lease, or manifest expiry. Terminal.
    pub fn freeze(&mut self) {
        self.state = Authority::Frozen;
    }

    /// The degraded cap for this state: the manifest's value when degraded, zero otherwise.
    pub fn degraded_cap(&self, manifest_degraded_cap: u128) -> u128 {
        match self.state {
            Authority::Degraded => manifest_degraded_cap,
            _ => 0,
        }
    }
}

/// A degraded session may not exceed the manifest's `degraded_cap`.
///
/// This is the kernel-side half of the check; the Cedar policy enforces the same bound so
/// the two cannot drift.
pub fn check_degraded_cap(amount: u128, degraded_cap: u128) -> Result<(), Code> {
    if amount > degraded_cap {
        return Err(Code::AuthorityDegradedCap);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_session_is_full() {
        let ledger = AuthorityLedger::new();
        assert_eq!(ledger.state(), Authority::Full);
        assert!(ledger.state().permits_value());
    }

    #[test]
    fn untrusted_ingress_degrades_the_whole_session() {
        let mut ledger = AuthorityLedger::new();
        ledger.on_ingress(false);
        assert_eq!(ledger.state(), Authority::Degraded);
        assert!(!ledger.state().permits_value());
    }

    #[test]
    fn trusted_ingress_leaves_a_session_alone() {
        let mut ledger = AuthorityLedger::new();
        ledger.on_ingress(true);
        assert_eq!(ledger.state(), Authority::Full);
    }

    /// The Bankr reconstruction: one untrusted reply degrades the session, and the
    /// transfer that follows is bounded by the manifest's degraded cap.
    #[test]
    fn a_degraded_session_is_bounded_by_the_manifest_cap() {
        let mut ledger = AuthorityLedger::new();
        ledger.on_ingress(false);
        assert_eq!(ledger.state(), Authority::Degraded);

        // The manifest's degraded cap is zero by default, so any value transfer is over it.
        assert_eq!(check_degraded_cap(1, 0), Err(Code::AuthorityDegradedCap));
        assert_eq!(check_degraded_cap(0, 0), Ok(()));
        assert_eq!(ledger.degraded_cap(0), 0);

        // A manifest that raised the degraded cap permits a small transfer.
        assert_eq!(ledger.degraded_cap(50), 50);
        assert_eq!(check_degraded_cap(50, 50), Ok(()));
        assert_eq!(check_degraded_cap(51, 50), Err(Code::AuthorityDegradedCap));
    }

    #[test]
    fn repeated_denials_escalate_to_askonly() {
        let mut ledger = AuthorityLedger::new();
        ledger.on_ingress(false);
        ledger.on_denial();
        ledger.on_denial();
        assert_eq!(
            ledger.state(),
            Authority::Degraded,
            "two denials are not yet enough"
        );
        ledger.on_denial();
        assert_eq!(ledger.state(), Authority::AskOnly);
        assert!(!ledger.state().permits_value());
    }

    #[test]
    fn a_freeze_is_terminal() {
        let mut ledger = AuthorityLedger::new();
        ledger.freeze();
        assert_eq!(ledger.state(), Authority::Frozen);
        // No transition leaves Frozen.
        ledger.on_ingress(true);
        ledger.on_denial();
        assert_eq!(ledger.state(), Authority::Frozen);
    }

    #[test]
    fn states_round_trip_through_their_exact_strings() {
        for state in [
            Authority::Full,
            Authority::Degraded,
            Authority::AskOnly,
            Authority::Frozen,
        ] {
            assert_eq!(Authority::parse(state.as_str()), Some(state));
        }
        assert_eq!(
            Authority::parse("Full"),
            None,
            "the strings are lowercase and exact"
        );
    }
}
