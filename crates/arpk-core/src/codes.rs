//! Reason codes. Every denial and panic in ARPK uses one of these exact strings.
///
/// Binding rule (from the build plan): a test that asserts "no reason code" is a
/// smoke test, not a test. Tests assert these strings exactly.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    // manifest
    ManifestMissing,
    ManifestExpired,
    ManifestHashMismatch,
    ManifestRevoked,
    // receipt
    ReceiptBadSignature,
    ReceiptKeyInvalid,
    ReceiptReplayed,
    ReceiptExpired,
    ReceiptNotYetValid,
    ReceiptTtlTooLong,
    ReceiptActionHashMismatch,
    ReceiptClassMismatch,
    // value
    ValuePerCallExceeded,
    ValueBucketExceeded,
    ValuePctExceeded,
    ValueApprovalRequired,
    ValueOverflow,
    // venue
    VenuePaused,
    VenueExposureCap,
    // time
    TimeRegression,
    /// Structurally invalid input (wrong length, unparseable destination).
    Malformed,
    // policy (kernel PDP)
    PolicyEvalError,
    // action
    ActionNotPermitted,
    ActionUnclassified,
    // authority ledger
    AuthorityDegradedCap,
    AuthorityFrozen,
    AuthorityAskOnly,
    // tier
    TierAdministrativeDenied,
    // lease
    LeaseStale,
    // approval
    ApprovalTimeout,
}

impl Code {
    /// Every reason code. Validators use this to reject invented codes — a trace or a
    /// report that cites a code not in this list is a bug, not a finding.
    pub const ALL: &'static [Code] = &[
        Code::ManifestMissing,
        Code::ManifestExpired,
        Code::ManifestHashMismatch,
        Code::ManifestRevoked,
        Code::ReceiptBadSignature,
        Code::ReceiptKeyInvalid,
        Code::ReceiptReplayed,
        Code::ReceiptExpired,
        Code::ReceiptNotYetValid,
        Code::ReceiptTtlTooLong,
        Code::ReceiptActionHashMismatch,
        Code::ReceiptClassMismatch,
        Code::ValuePerCallExceeded,
        Code::ValueBucketExceeded,
        Code::ValuePctExceeded,
        Code::ValueApprovalRequired,
        Code::ValueOverflow,
        Code::VenuePaused,
        Code::VenueExposureCap,
        Code::TimeRegression,
        Code::Malformed,
        Code::PolicyEvalError,
        Code::ActionNotPermitted,
        Code::ActionUnclassified,
        Code::AuthorityDegradedCap,
        Code::AuthorityFrozen,
        Code::AuthorityAskOnly,
        Code::TierAdministrativeDenied,
        Code::LeaseStale,
        Code::ApprovalTimeout,
    ];

    pub fn as_str(self) -> &'static str {
        use Code::*;
        match self {
            ManifestMissing => "ARPK:manifest.missing",
            ManifestExpired => "ARPK:manifest.expired",
            ManifestHashMismatch => "ARPK:manifest.hash_mismatch",
            ManifestRevoked => "ARPK:manifest.revoked",
            ReceiptBadSignature => "ARPK:receipt.bad_signature",
            ReceiptKeyInvalid => "ARPK:receipt.key_invalid",
            ReceiptReplayed => "ARPK:receipt.replayed",
            ReceiptExpired => "ARPK:receipt.expired",
            ReceiptNotYetValid => "ARPK:receipt.not_yet_valid",
            ReceiptTtlTooLong => "ARPK:receipt.ttl_too_long",
            ReceiptActionHashMismatch => "ARPK:receipt.action_hash_mismatch",
            ReceiptClassMismatch => "ARPK:receipt.class_mismatch",
            ValuePerCallExceeded => "ARPK:value.per_call_exceeded",
            ValueBucketExceeded => "ARPK:value.bucket_exceeded",
            ValuePctExceeded => "ARPK:value.pct_exceeded",
            ValueApprovalRequired => "ARPK:value.approval_required",
            ValueOverflow => "ARPK:value.overflow",
            VenuePaused => "ARPK:venue.paused",
            VenueExposureCap => "ARPK:venue.exposure_cap",
            TimeRegression => "ARPK:time.regression",
            Malformed => "ARPK:malformed",
            PolicyEvalError => "ARPK:policy.eval_error",
            ActionNotPermitted => "ARPK:action.not_permitted",
            ActionUnclassified => "ARPK:action.unclassified",
            AuthorityDegradedCap => "ARPK:authority.degraded_cap",
            AuthorityFrozen => "ARPK:authority.frozen",
            AuthorityAskOnly => "ARPK:authority.askonly",
            TierAdministrativeDenied => "ARPK:tier.administrative_denied",
            LeaseStale => "ARPK:lease.stale",
            ApprovalTimeout => "ARPK:approval.timeout",
        }
    }
}

impl core::fmt::Display for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
