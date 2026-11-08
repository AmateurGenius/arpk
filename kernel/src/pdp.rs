//! Cedar policy decision point — the kernel's PDP.
//!
//! Spike S3 (build plan §6.2): `cedar-policy` embeds on Termux, the embedded schema
//! validates the embedded policy set, and a forced error denies.
//!
//! Amounts reach Cedar only as bounded `Long` values precomputed by monitors — Cedar
//! never sees an unbounded integer. A policy that errors is skipped by Cedar, so the
//! kernel treats any diagnostics error as a deny (`ARPK:policy.eval_error`, B14).
//!
//! Policies are the six from §5.6: permit-transfer-full, permit-degraded, forbid-stale,
//! forbid-venue-paused, forbid-admin-autonomous, forbid-askonly. The contract's caps
//! remain the bound; kernel caps are only ever more restrictive.

use std::str::FromStr;

use cedar_policy::RestrictedExpression;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};

use arpk_core::codes::Code;

/// Strict schema: the entity types, the `execute_value` action, and the bounded
/// context record the monitors build. Source of truth: `policies/schema.cedarschema`.
const SCHEMA: &str = include_str!("../../policies/schema.cedarschema");

/// The six policies from the build plan. Amounts appear only as `Long`.
/// Source of truth: `policies/base.cedar`.
const POLICIES: &str = include_str!("../../policies/base.cedar");

/// A loaded, schema-validated policy set.
pub struct Pdp {
    policies: PolicySet,
    schema: Schema,
}

/// The kernel's verdict. A denial always carries an exact `ARPK:*` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(Code),
}

impl Pdp {
    /// Loads the embedded policy set and validates it against the strict schema.
    pub fn load() -> Result<Self, PdpError> {
        let schema = Schema::from_str(SCHEMA).map_err(|e| PdpError::Schema(e.to_string()))?;
        let policies =
            PolicySet::from_str(POLICIES).map_err(|e| PdpError::PolicySet(e.to_string()))?;
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(PdpError::Validation(errors));
        }
        Ok(Self { policies, schema })
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Number of static policies embedded.
    pub fn policy_count(&self) -> usize {
        self.policies.policies().count()
    }

    /// Authorizes one request. Any Cedar diagnostics error is a deny.
    pub fn evaluate(&self, request: &Request, entities: &Entities) -> Verdict {
        let response = Authorizer::new().is_authorized(request, &self.policies, entities);
        if response.diagnostics().errors().next().is_some() {
            return Verdict::Deny(Code::PolicyEvalError);
        }
        match response.decision() {
            Decision::Allow => Verdict::Allow,
            Decision::Deny => Verdict::Deny(Code::ActionNotPermitted),
        }
    }
}

/// Load-time failure. The kernel treats this as fail-closed: nothing is authorized.
#[derive(Debug)]
pub enum PdpError {
    Schema(String),
    PolicySet(String),
    Validation(Vec<String>),
}

impl core::fmt::Display for PdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PdpError::Schema(e) => write!(f, "ARPK: schema error: {e}"),
            PdpError::PolicySet(e) => write!(f, "ARPK: policy set error: {e}"),
            PdpError::Validation(errors) => {
                write!(f, "ARPK: policy set failed strict validation: {errors:?}")
            }
        }
    }
}

/// Builds the `execute_value` request the kernel evaluates.
///
/// `amount` is `None` only to force a missing-attribute evaluation error (B14).
pub fn request(
    agent_id: &str,
    venue_id: &str,
    authority: &str,
    stale: bool,
    amount: Option<i64>,
) -> Request {
    let principal = EntityUid::from_str(&format!("Agent::{agent_id:?}")).unwrap();
    let action = EntityUid::from_str(r#"Action::"execute_value""#).unwrap();
    let resource = EntityUid::from_str(&format!("Venue::{venue_id:?}")).unwrap();
    let mut pairs = vec![
        (
            "authority".to_string(),
            RestrictedExpression::from_str(&format!("{authority:?}")).unwrap(),
        ),
        (
            "stale".to_string(),
            RestrictedExpression::from_str(if stale { "true" } else { "false" }).unwrap(),
        ),
    ];
    if let Some(amount) = amount {
        pairs.push((
            "amount".to_string(),
            RestrictedExpression::from_str(&amount.to_string()).unwrap(),
        ));
    }
    let context = Context::from_pairs(pairs).unwrap();
    Request::new(principal, action, resource, context, None).unwrap()
}

/// Builds the entity store for a request.
///
/// `with_principal = false` omits the `Agent` entity, which forces an attribute-access
/// evaluation error in any policy that reads `principal.*` — the B14 forced error.
pub fn entities(
    agent_id: &str,
    venue_id: &str,
    venue_paused: bool,
    with_principal: bool,
) -> Entities {
    let mut items = Vec::new();
    if with_principal {
        items.push(format!(
            r#"{{"uid":{{"type":"Agent","id":{agent_id:?}}},"attrs":{{"agent_id":{agent_id:?},"tier":"standard"}},"parents":[]}}"#
        ));
    }
    items.push(format!(
        r#"{{"uid":{{"type":"Venue","id":{venue_id:?}}},"attrs":{{"venue_id":{venue_id:?},"paused":{venue_paused}}},"parents":[]}}"#
    ));
    Entities::from_json_str(&format!("[{}]", items.join(",")), None).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_policy_set_validates_against_the_strict_schema() {
        let pdp = Pdp::load().expect("embedded policy set must validate");
        assert_eq!(
            pdp.policy_count(),
            6,
            "all six policies from the plan must be embedded"
        );
    }

    #[test]
    fn full_authority_permits_a_live_transfer() {
        let pdp = Pdp::load().unwrap();
        let req = request("agent-0", "venue-0", "full", false, Some(1_000));
        let entities = entities("agent-0", "venue-0", false, true);
        assert_eq!(pdp.evaluate(&req, &entities), Verdict::Allow);
    }

    #[test]
    fn paused_venue_denies_with_action_not_permitted() {
        let pdp = Pdp::load().unwrap();
        let req = request("agent-0", "venue-0", "full", false, Some(1_000));
        let entities = entities("agent-0", "venue-0", true, true);
        assert_eq!(
            pdp.evaluate(&req, &entities),
            Verdict::Deny(Code::ActionNotPermitted)
        );
        assert_eq!(
            Code::ActionNotPermitted.as_str(),
            "ARPK:action.not_permitted"
        );
    }

    /// B14: the principal entity is absent, so `principal.tier` errors during
    /// evaluation. Cedar skips that policy and records a diagnostic; the kernel must
    /// deny with the exact `ARPK:policy.eval_error` code.
    #[test]
    fn forced_error_denies_with_the_exact_code() {
        let pdp = Pdp::load().unwrap();
        let req = request("agent-0", "venue-0", "full", false, Some(1_000));
        let entities = entities("agent-0", "venue-0", false, false);
        assert_eq!(
            pdp.evaluate(&req, &entities),
            Verdict::Deny(Code::PolicyEvalError)
        );
        assert_eq!(Code::PolicyEvalError.as_str(), "ARPK:policy.eval_error");
    }

    /// B14, second path: a context missing the bounded `amount` attribute makes
    /// `context.amount <= 0` error, which Cedar skips and reports as a diagnostic.
    #[test]
    fn missing_context_amount_is_also_a_forced_error() {
        let pdp = Pdp::load().unwrap();
        let req = request("agent-0", "venue-0", "degraded", false, None);
        let entities = entities("agent-0", "venue-0", false, true);
        assert_eq!(
            pdp.evaluate(&req, &entities),
            Verdict::Deny(Code::PolicyEvalError)
        );
    }

    /// The embedded schema is also the request schema: a well-formed request validates.
    #[test]
    fn a_well_formed_request_validates_against_the_embedded_schema() {
        let pdp = Pdp::load().unwrap();
        let principal = EntityUid::from_str(r#"Agent::"agent-0""#).unwrap();
        let action = EntityUid::from_str(r#"Action::"execute_value""#).unwrap();
        let resource = EntityUid::from_str(r#"Venue::"venue-0""#).unwrap();
        let context = Context::from_pairs(vec![
            (
                "authority".to_string(),
                RestrictedExpression::from_str("\"full\"").unwrap(),
            ),
            (
                "stale".to_string(),
                RestrictedExpression::from_str("false").unwrap(),
            ),
            (
                "amount".to_string(),
                RestrictedExpression::from_str("1000").unwrap(),
            ),
        ])
        .unwrap();
        assert!(Request::new(principal, action, resource, context, Some(pdp.schema())).is_ok());
    }
}
