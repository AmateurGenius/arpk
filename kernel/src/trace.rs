//! `arpk.trace/1` — the scenario trace schema shared by the dashboard, the CLI and CI.
//!
//! A trace is a reconstruction of one scenario across the five lanes (owner, agent,
//! kernel, relayer, vault). It is the dashboard's Theater content and the CLI's `demo`
//! output. Every trace carries the provenance fields that make it checkable: which
//! manifest it ran under, what was simulated, and whether the bound held.
//!
//! Two kinds exist and they must be labelled differently:
//! - **recorded** — emitted by a real run (the sandbox e2e writes `baseline`). Real data.
//! - **reconstruction** — a counterfactual built from the scenario definition (`bankr`,
//!   `lobstar`). The `simulated` array is mandatory and rendered on the page; the
//!   `counterfactual: true` flag must never be dropped.

use serde::{Deserialize, Serialize};

use arpk_core::codes::Code;

pub const SCHEMA: &str = "arpk.trace/1";

pub const LANES: [&str; 5] = ["owner", "agent", "kernel", "relayer", "vault"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trace {
    pub schema: String,
    pub id: String,
    pub title: String,
    /// `"sandbox"` or `"testnet"`.
    pub mode: String,
    /// A reconstruction of an incident, not a reproduction. Always rendered.
    pub counterfactual: bool,
    /// What was *not* really executed. Mandatory and rendered on the page.
    pub simulated: Vec<String>,
    pub manifest_hash: String,
    pub steps: Vec<Step>,
    pub metric: Metric,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub i: u32,
    pub lane: String,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Authority transition, e.g. `"Full→Degraded"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<BucketSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// The exact `ARPK:*` code, when this step is a denial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funds_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketSnapshot {
    pub tokens: String,
    pub capacity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metric {
    pub funds_out: String,
    pub cap: String,
    pub holds: bool,
}

#[derive(Debug)]
pub enum TraceError {
    Schema,
    Mode,
    Lane {
        index: usize,
        lane: String,
    },
    StepIndex {
        expected: u32,
        found: u32,
    },
    MissingSimulated,
    DenialWithoutCode {
        index: usize,
    },
    MetricMismatch {
        funds_out: u128,
        cap: u128,
        holds: bool,
    },
    NotCounterfactual,
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceError::Schema => write!(f, "schema must be {SCHEMA}"),
            TraceError::Mode => write!(f, "mode must be \"sandbox\" or \"testnet\""),
            TraceError::Lane { index, lane } => {
                write!(
                    f,
                    "step {index}: unknown lane '{lane}' (expected one of {LANES:?})"
                )
            }
            TraceError::StepIndex { expected, found } => {
                write!(
                    f,
                    "steps must be numbered from 0: expected {expected}, found {found}"
                )
            }
            TraceError::MissingSimulated => write!(
                f,
                "a counterfactual trace must list what was simulated (the `simulated` array)"
            ),
            TraceError::DenialWithoutCode { index } => {
                write!(f, "step {index}: a denial must carry an exact ARPK:* code")
            }
            TraceError::MetricMismatch {
                funds_out,
                cap,
                holds,
            } => write!(
                f,
                "metric says holds={holds} but funds_out {funds_out} vs cap {cap}"
            ),
            TraceError::NotCounterfactual => write!(f, "a reconstruction must be counterfactual"),
        }
    }
}

impl std::error::Error for TraceError {}

impl Trace {
    /// Validates the invariants a judge would check. Returns `Ok(())` or the first problem.
    pub fn validate(&self) -> Result<(), TraceError> {
        if self.schema != SCHEMA {
            return Err(TraceError::Schema);
        }
        if self.mode != "sandbox" && self.mode != "testnet" {
            return Err(TraceError::Mode);
        }
        if self.counterfactual {
            if self.simulated.is_empty() {
                return Err(TraceError::MissingSimulated);
            }
        }
        for (expected, step) in self.steps.iter().enumerate() {
            if step.i as usize != expected {
                return Err(TraceError::StepIndex {
                    expected: expected as u32,
                    found: step.i,
                });
            }
            if !LANES.contains(&step.lane.as_str()) {
                return Err(TraceError::Lane {
                    index: expected,
                    lane: step.lane.clone(),
                });
            }
            if step.verdict.as_deref() == Some("deny") {
                match step.reason.as_deref() {
                    Some(code) if code.starts_with("ARPK:") => {
                        // Must be a real reason code.
                        if !Code::ALL.iter().any(|c| c.as_str() == code) {
                            return Err(TraceError::DenialWithoutCode { index: expected });
                        }
                    }
                    _ => return Err(TraceError::DenialWithoutCode { index: expected }),
                }
            }
        }
        let funds_out: u128 =
            self.metric
                .funds_out
                .parse()
                .map_err(|_| TraceError::MetricMismatch {
                    funds_out: 0,
                    cap: 0,
                    holds: self.metric.holds,
                })?;
        let cap: u128 = self
            .metric
            .cap
            .parse()
            .map_err(|_| TraceError::MetricMismatch {
                funds_out,
                cap: 0,
                holds: self.metric.holds,
            })?;
        if self.metric.holds != (funds_out <= cap) {
            return Err(TraceError::MetricMismatch {
                funds_out,
                cap,
                holds: self.metric.holds,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn a_recorded_trace_validates() {
        let t = Trace {
            schema: SCHEMA.to_string(),
            id: "baseline".to_string(),
            title: "Baseline transfer".to_string(),
            mode: "sandbox".to_string(),
            counterfactual: false,
            simulated: vec![],
            manifest_hash: "0xabc".to_string(),
            steps: vec![
                step(0, "agent", "intent", "send 1 NEAR to dest 0"),
                step(1, "kernel", "verdict", "allow"),
                {
                    let mut s = step(2, "vault", "outcome", "funds out 1");
                    s.funds_out = Some("1".to_string());
                    s
                },
            ],
            metric: Metric {
                funds_out: "1".to_string(),
                cap: "10".to_string(),
                holds: true,
            },
        };
        t.validate().expect("a recorded trace must validate");
    }

    #[test]
    fn a_denial_must_carry_a_real_reason_code() {
        let mut t = Trace {
            schema: SCHEMA.to_string(),
            id: "bankr".to_string(),
            title: "Bankr".to_string(),
            mode: "sandbox".to_string(),
            counterfactual: true,
            simulated: vec!["LLM chain".to_string()],
            manifest_hash: "0xdef".to_string(),
            steps: vec![step(0, "agent", "ingress", "untrusted reply"), {
                let mut s = step(1, "kernel", "verdict", "deny");
                s.verdict = Some("deny".to_string());
                s.reason = Some("ARPK:authority.degraded_cap".to_string());
                s
            }],
            metric: Metric {
                funds_out: "0".to_string(),
                cap: "10".to_string(),
                holds: true,
            },
        };
        t.validate().expect("a real reason code must validate");

        t.steps[1].reason = Some("ARPK:made.up".to_string());
        assert!(t.validate().is_err(), "an invented code must be rejected");
    }

    #[test]
    fn a_counterfactual_must_declare_what_was_simulated() {
        let mut t = Trace {
            schema: SCHEMA.to_string(),
            id: "bankr".to_string(),
            title: "Bankr".to_string(),
            mode: "sandbox".to_string(),
            counterfactual: true,
            simulated: vec!["LLM chain".to_string()],
            manifest_hash: "0xdef".to_string(),
            steps: vec![step(0, "agent", "ingress", "x")],
            metric: Metric {
                funds_out: "0".to_string(),
                cap: "10".to_string(),
                holds: true,
            },
        };
        t.simulated.clear();
        assert!(t.validate().is_err());
    }

    #[test]
    fn the_metric_must_agree_with_the_bound() {
        let t = Trace {
            schema: SCHEMA.to_string(),
            id: "bad".to_string(),
            title: "Bad".to_string(),
            mode: "sandbox".to_string(),
            counterfactual: false,
            simulated: vec![],
            manifest_hash: "0x0".to_string(),
            steps: vec![step(0, "vault", "outcome", "funds out 20")],
            metric: Metric {
                funds_out: "20".to_string(),
                cap: "10".to_string(),
                holds: true,
            },
        };
        assert!(t.validate().is_err(), "a broken bound must not validate");
    }

    #[test]
    fn steps_are_deserialized_from_the_documented_shape() {
        let json = json!({
            "schema": "arpk.trace/1",
            "id": "bankr",
            "title": "Grok/Bankr reconstruction",
            "mode": "sandbox",
            "counterfactual": true,
            "simulated": ["LLM-to-LLM chain", "NFT permission escalation"],
            "manifest_hash": "0xdead",
            "steps": [
                {"i": 0, "lane": "agent", "kind": "ingress",
                 "label": "Reply decoded by upstream model",
                 "label_source": "untrusted",
                 "authority": "Full→Degraded",
                 "bucket": {"tokens": "5", "capacity": "5"}}
            ],
            "metric": {"funds_out": "0", "cap": "5", "holds": true}
        });
        let t: Trace = serde_json::from_value(json).expect("the documented shape must parse");
        t.validate().expect("the documented shape must validate");
    }
}
