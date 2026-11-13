//! `arpkd serve` — JSON lines over a unix socket.
//!
//! Typed events: `Action` (authorize and sign), `Observation` (record audit evidence),
//! `Control` (operate the kernel), `State` (query it). A malformed line is answered with
//! the exact `ARPK:malformed` code — never a panic, never a dropped connection.
//!
//! The agent plane reaches only this socket: no value-bearing credential crosses it, and
//! the kernel's own key never leaves the process.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{SystemTime, UNIX_EPOCH};

use arpk_core::codes::Code;
use arpk_core::MAX_RECEIPT_TTL_MS;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::enforce::{self, SignIntent};
use crate::{intent, manifest, monitors, pdp, receipt};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Event {
    Action(ActionEvent),
    Observation(ObservationEvent),
    Control(ControlEvent),
    State,
}

#[derive(Deserialize)]
struct ActionEvent {
    #[serde(deserialize_with = "hex_bytes")]
    agent_id: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    session_id: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    nonce: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    manifest_hash: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    context_hash: Vec<u8>,
    contract: String,
    /// The chain id, for the receipt domain. The contract checks it on-chain.
    chain: String,
    /// The venue id. Must be one the manifest issued.
    venue: String,
    /// Handle-based intent. `deny_unknown_fields`: an injected destination is unrepresentable.
    action: intent::Intent,
    authority: String,
    #[serde(default = "default_tier")]
    agent_tier: String,
    #[serde(default)]
    venue_paused: bool,
    #[serde(default)]
    stale: bool,
    #[serde(default)]
    ttl_ms: Option<u64>,
    #[serde(default)]
    issued_ms: Option<u64>,
    #[serde(default)]
    agent_expiry_ms: Option<u64>,
    #[serde(default, deserialize_with = "opt_u128_from")]
    exposure: Option<u128>,
    #[serde(default, deserialize_with = "opt_u128_from")]
    exposure_cap: Option<u128>,
    #[serde(default, deserialize_with = "opt_u128_from")]
    approval_threshold: Option<u128>,
    /// The manifest's per-asset degraded cap, for a degraded session.
    #[serde(default)]
    degraded_cap: Option<u128>,
    #[serde(default)]
    approval_expiry_ms: Option<u64>,
}

fn default_tier() -> String {
    "standard".to_string()
}

#[derive(Deserialize)]
struct ObservationEvent {
    /// keccak256 of the observation, for the audit chain.
    #[serde(deserialize_with = "hex_bytes")]
    action_hash: Vec<u8>,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
struct ControlEvent {
    command: String,
    #[serde(default)]
    now_ms: u64,
}

/// Kernel state held for the lifetime of the server.
pub struct ServeState {
    ledger: monitors::SpendLedger,
    pdp: pdp::Pdp,
    observations: Vec<ObservationEvent>,
    /// The owner's manifest. The agent names *handles* into this; the kernel resolves them,
    /// so a destination the manifest never issued cannot be expressed.
    manifest: manifest::Manifest,
}

impl ServeState {
    pub fn new(pdp: pdp::Pdp, manifest: manifest::Manifest) -> Self {
        Self {
            ledger: monitors::SpendLedger::new(),
            pdp,
            observations: Vec::new(),
            manifest,
        }
    }

    /// Handles one line. Always returns one JSON line to write back.
    pub fn handle_line(&mut self, line: &str) -> String {
        match serde_json::from_str::<Event>(line) {
            Ok(event) => self.handle(event),
            Err(_) => denial(Code::Malformed),
        }
    }

    fn handle(&mut self, event: Event) -> String {
        match event {
            Event::Action(e) => self.handle_action(e),
            Event::Observation(o) => {
                let count = self.observations.len() + 1;
                let out = json!({
                    "ok": true,
                    "recorded": "observation",
                    "action_hash": hex(&o.action_hash),
                    "note": o.note.clone(),
                    "count": count,
                });
                self.observations.push(o);
                serde_json::to_string(&out).unwrap()
            }
            Event::Control(c) => {
                let released = match c.command.as_str() {
                    "release_expired" => self.ledger.release_expired(c.now_ms),
                    _ => return denial(Code::ActionUnclassified),
                };
                serde_json::to_string(&json!({"ok": true, "released": released})).unwrap()
            }
            Event::State => serde_json::to_string(&json!({
                "ok": true,
                "outstanding": self.ledger.outstanding(),
                "reservations": self.ledger.len(),
                "observations": self.observations.len(),
                "policies": self.pdp.policy_count(),
            }))
            .unwrap(),
        }
    }

    fn handle_action(&mut self, e: ActionEvent) -> String {
        // Wrong byte lengths are malformed input, not policy denials.
        let agent_id = match fixed::<32>(&e.agent_id) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };
        let session_id = match fixed::<16>(&e.session_id) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };
        let nonce = match fixed::<16>(&e.nonce) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };
        let manifest_hash = match fixed::<32>(&e.manifest_hash) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };
        let context_hash = match fixed::<32>(&e.context_hash) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };

        // The kernel holds the owner's manifest. The receipt must name the manifest the
        // kernel actually read, so a file that does not hash to the on-chain value is refused.
        let held = match manifest::manifest_hash(&self.manifest) {
            Ok(h) => h,
            Err(_) => return denial(Code::Malformed),
        };
        if held != manifest_hash {
            return denial(Code::ManifestHashMismatch);
        }

        // The venue is enumerated too: an unissued venue is not a place value may go.
        if !self.manifest.value.venues.iter().any(|v| v.id == e.venue) {
            return denial(Code::ActionUnclassified);
        }

        // Handles -> the exact action. An unissued handle is refused here, before the PDP.
        let resolved = match intent::resolve(&self.manifest, &e.action, &e.chain, &e.venue) {
            Ok(r) => r,
            Err(code) => return denial(code),
        };

        let issued_ms = e.issued_ms.unwrap_or_else(now_ms);
        let intent = SignIntent {
            agent_id,
            session_id,
            nonce,
            manifest_hash,
            context_hash,
            action: resolved.action,
            authority: e.authority,
            agent_tier: e.agent_tier,
            venue_paused: e.venue_paused,
            stale: e.stale,
            ttl_ms: e.ttl_ms.unwrap_or(MAX_RECEIPT_TTL_MS),
            issued_ms,
            agent_expiry_ms: e.agent_expiry_ms.unwrap_or(u64::MAX),
            exposure: e.exposure.unwrap_or(0),
            exposure_cap: e.exposure_cap.unwrap_or(u128::MAX),
            approval_threshold: e.approval_threshold.unwrap_or(u128::MAX),
            degraded_cap: e.degraded_cap.unwrap_or(0),
            approval_expiry_ms: e.approval_expiry_ms,
        };

        if let Err(code) = enforce::enforce(&self.pdp, &intent) {
            return denial(code);
        }
        // Reserve the value against the nonce for the receipt's lifetime, so a receipt
        // cannot be spent twice off-chain.
        if let Err(code) = self.ledger.reserve(
            nonce,
            intent.action.amount,
            issued_ms.saturating_add(intent.ttl_ms),
            issued_ms,
        ) {
            return denial(code);
        }

        let key = match receipt::KernelKey::simulator() {
            Ok(k) => k,
            Err(e) => return error_out(&e.to_string()),
        };
        let domain = receipt::domain(&intent.action.chain, &e.contract);
        let signed = match receipt::sign_value(
            key.signing_key(),
            &domain,
            &receipt::ReceiptRequest {
                action: intent.action.clone(),
                agent_id: intent.agent_id,
                session_id: intent.session_id,
                manifest_hash: intent.manifest_hash,
                context_hash: intent.context_hash,
                nonce: intent.nonce,
                issued_ms: intent.issued_ms,
                ttl_ms: intent.ttl_ms,
            },
        ) {
            Ok(s) => s,
            Err(e) => return error_out(&e.to_string()),
        };

        serde_json::to_string(&json!({
            "ok": true,
            "agent_id": signed.receipt.agent_id.to_vec(),
            "action": {
                "chain": intent.action.chain,
                "venue": intent.action.venue,
                "to": intent.action.to,
                "asset": intent.action.asset,
                "amount": intent.action.amount.to_string(),
                "memo_hash": intent.action.memo_hash.to_vec(),
            },
            "receipt": {
                "agent_id": signed.receipt.agent_id.to_vec(),
                "session_id": signed.receipt.session_id.to_vec(),
                "class": signed.receipt.class,
                "action_hash": signed.action_hash.to_vec(),
                "manifest_hash": signed.receipt.manifest_hash.to_vec(),
                "context_hash": signed.receipt.context_hash.to_vec(),
                "verdict": signed.receipt.verdict,
                "nonce": signed.receipt.nonce.to_vec(),
                "issued_ms": signed.receipt.issued_ms.to_string(),
                "expiry_ms": signed.receipt.expiry_ms.to_string(),
            },
            "signature": signed.signature,
            "v": signed.v,
        }))
        .unwrap()
    }
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], ()> {
    v.try_into().map_err(|_| ())
}

/// Byte fields arrive as hex strings over the socket, the same encoding the CLI accepts.
fn hex_bytes<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    if s.len() % 2 != 0 {
        return Err(serde::de::Error::custom("hex length must be even"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(serde::de::Error::custom))
        .collect()
}

fn u128_from_value(v: Value) -> Result<u128, String> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .map(|x| x as u128)
            .ok_or_else(|| "amount out of range".to_string()),
        Value::String(s) => s.parse().map_err(|e| format!("amount: {e}")),
        _ => Err("amount must be a number or decimal string".to_string()),
    }
}

fn opt_u128_from<'de, D>(d: D) -> Result<Option<u128>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(d)? {
        None | Some(Value::Null) => None,
        Some(v) => Some(u128_from_value(v).map_err(serde::de::Error::custom)?),
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error_out(msg: &str) -> String {
    serde_json::to_string(&json!({ "error": msg })).unwrap()
}

fn denial(code: Code) -> String {
    error_out(code.as_str())
}

/// Serves JSON lines on a unix socket until the process is killed.
///
/// `manifest` is the owner's manifest, loaded by the caller. Every action is resolved
/// against it, so the agent cannot name a destination the manifest did not issue.
pub fn serve(socket_path: &str, manifest: manifest::Manifest) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    let pdp = pdp::Pdp::load().map_err(|e| e.to_string())?;
    let mut state = ServeState::new(pdp, manifest);
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = handle_client(stream, &mut state);
        }
    }
    Ok(())
}

fn handle_client(stream: UnixStream, state: &mut ServeState) -> std::io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for line in reader.lines() {
        let response = state.handle_line(&line?);
        writeln!(writer, "{response}")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ServeState {
        ServeState::new(pdp::Pdp::load().unwrap(), manifest())
    }

    /// The manifest the tests resolve handles against: one action, two destinations, one
    /// venue — so an unissued handle is easy to express and easy to check.
    fn manifest() -> manifest::Manifest {
        let text = r#"{
            "agent_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expiry_ms":1800000000000,
            "lease_ttl_s":3600,
            "owner":"owner.test.near",
            "permitted_actions":[{"tool":"transfer","tier":"value"}],
            "value":{
                "assets":[{"asset":"near","per_call_cap":5000,"bucket":{"capacity":5000,"refill_per_s":10},
                           "pct_of_balance_cap_bps":10000,"approval_threshold":5000,"degraded_cap":0}],
                "destinations":["alice.test.near","bob.test.near"],
                "venues":[{"id":"venue-a","exposure_cap":10000}]
            }
        }"#;
        serde_json::from_str(text).expect("the fixture manifest must parse")
    }

    fn manifest_hash_hex() -> String {
        let h = manifest::manifest_hash(&manifest()).expect("the fixture manifest must hash");
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A valid action line. The nonce is the only varying field.
    fn action_line(nonce: &str) -> String {
        format!(
            r#"{{"type":"action","agent_id":"{}","session_id":"{}","nonce":"{}","manifest_hash":"{}","context_hash":"{}","contract":"vault.test.near","chain":"near","venue":"venue-a","authority":"full","action":{{"action":0,"dest":1,"amount":"100"}},"issued_ms":1762400000000,"ttl_ms":60000}}"#,
            "aa".repeat(32),
            "01".repeat(16),
            nonce,
            manifest_hash_hex(),
            "22".repeat(32),
        )
    }

    #[test]
    fn a_malformed_line_gets_the_exact_code() {
        let mut s = state();
        assert_eq!(
            s.handle_line("this is not json"),
            format!("{{\"error\":\"{}\"}}", Code::Malformed.as_str())
        );
    }

    #[test]
    fn an_unknown_event_type_is_malformed() {
        let mut s = state();
        assert!(s
            .handle_line(r#"{"type":"nonsense"}"#)
            .contains(Code::Malformed.as_str()));
    }

    #[test]
    fn an_action_missing_its_shape_is_malformed() {
        let mut s = state();
        assert!(s
            .handle_line(r#"{"type":"action"}"#)
            .contains(Code::Malformed.as_str()));
    }

    #[test]
    fn state_reports_the_kernel() {
        let mut s = state();
        let v: Value = serde_json::from_str(&s.handle_line(r#"{"type":"state"}"#)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["policies"], 6);
        assert_eq!(v["outstanding"], 0);
    }

    #[test]
    fn an_unknown_control_command_is_unclassified() {
        let mut s = state();
        let out = s.handle_line(r#"{"type":"control","command":"explode"}"#);
        assert!(out.contains(Code::ActionUnclassified.as_str()), "{out}");
    }

    #[test]
    fn release_expired_is_ok() {
        let mut s = state();
        let v: Value = serde_json::from_str(
            &s.handle_line(r#"{"type":"control","command":"release_expired","now_ms":1000}"#),
        )
        .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["released"], 0);
    }

    #[test]
    fn an_observation_is_recorded() {
        let mut s = state();
        let v: Value =
            serde_json::from_str(&s.handle_line(r#"{"type":"observation","action_hash":"00"}"#))
                .unwrap();
        assert_eq!(v["ok"], true);
        let state: Value = serde_json::from_str(&s.handle_line(r#"{"type":"state"}"#)).unwrap();
        assert_eq!(state["observations"], 1);
    }

    #[test]
    fn a_full_action_is_signed_and_reserved() {
        let mut s = state();
        let v: Value =
            serde_json::from_str(&s.handle_line(&action_line(&"02".repeat(16)))).unwrap();
        assert!(v["receipt"].is_object(), "{v}");
        assert!(v["v"] == 0 || v["v"] == 1, "v was {}", v["v"]);
        let state: Value = serde_json::from_str(&s.handle_line(r#"{"type":"state"}"#)).unwrap();
        assert_eq!(state["reservations"], 1);
        assert_eq!(state["outstanding"], 100);
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let mut s = state();
        let nonce = "02".repeat(16);
        let first = s.handle_line(&action_line(&nonce));
        assert!(first.contains("\"ok\":true"), "{first}");
        let second = s.handle_line(&action_line(&nonce));
        assert!(second.contains(Code::ReceiptReplayed.as_str()), "{second}");
    }

    #[test]
    fn a_denied_action_does_not_reserve() {
        let mut s = state();
        let line = action_line(&"03".repeat(16))
            .replace("\"authority\":\"full\"", "\"authority\":\"askonly\"");
        let out = s.handle_line(&line);
        assert!(out.contains(Code::ActionNotPermitted.as_str()), "{out}");
        let state: Value = serde_json::from_str(&s.handle_line(r#"{"type":"state"}"#)).unwrap();
        assert_eq!(state["reservations"], 0);
    }

    #[test]
    fn an_unissued_action_handle_is_unclassified() {
        let mut s = state();
        let line = action_line(&"04".repeat(16)).replace(
            r#""action":{"action":0,"dest":1,"amount":"100"}"#,
            r#""action":{"action":7,"amount":"1"}"#,
        );
        let out = s.handle_line(&line);
        assert!(out.contains(Code::ActionUnclassified.as_str()), "{out}");
    }

    #[test]
    fn an_unissued_destination_handle_is_unclassified() {
        let mut s = state();
        let line = action_line(&"05".repeat(16)).replace(
            r#""action":{"action":0,"dest":1,"amount":"100"}"#,
            r#""action":{"action":0,"dest":9,"amount":"1"}"#,
        );
        let out = s.handle_line(&line);
        assert!(out.contains(Code::ActionUnclassified.as_str()), "{out}");
    }

    /// The end-to-end form of the claim: an injected `to` is not merely refused by policy,
    /// it is unrepresentable — the schema has no field for it.
    #[test]
    fn an_injected_destination_is_malformed() {
        let mut s = state();
        let line = action_line(&"06".repeat(16)).replace(
            r#""action":{"action":0,"dest":1,"amount":"100"}"#,
            r#""action":{"action":0,"dest":1,"amount":"100","to":"attacker.test.near"}"#,
        );
        let out = s.handle_line(&line);
        assert!(out.contains(Code::Malformed.as_str()), "{out}");
    }

    #[test]
    fn an_unissued_venue_is_unclassified() {
        let mut s = state();
        let line =
            action_line(&"07".repeat(16)).replace(r#""venue":"venue-a""#, r#""venue":"venue-z""#);
        let out = s.handle_line(&line);
        assert!(out.contains(Code::ActionUnclassified.as_str()), "{out}");
    }

    #[test]
    fn a_manifest_hash_that_does_not_match_the_held_manifest_is_refused() {
        let mut s = state();
        let line =
            action_line(&"08".repeat(16)).replace(manifest_hash_hex().as_str(), &"ff".repeat(32));
        let out = s.handle_line(&line);
        assert!(out.contains(Code::ManifestHashMismatch.as_str()), "{out}");
    }
}
