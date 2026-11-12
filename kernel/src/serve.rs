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
use crate::{monitors, pdp, receipt};

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
    action: ValueActionIn,
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
struct ValueActionIn {
    chain: String,
    venue: String,
    to: String,
    asset: String,
    #[serde(deserialize_with = "u128_from")]
    amount: u128,
    #[serde(deserialize_with = "hex_bytes")]
    memo_hash: Vec<u8>,
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
}

impl ServeState {
    pub fn new(pdp: pdp::Pdp) -> Self {
        Self {
            ledger: monitors::SpendLedger::new(),
            pdp,
            observations: Vec::new(),
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
        let memo_hash = match fixed::<32>(&e.action.memo_hash) {
            Ok(v) => v,
            Err(_) => return denial(Code::Malformed),
        };

        let issued_ms = e.issued_ms.unwrap_or_else(now_ms);
        let intent = SignIntent {
            agent_id,
            session_id,
            nonce,
            manifest_hash,
            context_hash,
            action: receipt::ActionInput {
                chain: e.action.chain,
                venue: e.action.venue,
                to: e.action.to,
                asset: e.action.asset,
                amount: e.action.amount,
                memo_hash,
            },
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

fn u128_from<'de, D>(d: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    u128_from_value(Value::deserialize(d)?).map_err(serde::de::Error::custom)
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
pub fn serve(socket_path: &str) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    let pdp = pdp::Pdp::load().map_err(|e| e.to_string())?;
    let mut state = ServeState::new(pdp);
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
        ServeState::new(pdp::Pdp::load().unwrap())
    }

    fn action_line(nonce: &str) -> String {
        format!(
            r#"{{"type":"action","agent_id":"{}","session_id":"{}","nonce":"{}","manifest_hash":"{}","context_hash":"{}","contract":"vault.test.near","authority":"full","action":{{"chain":"near","venue":"venue-a","to":"dest.test.near","asset":"near","amount":100,"memo_hash":"{}"}},"issued_ms":1762400000000,"ttl_ms":60000}}"#,
            "aa".repeat(32),
            "01".repeat(16),
            nonce,
            "11".repeat(32),
            "22".repeat(32),
            "00".repeat(32),
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
}
