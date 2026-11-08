//! Minimal NEAR JSON-RPC client for the kernel's view calls.
//!
//! TLS comes from the system `curl` rather than an HTTP stack in the dependency tree:
//! the kernel makes a handful of view calls per request, and keeping the tree small
//! keeps the attack surface small. The transport sits behind a trait so the parsing and
//! failure paths are testable without a network. Every failure is a denial, never a panic.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::process::Command;

/// A JSON-RPC 2.0 transport: POST a request body, return the response body.
pub trait Transport {
    fn post(&self, endpoint: &str, body: &str) -> Result<String, RpcFailure>;
}

/// The production transport: `curl -s --max-time 20 -X POST`.
pub struct CurlTransport;

impl Transport for CurlTransport {
    fn post(&self, endpoint: &str, body: &str) -> Result<String, RpcFailure> {
        let out = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "20",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                body,
                endpoint,
            ])
            .output()
            .map_err(|e| RpcFailure::Transport(e.to_string()))?;
        if !out.status.success() {
            return Err(RpcFailure::Transport(format!("curl exited {}", out.status)));
        }
        String::from_utf8(out.stdout).map_err(|e| RpcFailure::Transport(e.to_string()))
    }
}

/// Why a view call failed. The caller maps this onto an exact `ARPK:*` code; the RPC
/// layer never invents one.
#[derive(Debug)]
pub enum RpcFailure {
    Transport(String),
    Malformed(String),
    Node { code: i64, message: String },
}

impl std::fmt::Display for RpcFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcFailure::Transport(e) => write!(f, "ARPK:rpc.transport ({e})"),
            RpcFailure::Malformed(e) => write!(f, "ARPK:rpc.malformed ({e})"),
            RpcFailure::Node { code, message } => {
                write!(f, "ARPK:rpc.node ({code}: {message})")
            }
        }
    }
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    #[serde(default)]
    error: Option<RpcNodeError>,
}

#[derive(Deserialize)]
struct RpcNodeError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct QueryResult {
    /// The view method's return value, JSON-encoded by NEAR into a byte array.
    result: Vec<u8>,
}

/// A NEAR JSON-RPC client over a [`Transport`].
pub struct Rpc<T: Transport> {
    endpoint: String,
    transport: T,
}

impl<T: Transport> Rpc<T> {
    pub fn new(endpoint: &str, transport: T) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            transport,
        }
    }

    /// Calls a contract view method and returns its JSON return value.
    pub fn view_call<D: DeserializeOwned>(
        &self,
        account: &str,
        method: &str,
        args: &serde_json::Value,
    ) -> Result<D, RpcFailure> {
        let args_json =
            serde_json::to_string(args).map_err(|e| RpcFailure::Malformed(e.to_string()))?;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "arpkd",
            "method": "query",
            "params": {
                "request_type": "call_function",
                "account_id": account,
                "method_name": method,
                "args_base64": b64(args_json.as_bytes()),
                "finality": "optimistic",
            }
        });
        let body =
            serde_json::to_string(&body).map_err(|e| RpcFailure::Malformed(e.to_string()))?;
        let raw = self.transport.post(&self.endpoint, &body)?;
        let env: RpcEnvelope<QueryResult> =
            serde_json::from_str(&raw).map_err(|e| RpcFailure::Malformed(e.to_string()))?;
        if let Some(err) = env.error {
            return Err(RpcFailure::Node {
                code: err.code,
                message: err.message,
            });
        }
        let qr = env
            .result
            .ok_or_else(|| RpcFailure::Malformed("missing result field".into()))?;
        serde_json::from_slice(&qr.result).map_err(|e| RpcFailure::Malformed(e.to_string()))
    }
}

/// Standard base64 with padding — NEAR's `args_base64` format.
fn b64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        body: String,
    }
    impl Transport for Mock {
        fn post(&self, _endpoint: &str, _body: &str) -> Result<String, RpcFailure> {
            Ok(self.body.clone())
        }
    }

    fn envelope(inner: &serde_json::Value) -> String {
        let bytes = serde_json::to_string(&inner.to_string().into_bytes()).unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":"arpkd","result":{{"block_hash":"x","block_height":1,"logs":[],"result":{bytes}}}}}"#
        )
    }

    #[test]
    fn view_call_decodes_the_return_value() {
        let rpc: Rpc<Mock> = Rpc::new(
            "http://localhost:3030",
            Mock {
                body: envelope(&serde_json::json!({"ledger": "1000"})),
            },
        );
        let v: serde_json::Value = rpc
            .view_call("vault.test.near", "ledger", &serde_json::json!({}))
            .unwrap();
        assert_eq!(v["ledger"], "1000");
    }

    #[test]
    fn a_malformed_response_is_an_error_not_a_panic() {
        let rpc: Rpc<Mock> = Rpc::new(
            "http://localhost:3030",
            Mock {
                body: "not json at all".to_string(),
            },
        );
        let err = rpc
            .view_call::<serde_json::Value>("vault.test.near", "ledger", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RpcFailure::Malformed(_)), "{err:?}");
    }

    #[test]
    fn a_node_error_is_surfaced() {
        let rpc: Rpc<Mock> = Rpc::new(
            "http://localhost:3030",
            Mock {
                body: r#"{"jsonrpc":"2.0","id":"arpkd","error":{"code":-32000,"message":"account not found"}}"#
                    .to_string(),
            },
        );
        let err = rpc
            .view_call::<serde_json::Value>("missing.test.near", "ledger", &serde_json::json!({}))
            .unwrap_err();
        match err {
            RpcFailure::Node { code, message } => {
                assert_eq!(code, -32000);
                assert_eq!(message, "account not found");
            }
            other => panic!("expected a node error, got {other:?}"),
        }
    }

    #[test]
    fn base64_matches_the_standard_encoding() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64(b"hel"), "aGVs");
        assert_eq!(b64(&[0u8, 0, 1]), "AAAB");
    }
}
