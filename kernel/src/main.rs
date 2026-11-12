//! `arpkd` — the ARPK kernel daemon (TEE: simulator).
//!
//! WP1b ships the CLI first: it is the minimum the plan's cut rule keeps. `serve` and
//! the live monitors follow.
//!
//! - `public-key`    — print the 64-byte kernel key the contract registers
//! - `manifest-hash` — canonicalize a manifest file, print its on-chain hash
//! - `sign`          — evaluate the Cedar PDP, then sign; prints one JSON line that is
//!   exactly the argument list of the vault's `execute_value`
//!
//! Denials always carry an exact `ARPK:*` code.

use std::process::exit;

use arpk_core::codes::Code;
use arpk_core::MAX_RECEIPT_TTL_MS;
use arpk_kernel::receipt::{self, ActionInput, ReceiptRequest};
use arpk_kernel::{enforce, manifest, monitors, pdp, rpc, serve};
use serde::Serialize;

const USAGE: &str = "\
arpkd — ARPK kernel (TEE: simulator)

  arpkd public-key
  arpkd manifest-hash --manifest <file.json>
  arpkd agent --rpc <url> --contract <account> --agent <hex32> [--now-ms <ms>]
  arpkd serve --socket <path>
  arpkd sign --chain <id> --contract <account> --agent <hex32> --session <hex16>
              --nonce <hex16> --manifest-hash <hex32> --context-hash <hex32>
              --venue <id> --to <account> --asset <symbol> --amount <u128>
              --memo-hash <hex32> --authority <full|degraded|askonly>
              [--agent-tier <standard|administrative>] [--venue-paused <bool>]
              [--stale <bool>] [--ttl-ms <ms>] [--issued-ms <ms>]
              [--agent-expiry-ms <ms>] [--exposure <u128>] [--exposure-cap <u128>]
              [--approval-threshold <u128>] [--approval-expiry-ms <ms>]

Amounts and timestamps are decimal. Hashes are 0x-prefixed or bare hex.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        exit(2);
    }
    let result = match args[0].as_str() {
        "public-key" => cmd_public_key(),
        "manifest-hash" => cmd_manifest_hash(&args[1..]),
        "agent" => cmd_agent(&args[1..]),
        "serve" => cmd_serve(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        other => Err(format!("unknown command '{other}'")),
    };
    if let Err(e) = result {
        eprintln!("arpkd: {e}");
        exit(1);
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str, len: usize, what: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != len * 2 {
        return Err(format!(
            "{what}: expected {len} bytes ({} hex chars), got {}",
            len * 2,
            s.len()
        ));
    }
    (0..len)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("{what}: {e}")))
        .collect()
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    arg(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn bool_arg(args: &[String], name: &str, default: bool) -> Result<bool, String> {
    match arg(args, name) {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(format!("{name}: expected true or false, got '{other}'")),
        None => Ok(default),
    }
}

fn fixed<const N: usize>(v: &[u8], what: &str) -> Result<[u8; N], String> {
    v.try_into()
        .map_err(|_| format!("{what}: expected {N} bytes, got {}", v.len()))
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn cmd_public_key() -> Result<(), String> {
    let key = receipt::KernelKey::simulator().map_err(|e| e.to_string())?;
    println!("{}", hex(key.public_key()));
    Ok(())
}

fn cmd_manifest_hash(args: &[String]) -> Result<(), String> {
    let path = required(args, "--manifest")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let m: manifest::Manifest =
        serde_json::from_str(&text).map_err(|e| format!("parse manifest: {e}"))?;
    let canonical = manifest::canonical_manifest_json(&m).map_err(|e| e.to_string())?;
    eprintln!("canonical: {canonical}");
    println!(
        "{}",
        hex(&manifest::manifest_hash(&m).map_err(|e| e.to_string())?)
    );
    Ok(())
}

/// The argument list of the vault's `execute_value`, encoded exactly as the contract's
/// serde DTOs expect: byte fields are JSON arrays (not hex), `U128`/`U64` are strings.
#[derive(Serialize)]
struct ActionOut {
    chain: String,
    venue: String,
    to: String,
    asset: String,
    amount: String,
    memo_hash: Vec<u8>,
}

#[derive(Serialize)]
struct ReceiptOut {
    agent_id: Vec<u8>,
    session_id: Vec<u8>,
    class: u8,
    action_hash: Vec<u8>,
    manifest_hash: Vec<u8>,
    context_hash: Vec<u8>,
    verdict: u8,
    nonce: Vec<u8>,
    issued_ms: String,
    expiry_ms: String,
}

#[derive(Serialize)]
struct SignOutput {
    agent_id: Vec<u8>,
    action: ActionOut,
    receipt: ReceiptOut,
    signature: Vec<u8>,
    v: u8,
}

/// Fetches an agent record from the vault and checks its lease. The relayer uses this to
/// fill the lease monitor's snapshot; a missing record or a stale lease denies.
fn cmd_agent(args: &[String]) -> Result<(), String> {
    let rpc_url = required(args, "--rpc")?;
    let contract = required(args, "--contract")?;
    let agent_hex = required(args, "--agent")?;
    let now_ms: u64 = match arg(args, "--now-ms") {
        Some(v) => v.parse().map_err(|e| format!("--now-ms: {e}"))?,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64,
    };
    let agent_id = fixed::<32>(&unhex(agent_hex, 32, "--agent")?, "--agent")?;
    let client: rpc::Rpc<rpc::CurlTransport> = rpc::Rpc::new(rpc_url, rpc::CurlTransport);
    let agent: serde_json::Value = client
        .view_call(
            contract,
            "get_agent",
            &serde_json::json!({ "agent_id": agent_id }),
        )
        .map_err(|e| e.to_string())?;
    if agent.is_null() {
        return Err(Code::ManifestMissing.as_str().to_string());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&agent).map_err(|e| e.to_string())?
    );
    let expiry_ms = agent
        .get("expiry_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "agent record has no expiry_ms".to_string())?;
    monitors::check_lease(expiry_ms, now_ms).map_err(|e| e.as_str().to_string())?;
    Ok(())
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let socket = required(args, "--socket")?;
    serve::serve(socket)
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let pdp = pdp::Pdp::load().map_err(|e| e.to_string())?;
    eprintln!(
        "arpkd: PDP validated ({} policies); TEE=simulator",
        pdp.policy_count()
    );
    let key = receipt::KernelKey::simulator().map_err(|e| e.to_string())?;

    let chain = required(args, "--chain")?;
    let contract = required(args, "--contract")?;
    let agent_hex = required(args, "--agent")?;
    let session_hex = required(args, "--session")?;
    let nonce_hex = required(args, "--nonce")?;
    let manifest_hex = required(args, "--manifest-hash")?;
    let context_hex = required(args, "--context-hash")?;
    let memo_hex = required(args, "--memo-hash")?;
    let venue = required(args, "--venue")?;
    let to = required(args, "--to")?;
    let asset = required(args, "--asset")?;
    let amount: u128 = required(args, "--amount")?
        .parse()
        .map_err(|e| format!("--amount: {e}"))?;
    let authority = required(args, "--authority")?;
    let agent_tier = arg(args, "--agent-tier").unwrap_or("standard");
    let venue_paused = bool_arg(args, "--venue-paused", false)?;
    let stale = bool_arg(args, "--stale", false)?;
    let ttl_ms: u64 = match arg(args, "--ttl-ms") {
        Some(v) => v.parse().map_err(|e| format!("--ttl-ms: {e}"))?,
        None => MAX_RECEIPT_TTL_MS,
    };
    let issued_ms: u64 = match arg(args, "--issued-ms") {
        Some(v) => v.parse().map_err(|e| format!("--issued-ms: {e}"))?,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64,
    };
    // Monitor snapshots. The relayer and `serve` fill these from RPC view calls; the CLI
    // takes them as arguments so the same enforcement path is exercisable standalone.
    let agent_expiry_ms: u64 = match arg(args, "--agent-expiry-ms") {
        Some(v) => v.parse().map_err(|e| format!("--agent-expiry-ms: {e}"))?,
        None => u64::MAX,
    };
    let exposure: u128 = match arg(args, "--exposure") {
        Some(v) => v.parse().map_err(|e| format!("--exposure: {e}"))?,
        None => 0,
    };
    let exposure_cap: u128 = match arg(args, "--exposure-cap") {
        Some(v) => v.parse().map_err(|e| format!("--exposure-cap: {e}"))?,
        None => u128::MAX,
    };
    let approval_threshold: u128 = match arg(args, "--approval-threshold") {
        Some(v) => v
            .parse()
            .map_err(|e| format!("--approval-threshold: {e}"))?,
        None => u128::MAX,
    };
    let degraded_cap: u128 = match arg(args, "--degraded-cap") {
        Some(v) => v.parse().map_err(|e| format!("--degraded-cap: {e}"))?,
        None => 0,
    };
    let approval_expiry_ms: Option<u64> = match arg(args, "--approval-expiry-ms") {
        Some(v) => Some(
            v.parse()
                .map_err(|e| format!("--approval-expiry-ms: {e}"))?,
        ),
        None => None,
    };

    let agent_id = fixed::<32>(&unhex(agent_hex, 32, "--agent")?, "--agent")?;
    let session_id = fixed::<16>(&unhex(session_hex, 16, "--session")?, "--session")?;
    let nonce = fixed::<16>(&unhex(nonce_hex, 16, "--nonce")?, "--nonce")?;
    let manifest_hash = fixed::<32>(
        &unhex(manifest_hex, 32, "--manifest-hash")?,
        "--manifest-hash",
    )?;
    let context_hash = fixed::<32>(&unhex(context_hex, 32, "--context-hash")?, "--context-hash")?;
    let memo_hash = fixed::<32>(&unhex(memo_hex, 32, "--memo-hash")?, "--memo-hash")?;

    // The kernel is the policy decision point: it signs only what the Cedar PDP and the
    // monitors permit. `serve` runs the same path.
    let action = ActionInput {
        chain: chain.to_string(),
        venue: venue.to_string(),
        to: to.to_string(),
        asset: asset.to_string(),
        amount,
        memo_hash,
    };
    let intent = enforce::SignIntent {
        agent_id,
        session_id,
        nonce,
        manifest_hash,
        context_hash,
        action: action.clone(),
        authority: authority.to_string(),
        agent_tier: agent_tier.to_string(),
        venue_paused,
        stale,
        ttl_ms,
        issued_ms,
        agent_expiry_ms,
        exposure,
        exposure_cap,
        approval_threshold,
        degraded_cap,
        approval_expiry_ms,
    };
    enforce::enforce(&pdp, &intent).map_err(|e| e.as_str().to_string())?;

    let req = ReceiptRequest {
        action,
        agent_id,
        session_id,
        manifest_hash,
        context_hash,
        nonce,
        issued_ms,
        ttl_ms,
    };
    let signed = receipt::sign_value(key.signing_key(), &receipt::domain(chain, contract), &req)
        .map_err(|e| e.to_string())?;

    let out = SignOutput {
        agent_id: signed.receipt.agent_id.to_vec(),
        action: ActionOut {
            chain: chain.to_string(),
            venue: venue.to_string(),
            to: to.to_string(),
            asset: asset.to_string(),
            amount: amount.to_string(),
            memo_hash: memo_hash.to_vec(),
        },
        receipt: ReceiptOut {
            agent_id: signed.receipt.agent_id.to_vec(),
            session_id: signed.receipt.session_id.to_vec(),
            class: signed.receipt.class,
            action_hash: signed.action_hash.to_vec(),
            manifest_hash: signed.receipt.manifest_hash.to_vec(),
            context_hash: signed.receipt.context_hash.to_vec(),
            verdict: signed.receipt.verdict,
            nonce: signed.receipt.nonce.to_vec(),
            issued_ms: signed.receipt.issued_ms.to_string(),
            expiry_ms: signed.receipt.expiry_ms.to_string(),
        },
        signature: signed.signature.clone(),
        v: signed.v,
    };
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| e.to_string())?
    );
    Ok(())
}
