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

mod manifest;
mod pdp;
mod receipt;

use std::process::exit;

use arpk_core::MAX_RECEIPT_TTL_MS;
use serde::Serialize;

use crate::receipt::{ActionInput, ReceiptRequest};

const USAGE: &str = "\
arpkd — ARPK kernel (TEE: simulator)

  arpkd public-key
  arpkd manifest-hash --manifest <file.json>
  arpkd sign --chain <id> --contract <account> --agent <hex32> --session <hex16>
              --nonce <hex16> --manifest-hash <hex32> --context-hash <hex32>
              --venue <id> --to <account> --asset <symbol> --amount <u128>
              --memo-hash <hex32> --authority <full|degraded|askonly>
              [--agent-tier <standard|administrative>] [--venue-paused <bool>]
              [--stale <bool>] [--ttl-ms <ms>] [--issued-ms <ms>]

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

#[derive(Serialize)]
struct ActionOut {
    chain: String,
    venue: String,
    to: String,
    asset: String,
    /// NEAR's `U128` serializes as a decimal string.
    amount: String,
    memo_hash: String,
}

#[derive(Serialize)]
struct ReceiptOut {
    agent_id: String,
    session_id: String,
    class: u8,
    action_hash: String,
    manifest_hash: String,
    context_hash: String,
    verdict: u8,
    nonce: String,
    /// NEAR's `U64` serializes as a decimal string.
    issued_ms: String,
    expiry_ms: String,
}

#[derive(Serialize)]
struct SignOutput {
    agent_id: String,
    action: ActionOut,
    receipt: ReceiptOut,
    signature: String,
    v: u8,
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let pdp = pdp::Pdp::load().map_err(|e| e.to_string())?;
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

    let agent_id = fixed::<32>(&unhex(agent_hex, 32, "--agent")?, "--agent")?;
    let session_id = fixed::<16>(&unhex(session_hex, 16, "--session")?, "--session")?;
    let nonce = fixed::<16>(&unhex(nonce_hex, 16, "--nonce")?, "--nonce")?;
    let manifest_hash = fixed::<32>(
        &unhex(manifest_hex, 32, "--manifest-hash")?,
        "--manifest-hash",
    )?;
    let context_hash = fixed::<32>(&unhex(context_hex, 32, "--context-hash")?, "--context-hash")?;
    let memo_hash = fixed::<32>(&unhex(memo_hex, 32, "--memo-hash")?, "--memo-hash")?;

    // The kernel is the policy decision point: it signs only what Cedar permits.
    let entities = pdp::entities(&hex(&agent_id), venue, venue_paused, true, agent_tier);
    // Cedar's `Long` is i64; amounts above it are saturated for the policy check only.
    // The contract's caps remain the bound on the real value.
    let cedar_amount = i64::try_from(amount).unwrap_or(i64::MAX);
    let request = pdp::request(&hex(&agent_id), venue, authority, stale, Some(cedar_amount));
    if let pdp::Verdict::Deny(code) = pdp.evaluate(&request, &entities) {
        return Err(code.as_str().to_string());
    }

    let req = ReceiptRequest {
        action: ActionInput {
            chain: chain.to_string(),
            venue: venue.to_string(),
            to: to.to_string(),
            asset: asset.to_string(),
            amount,
            memo_hash,
        },
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
        agent_id: hex(&signed.receipt.agent_id),
        action: ActionOut {
            chain: chain.to_string(),
            venue: venue.to_string(),
            to: to.to_string(),
            asset: asset.to_string(),
            amount: amount.to_string(),
            memo_hash: hex(&memo_hash),
        },
        receipt: ReceiptOut {
            agent_id: hex(&signed.receipt.agent_id),
            session_id: hex(&signed.receipt.session_id),
            class: signed.receipt.class,
            action_hash: hex(&signed.receipt.action_hash),
            manifest_hash: hex(&signed.receipt.manifest_hash),
            context_hash: hex(&signed.receipt.context_hash),
            verdict: signed.receipt.verdict,
            nonce: hex(&signed.receipt.nonce),
            issued_ms: signed.receipt.issued_ms.to_string(),
            expiry_ms: signed.receipt.expiry_ms.to_string(),
        },
        signature: hex(&signed.signature),
        v: signed.v,
    };
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| e.to_string())?
    );
    Ok(())
}
