#![cfg(feature = "sandbox")]
//! CI-only end-to-end: intent → kernel receipt → on-chain transfer.
//!
//! This file compiles only under the `sandbox` feature, which pulls in near-workspaces.
//! The near-sandbox binary is glibc-only, so it cannot run on Termux/Bionic — the CI
//! workflow builds the wasm and runs this job on Ubuntu.
//!
//! The receipt submitted here is the one the kernel library actually produces: this file
//! links `arpk_kernel` rather than reimplementing the signing path, so a drift between the
//! kernel and the contract fails this test instead of being papered over.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use near_workspaces::types::{AccessKey, KeyType, NearToken, SecretKey};
use near_workspaces::Contract;
use serde_json::{json, Value};

use arpk_core::eip712::{self, Receipt as CoreReceipt, ValueAction};
use arpk_core::{class, verdict, MAX_RECEIPT_TTL_MS};
use arpk_kernel::enforce::{self, SignIntent};
use arpk_kernel::pdp;
use arpk_kernel::receipt::{self, ActionInput, ReceiptRequest};

/// The wasm this crate builds. CI builds it before running the e2e job.
fn wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/wasm32-unknown-unknown/release/near_vault.wasm")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_millis() as u64
}

/// A deterministic, valid secp256k1 scalar for the simulator kernel key. The contract is
/// told this key's 64-byte public form, exactly as a real deployment would register it.
const KERNEL_KEY: [u8; 32] = [7u8; 32];

const AGENT_ID: [u8; 32] = [0xAB; 32];
const MANIFEST_HASH: [u8; 32] = [0xCD; 32];
const SESSION_ID: [u8; 16] = [0x11; 16];
const CONTEXT_HASH: [u8; 32] = [0x22; 32];
const MEMO_HASH: [u8; 32] = [0x33; 32];

const VENUE: &str = "venue-a";
const ASSET: &str = "near";

/// 1 NEAR in yoctoNEAR.
const YOCTO: u128 = 1_000_000_000_000_000_000_000_000;

/// Sandbox dev accounts start with 100 NEAR, and the owner pays gas for the owner calls
/// *and* funds the vault — so the deposit has to leave room for that.
const DEPOSIT: u128 = 50 * YOCTO;
const AMOUNT: u128 = YOCTO;
const PER_CALL_CAP: u128 = 10 * YOCTO;
const BUCKET_CAPACITY: u128 = 100 * YOCTO;
const APPROVAL_THRESHOLD: u128 = 1_000 * YOCTO;
const EXPOSURE_CAP: u128 = 1_000 * YOCTO;

const AGENT_EXPIRY_MS: u64 = 3_600_000;

struct Kit {
    contract: Contract,
    #[allow(dead_code)]
    owner: near_workspaces::Account,
    relayer: near_workspaces::Account,
    recipient: near_workspaces::Account,
    agent_id: [u8; 32],
    manifest_hash: [u8; 32],
    kernel: receipt::KernelKey,
    pdp: pdp::Pdp,
    chain: String,
}

async fn setup() -> anyhow::Result<Kit> {
    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read(wasm_path())
        .map_err(|e| anyhow::anyhow!("read wasm at {}: {e}", wasm_path().display()))?;

    let owner = worker.dev_create_account().await?;
    let contract = worker.dev_deploy(&wasm).await?;

    contract
        .call("new")
        .args_json(json!({ "owner": owner.id() }))
        .transact()
        .await?
        .into_result()?;

    let kernel = receipt::KernelKey::from_bytes(&KERNEL_KEY)?;
    let agent_id = AGENT_ID;
    let manifest_hash = MANIFEST_HASH;

    // Owner methods require exactly 1 yocto, which is what makes a function-call key
    // incapable of reaching them.
    // Owner methods must be called by the owner account: `contract.call(...)` signs as
    // the contract's own account, which fails `assert_owner()`.
    owner
        .call(contract.id(), "register_manifest")
        .args_json(json!({
            "agent_id": agent_id,
            "manifest_hash": manifest_hash,
            "expiry_ms": (now_ms() + AGENT_EXPIRY_MS).to_string(),
            "assets": [{
                "asset": ASSET,
                "per_call_cap": PER_CALL_CAP.to_string(),
                "pct_cap_bps": "10000",
                "approval_threshold": APPROVAL_THRESHOLD.to_string(),
                "bucket_capacity": BUCKET_CAPACITY.to_string(),
                // Zero refill: the assertion below checks the bucket moved by *exactly*
                // the transferred amount, and a live refill would add a few hundred yocto
                // between the two reads.
                "bucket_refill_per_s": "0",
            }],
            "venues": [{ "venue": VENUE, "exposure_cap": EXPOSURE_CAP.to_string() }],
        }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;

    owner
        .call(contract.id(), "register_kernel_key")
        .args_json(json!({
            "public_key": kernel.public_key(),
            "expiry_ms": (now_ms() + AGENT_EXPIRY_MS).to_string(),
        }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;

    owner
        .call(contract.id(), "deposit")
        .deposit(NearToken::from_yoctonear(DEPOSIT))
        .transact()
        .await?
        .into_result()?;

    let recipient = worker.dev_create_account().await?;

    // The relayer authenticates with a function-call key restricted to `execute_value` on
    // this vault. A leaked relayer key can only submit receipts the kernel already signed.
    let mut relayer = worker.dev_create_account().await?;
    let fc_sk = SecretKey::from_seed(KeyType::ED25519, "arpk-relayer-fc");
    relayer
        .batch(relayer.id())
        .add_key(
            fc_sk.public_key(),
            AccessKey::function_call_access(contract.id(), &["execute_value"], None),
        )
        .transact()
        .await?
        .into_result()?;
    relayer.set_secret_key(fc_sk);

    // The kernel must build the same EIP-712 domain separator as the contract, and the
    // salt includes the chain id. Read it from the contract rather than assuming: the
    // sandbox's chain id is not something the test should have to know.
    let chain: String = contract.view("chain_id").await?.json()?;

    Ok(Kit {
        contract,
        owner,
        relayer,
        recipient,
        agent_id,
        manifest_hash,
        kernel,
        pdp: pdp::Pdp::load()?,
        chain,
    })
}

/// Everything that varies between the happy path and the negatives.
struct IntentSpec {
    /// `None` means the kit's recipient account. Overridden only to test a bad destination.
    to: Option<String>,
    amount: u128,
    nonce: [u8; 16],
    ttl_ms: u64,
    /// Skip the kernel's own guards and sign anyway — used to prove the contract enforces
    /// the TTL independently of the kernel.
    craft_raw: bool,
}

impl IntentSpec {
    fn new(nonce_byte: u8) -> Self {
        Self {
            to: None,
            amount: AMOUNT,
            nonce: [nonce_byte; 16],
            ttl_ms: MAX_RECEIPT_TTL_MS,
            craft_raw: false,
        }
    }
}

/// Runs the kernel's real enforcement path and signs, then shapes the result as the
/// `execute_value` argument list (byte fields as JSON arrays, `U128`/`U64` as strings).
///
/// `key` is passed separately so the negatives can sign with a key the contract never
/// registered, without rebuilding the whole kit.
fn kernel_sign(kit: &Kit, key: &receipt::KernelKey, spec: &IntentSpec) -> anyhow::Result<Value> {
    let issued_ms = now_ms();
    let to = spec
        .to
        .clone()
        .unwrap_or_else(|| kit.recipient.id().to_string());
    let action = ActionInput {
        chain: kit.chain.clone(),
        venue: VENUE.to_string(),
        to: to.clone(),
        asset: ASSET.to_string(),
        amount: spec.amount,
        memo_hash: MEMO_HASH,
    };

    let (receipt_json, signature, v) = if spec.craft_raw {
        // Deliberately bypass the kernel's TTL guard so the contract's own check is what
        // is under test.
        let expiry_ms = issued_ms + MAX_RECEIPT_TTL_MS + 1;
        let action_hash = eip712::hash_value_action(
            &receipt::Sha3,
            &ValueAction {
                chain: action.chain.clone(),
                venue: action.venue.clone(),
                to: action.to.clone(),
                asset: action.asset.clone(),
                amount: action.amount,
                memo_hash: action.memo_hash,
            },
        );
        let core = CoreReceipt {
            agent_id: kit.agent_id,
            session_id: SESSION_ID,
            class: class::VALUE,
            action_hash,
            manifest_hash: kit.manifest_hash,
            context_hash: CONTEXT_HASH,
            verdict: verdict::ALLOW,
            nonce: spec.nonce,
            issued_ms,
            expiry_ms,
        };
        let digest = eip712::digest(
            &receipt::Sha3,
            &receipt::domain(&kit.chain, kit.contract.id().as_str()),
            &core,
        );
        let (sig, recid) = key.signing_key().sign_prehash_recoverable(&digest);
        (
            json!({
                "agent_id": core.agent_id,
                "session_id": core.session_id,
                "class": core.class,
                "action_hash": core.action_hash,
                "manifest_hash": core.manifest_hash,
                "context_hash": core.context_hash,
                "verdict": core.verdict,
                "nonce": core.nonce,
                "issued_ms": core.issued_ms.to_string(),
                "expiry_ms": core.expiry_ms.to_string(),
            }),
            sig.to_bytes().to_vec(),
            recid.to_byte(),
        )
    } else {
        let intent = SignIntent {
            agent_id: kit.agent_id,
            session_id: SESSION_ID,
            nonce: spec.nonce,
            manifest_hash: kit.manifest_hash,
            context_hash: CONTEXT_HASH,
            action: action.clone(),
            authority: "full".to_string(),
            agent_tier: "standard".to_string(),
            venue_paused: false,
            stale: false,
            ttl_ms: spec.ttl_ms,
            issued_ms,
            agent_expiry_ms: issued_ms + AGENT_EXPIRY_MS,
            exposure: 0,
            exposure_cap: EXPOSURE_CAP,
            approval_threshold: u128::MAX,
            approval_expiry_ms: None,
        };
        enforce::enforce(&kit.pdp, &intent)
            .map_err(|e| anyhow::anyhow!("kernel denied the intent: {}", e.as_str()))?;

        let req = ReceiptRequest {
            action: action.clone(),
            agent_id: kit.agent_id,
            session_id: SESSION_ID,
            manifest_hash: kit.manifest_hash,
            context_hash: CONTEXT_HASH,
            nonce: spec.nonce,
            issued_ms,
            ttl_ms: spec.ttl_ms,
        };
        let signed = receipt::sign_value(
            key.signing_key(),
            &receipt::domain(&kit.chain, kit.contract.id().as_str()),
            &req,
        )
        .map_err(|e| anyhow::anyhow!("kernel refused to sign: {e}"))?;
        let r = &signed.receipt;
        (
            json!({
                "agent_id": r.agent_id,
                "session_id": r.session_id,
                "class": r.class,
                "action_hash": r.action_hash,
                "manifest_hash": r.manifest_hash,
                "context_hash": r.context_hash,
                "verdict": r.verdict,
                "nonce": r.nonce,
                "issued_ms": r.issued_ms.to_string(),
                "expiry_ms": r.expiry_ms.to_string(),
            }),
            signed.signature.clone(),
            signed.v,
        )
    };

    Ok(json!({
        "agent_id": kit.agent_id,
        "action": {
            "chain": kit.chain,
            "venue": VENUE,
            "to": to,
            "asset": ASSET,
            "amount": spec.amount.to_string(),
            "memo_hash": MEMO_HASH,
        },
        "receipt": receipt_json,
        "signature": signature,
        "v": v,
    }))
}

/// The agent's remaining bucket tokens and venue exposure, read back from the chain.
async fn agent_state(kit: &Kit) -> anyhow::Result<(u128, u128)> {
    let agent: Value = kit
        .contract
        .view("get_agent")
        .args_json(json!({ "agent_id": kit.agent_id }))
        .await?
        .json()?;
    let tokens = agent["assets"][0]["bucket_tokens"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bucket_tokens is not a string: {agent}"))?
        .parse::<u128>()?;
    let exposure = agent["venues"][0]["exposure"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("exposure is not a string: {agent}"))?
        .parse::<u128>()?;
    Ok((tokens, exposure))
}

async fn submit(kit: &Kit, args: &Value) -> anyhow::Result<()> {
    kit.relayer
        .call(kit.contract.id(), "execute_value")
        .args_json(args)
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

/// Submit and report either success or the exact rejection, without asserting which.
async fn try_submit(kit: &Kit, args: &Value) -> Result<(), String> {
    match kit
        .relayer
        .call(kit.contract.id(), "execute_value")
        .args_json(args)
        .transact()
        .await
    {
        Ok(exec) => match exec.into_result() {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{e:?}")),
        },
        Err(e) => Err(format!("{e:?}")),
    }
}

async fn submit_err(kit: &Kit, args: &Value) -> String {
    let err = kit
        .relayer
        .call(kit.contract.id(), "execute_value")
        .args_json(args)
        .transact()
        .await
        .expect("the transaction should be submitted")
        .into_result()
        .expect_err("the contract should reject this");
    format!("{err}")
}

#[tokio::test]
async fn intent_to_receipt_to_on_chain_transfer() -> anyhow::Result<()> {
    let kit = setup().await?;

    let (tokens_before, exposure_before) = agent_state(&kit).await?;
    assert_eq!(exposure_before, 0, "a fresh agent has no venue exposure");

    // P0: the agent names an intent, the kernel signs it, the relayer submits it, value
    // moves on-chain.
    let args = kernel_sign(&kit, &kit.kernel, &IntentSpec::new(1))?;
    submit(&kit, &args).await?;

    let (tokens_after, exposure_after) = agent_state(&kit).await?;
    assert_eq!(
        tokens_before - tokens_after,
        AMOUNT,
        "exactly the transferred amount is consumed from the bucket"
    );
    assert_eq!(
        exposure_after - exposure_before,
        AMOUNT,
        "exactly the transferred amount is added to the venue exposure"
    );

    // B03: the same receipt cannot be spent twice.
    let replay = submit_err(&kit, &args).await;
    assert!(
        replay.contains("ARPK:receipt.replayed"),
        "replay must be rejected with the exact code, got: {replay}"
    );

    // B06: tampering with the amount breaks the action-hash binding.
    let mut tampered = args.clone();
    tampered["action"]["amount"] = json!((AMOUNT + 1).to_string());
    let tamper_err = submit_err(&kit, &tampered).await;
    assert!(
        tamper_err.contains("ARPK:receipt.action_hash_mismatch"),
        "a tampered amount must be rejected with the exact code, got: {tamper_err}"
    );

    // B20: the contract enforces the max TTL on-chain, independently of the kernel.
    let mut over_ttl = IntentSpec::new(2);
    over_ttl.craft_raw = true;
    let over_ttl_args = kernel_sign(&kit, &kit.kernel, &over_ttl)?;
    let ttl_err = submit_err(&kit, &over_ttl_args).await;
    assert!(
        ttl_err.contains("ARPK:receipt.ttl_too_long"),
        "an over-TTL receipt must be rejected on-chain, got: {ttl_err}"
    );

    // B21: a receipt signed by a key the contract never registered.
    let stranger = receipt::KernelKey::from_bytes(&[9u8; 32])?;
    let stranger_args = kernel_sign(&kit, &stranger, &IntentSpec::new(3))?;
    let key_err = submit_err(&kit, &stranger_args).await;
    assert!(
        key_err.contains("ARPK:receipt.key_invalid"),
        "an unregistered kernel key must be rejected, got: {key_err}"
    );

    // B07: revocation is immediate on-chain.
    kit.owner
        .call(kit.contract.id(), "revoke_agent")
        .args_json(json!({ "agent_id": kit.agent_id }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    let revoked_args = kernel_sign(&kit, &kit.kernel, &IntentSpec::new(4))?;
    let revoke_err = submit_err(&kit, &revoked_args).await;
    assert!(
        revoke_err.contains("ARPK:manifest.revoked"),
        "a revoked agent must be rejected, got: {revoke_err}"
    );

    Ok(())
}

#[tokio::test]
async fn twenty_transfers_stop_at_the_bucket_bound() -> anyhow::Result<()> {
    let kit = setup().await?;
    let (tokens_before, _) = agent_state(&kit).await?;

    // 10 NEAR per call (the per-call cap) against a 100 NEAR bucket with no refill: the
    // first ten must succeed and everything after must be denied by the bucket. That is
    // the bound over a sequence, not a single transfer.
    let amount = 10 * YOCTO;
    let mut accepted = 0u32;
    let mut denied = 0u32;

    for i in 0..20u8 {
        let spec = IntentSpec {
            amount,
            ..IntentSpec::new(200 + i)
        };
        let args = kernel_sign(&kit, &kit.kernel, &spec)?;
        match try_submit(&kit, &args).await {
            Ok(()) => accepted += 1,
            Err(msg) => {
                assert!(
                    msg.contains("ARPK:value.bucket_exceeded"),
                    "step {i}: expected the bucket to deny, got {msg}"
                );
                denied += 1;
            }
        }
    }

    assert_eq!(accepted, 10, "exactly the bucket capacity is spendable");
    assert_eq!(denied, 10, "everything past the bound is denied");

    let (tokens_after, _) = agent_state(&kit).await?;
    assert_eq!(
        tokens_before - tokens_after,
        amount * accepted as u128,
        "the bucket moved by exactly what was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn the_relayer_key_cannot_reach_an_owner_method() -> anyhow::Result<()> {
    let kit = setup().await?;

    // The relayer's function-call key is restricted to `execute_value`. Calling an owner
    // method with it must be rejected at the protocol level (`MethodNameMismatch`), before
    // the contract's own 1-yocto check is ever reached.
    //
    // That rejection surfaces as a broadcast error rather than an execution failure, so
    // both shapes are captured.
    let msg = match kit
        .relayer
        .call(kit.contract.id(), "revoke_agent")
        .args_json(json!({ "agent_id": kit.agent_id }))
        .transact()
        .await
    {
        Ok(exec) => match exec.into_result() {
            Ok(_) => panic!("a function-call key must not reach an owner method"),
            Err(e) => format!("{e:?}"),
        },
        Err(e) => format!("{e:?}"),
    };
    assert!(
        msg.contains("MethodNameMismatch") || msg.contains("ARPK:owner.required"),
        "the relayer key must be stopped before an owner method runs, got: {msg}"
    );

    Ok(())
}
