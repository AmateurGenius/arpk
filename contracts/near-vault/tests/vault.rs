//! WP1a battery: B02-B08, B17-B21, B24-B26.
//!
//! Every test asserts an exact `ARPK:*` reason code. A test that merely asserts "it
//! failed" is a smoke test and is not written here.

use arpk_core::eip712::{self, Domain, Receipt as CoreReceipt, ValueAction as CoreAction};
use arpk_core::{class, verdict, Keccak};
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use near_sdk::json_types::{U128, U64};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use near_sdk::{AccountId, NearToken};
use sha3::{Digest, Keccak256};

use near_vault::{AssetCapsDto, ReceiptDto, ValueActionDto, Vault, VenueCapDto};

const MS: u64 = 1_000_000;
const BASE_TS_MS: u64 = 1_762_400_000_000;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct Sha3;
impl Keccak for Sha3 {
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(data);
        h.finalize().into()
    }
}

fn account(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn to32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

fn to16(v: &[u8]) -> [u8; 16] {
    v.try_into().unwrap()
}

/// Build a context with an explicit predecessor, deposit and timestamp.
fn ctx(predecessor: AccountId, deposit: u128, ts_ms: u64) -> VMContextBuilder {
    let mut ctx = VMContextBuilder::new();
    ctx.current_account_id(account("vault.test.near"));
    ctx.signer_account_id(predecessor.clone());
    ctx.predecessor_account_id(predecessor);
    ctx.block_timestamp(ts_ms * MS);
    ctx.account_balance(NearToken::from_yoctonear(10u128.pow(27)));
    ctx.account_locked_balance(NearToken::from_yoctonear(0));
    ctx.attached_deposit(NearToken::from_yoctonear(deposit));
    ctx
}

struct Env {
    contract: Vault,
    kernel: SigningKey,
    kernel_pub: Vec<u8>,
    agent_id: Vec<u8>,
    manifest_hash: [u8; 32],
}

fn deploy() -> Env {
    let owner = account("owner.test.near");
    testing_env!(ctx(owner.clone(), 0, BASE_TS_MS).build());
    let mut contract = Vault::new(owner.clone());

    // Deterministic kernel signing key (never a real key).
    let kernel = SigningKey::from_slice(&[7u8; 32]).unwrap();
    // Uncompressed SEC1 (65 bytes: 0x04 || X || Y); ecrecover returns X || Y (64 bytes).
    let vk = kernel.verifying_key().to_sec1_point(false);
    let kernel_pub = vk.as_bytes()[1..].to_vec();

    // Register the kernel key as owner with 1 yocto.
    testing_env!(ctx(owner.clone(), 1, BASE_TS_MS).build());
    contract.register_kernel_key(kernel_pub.clone(), U64(BASE_TS_MS + 3_600_000));

    // agent_id must be 32 bytes: it is a receipt field, not a string.
    let agent_id = Sha3.keccak256(b"agent-0").to_vec();
    let manifest_hash = Sha3.keccak256(b"manifest-0");

    let assets = vec![AssetCapsDto {
        asset: "near".to_string(),
        per_call_cap: U128(1_000),
        pct_cap_bps: U128(10_000),
        approval_threshold: U128(5_000),
        bucket_capacity: U128(1_000),
        bucket_refill_per_s: U128(0),
    }];
    let venues = vec![VenueCapDto {
        venue: "venue-a".to_string(),
        exposure_cap: U128(10_000),
    }];

    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    contract.register_manifest(
        agent_id.clone(),
        manifest_hash,
        U64(BASE_TS_MS + 3_600_000),
        assets,
        venues,
    );

    // Fund the ledger so the %-of-balance cap has a base.
    testing_env!(ctx(account("funder.test.near"), 10u128.pow(24), BASE_TS_MS,).build());
    contract.deposit();

    Env {
        contract,
        kernel,
        kernel_pub,
        agent_id,
        manifest_hash,
    }
}

fn domain(env: &Env) -> Domain {
    let mut buf = Vec::new();
    buf.extend_from_slice(near_sdk::env::chain_id().as_bytes());
    buf.extend_from_slice(near_sdk::env::current_account_id().as_bytes());
    Domain {
        name: "ARPK".to_string(),
        version: "1".to_string(),
        salt: Sha3.keccak256(&buf),
    }
}

fn action(amount: u128) -> ValueActionDto {
    ValueActionDto {
        chain: "near".to_string(),
        venue: "venue-a".to_string(),
        to: "dest.test.near".to_string(),
        asset: "near".to_string(),
        amount: U128(amount),
        memo_hash: vec![0u8; 32],
    }
}

fn core_action(a: &ValueActionDto) -> CoreAction {
    CoreAction {
        chain: a.chain.clone(),
        venue: a.venue.clone(),
        to: a.to.clone(),
        asset: a.asset.clone(),
        amount: a.amount.0,
        memo_hash: to32(&a.memo_hash),
    }
}

/// Build and sign a receipt for `action` over the manifest on record.
fn sign(
    env: &Env,
    action: &ValueActionDto,
    nonce: [u8; 16],
    session_id: [u8; 16],
    issued_ms: u64,
    expiry_ms: u64,
) -> (ReceiptDto, Vec<u8>, u8) {
    sign_with_manifest(
        env,
        action,
        nonce,
        session_id,
        env.manifest_hash,
        issued_ms,
        expiry_ms,
    )
}

/// Same, but signs over an explicit manifest hash (used to build the mismatch case).
fn sign_with_manifest(
    env: &Env,
    action: &ValueActionDto,
    nonce: [u8; 16],
    session_id: [u8; 16],
    manifest_hash: [u8; 32],
    issued_ms: u64,
    expiry_ms: u64,
) -> (ReceiptDto, Vec<u8>, u8) {
    let d = domain(env);
    let action_hash = eip712::hash_value_action(&Sha3, &core_action(action));
    let receipt = CoreReceipt {
        agent_id: to32(&env.agent_id),
        session_id,
        class: class::VALUE,
        action_hash,
        manifest_hash,
        context_hash: [0u8; 32],
        verdict: verdict::ALLOW,
        nonce,
        issued_ms,
        expiry_ms,
    };
    let digest = eip712::digest(&Sha3, &d, &receipt);
    let (sig, recid) = env.kernel.sign_prehash_recoverable(&digest);
    let dto = ReceiptDto {
        agent_id: env.agent_id.clone(),
        session_id: session_id.to_vec(),
        class: receipt.class,
        action_hash: action_hash.to_vec(),
        manifest_hash: receipt.manifest_hash.to_vec(),
        context_hash: receipt.context_hash.to_vec(),
        verdict: receipt.verdict,
        nonce: nonce.to_vec(),
        issued_ms: U64(issued_ms),
        expiry_ms: U64(expiry_ms),
    };
    (dto, sig.to_bytes().to_vec(), recid.to_byte())
}

fn exec(env: &mut Env, a: ValueActionDto, r: ReceiptDto, sig: Vec<u8>, v: u8) {
    let predecessor = account("relayer.test.near");
    testing_env!(ctx(predecessor, 0, BASE_TS_MS).build());
    let _ = env
        .contract
        .execute_value(env.agent_id.clone(), a, r, sig, v);
}
// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

#[test]
fn transfers_value_with_a_valid_receipt() {
    let mut env = deploy();
    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [1u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
    assert!(env.contract.is_nonce_used(vec![1u8; 16]));
}

// ---------------------------------------------------------------------------
// B02-B08 receipt binding
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "ARPK:receipt.bad_signature")]
fn b02_forged_signature_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let (r, _sig, v) = sign(
        &env,
        &a,
        [2u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    let mut forged = [0u8; 64];
    forged[0] = 1;
    exec(&mut env, a, r, forged.to_vec(), v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.replayed")]
fn b03_replay_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [3u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a.clone(), r.clone(), sig.clone(), v);
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.expired")]
fn b04_expired_receipt_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [4u8; 16],
        [9u8; 16],
        BASE_TS_MS - 120_000,
        BASE_TS_MS - 1,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.action_hash_mismatch")]
fn b05_receipt_for_other_action_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let other = action(200);
    let (r, sig, v) = sign(
        &env,
        &other,
        [5u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.action_hash_mismatch")]
fn b06_tampered_amount_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [6u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    let mut tampered = a;
    tampered.amount = U128(101);
    exec(&mut env, tampered, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:manifest.revoked")]
fn b07_revoked_agent_is_rejected() {
    let mut env = deploy();
    let owner = account("owner.test.near");
    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    env.contract.revoke_agent(env.agent_id.clone());

    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [7u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:manifest.hash_mismatch")]
fn b08_manifest_hash_mismatch_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    // Sign a receipt that commits to a manifest hash other than the one on record.
    let wrong = Sha3.keccak256(b"manifest-other");
    let (r, sig, v) = sign_with_manifest(
        &env,
        &a,
        [8u8; 16],
        [9u8; 16],
        wrong,
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

// ---------------------------------------------------------------------------
// B17-B21 venue, approval, TTL, key
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "ARPK:venue.paused")]
fn b17_paused_venue_is_rejected() {
    let mut env = deploy();
    let owner = account("owner.test.near");
    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    env.contract.pause_venue("venue-a".to_string());

    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [17u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:value.approval_required")]
fn b18_amount_at_threshold_requires_approval() {
    let mut env = deploy();
    // threshold is 5_000; per-call cap is 1_000 so raise it via a fresh manifest
    let owner = account("owner.test.near");
    testing_env!(ctx(owner.clone(), 1, BASE_TS_MS).build());
    let assets = vec![AssetCapsDto {
        asset: "near".to_string(),
        per_call_cap: U128(10_000),
        pct_cap_bps: U128(10_000),
        approval_threshold: U128(5_000),
        bucket_capacity: U128(10_000),
        bucket_refill_per_s: U128(0),
    }];
    let venues = vec![VenueCapDto {
        venue: "venue-a".to_string(),
        exposure_cap: U128(100_000),
    }];
    env.contract.register_manifest(
        env.agent_id.clone(),
        env.manifest_hash,
        U64(BASE_TS_MS + 3_600_000),
        assets,
        venues,
    );

    let a = action(5_000);
    let (r, sig, v) = sign(
        &env,
        &a,
        [18u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.ttl_too_long")]
fn b20_ttl_above_max_is_rejected() {
    let mut env = deploy();
    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [20u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 120_001,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:receipt.key_invalid")]
fn b21_revoked_kernel_key_is_rejected() {
    let mut env = deploy();
    let owner = account("owner.test.near");
    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    env.contract.revoke_kernel_key(env.kernel_pub.clone());

    let a = action(100);
    let (r, sig, v) = sign(
        &env,
        &a,
        [21u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

// ---------------------------------------------------------------------------
// B24-B26 caps
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "ARPK:venue.exposure_cap")]
fn b24_venue_exposure_cap_is_enforced() {
    let mut env = deploy();
    // Give the bucket enough room so the venue cap is what binds, not the bucket.
    let owner = account("owner.test.near");
    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    let assets = vec![AssetCapsDto {
        asset: "near".to_string(),
        per_call_cap: U128(1_000),
        pct_cap_bps: U128(10_000),
        approval_threshold: U128(u128::MAX),
        bucket_capacity: U128(20_000),
        bucket_refill_per_s: U128(0),
    }];
    let venues = vec![VenueCapDto {
        venue: "venue-a".to_string(),
        exposure_cap: U128(10_000),
    }];
    env.contract.register_manifest(
        env.agent_id.clone(),
        env.manifest_hash,
        U64(BASE_TS_MS + 3_600_000),
        assets,
        venues,
    );

    // venue-a exposure cap is 10_000; per-call cap is 1_000
    for i in 0..10 {
        let a = action(1_000);
        let nonce = [24u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i];
        let (r, sig, v) = sign(&env, &a, nonce, [9u8; 16], BASE_TS_MS, BASE_TS_MS + 60_000);
        exec(&mut env, a, r, sig, v);
    }
    // 11th would take exposure to 11_000 > 10_000
    let a = action(1_000);
    let (r, sig, v) = sign(
        &env,
        &a,
        [24u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}

#[test]
#[should_panic(expected = "ARPK:value.bucket_exceeded")]
fn b25_bucket_bound_is_exact() {
    let mut env = deploy();
    // capacity 1_000, refill 0
    let a = action(1_000);
    let (r, sig, v) = sign(
        &env,
        &a,
        [25u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);

    // bucket is now empty; any further transfer fails
    let a2 = action(1);
    let (r2, sig2, v2) = sign(
        &env,
        &a2,
        [26u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a2, r2, sig2, v2);
}

#[test]
#[should_panic(expected = "ARPK:value.overflow")]
fn b26_u128_max_amount_is_rejected() {
    let mut env = deploy();
    // Raise the per-call cap so the overflow path is reached rather than the cap path.
    let owner = account("owner.test.near");
    testing_env!(ctx(owner, 1, BASE_TS_MS).build());
    let assets = vec![AssetCapsDto {
        asset: "near".to_string(),
        per_call_cap: U128(u128::MAX),
        pct_cap_bps: U128(10_000),
        approval_threshold: U128(u128::MAX),
        bucket_capacity: U128(u128::MAX),
        bucket_refill_per_s: U128(0),
    }];
    let venues = vec![VenueCapDto {
        venue: "venue-a".to_string(),
        exposure_cap: U128(u128::MAX),
    }];
    env.contract.register_manifest(
        env.agent_id.clone(),
        env.manifest_hash,
        U64(BASE_TS_MS + 3_600_000),
        assets,
        venues,
    );

    let a = action(u128::MAX);
    let (r, sig, v) = sign(
        &env,
        &a,
        [27u8; 16],
        [9u8; 16],
        BASE_TS_MS,
        BASE_TS_MS + 60_000,
    );
    exec(&mut env, a, r, sig, v);
}
