//! ARPK NEAR vault.
//!
//! Enforces the owner-chosen bound on value movement. Every denial panics with an
//! exact `ARPK:*` reason code and produces no effect.
//!
//! The bound itself lives in `arpk-core` and is shared verbatim with the kernel. This
//! contract is the enforcement point; the kernel is the model. The differential test
//! compares the two.

use arpk_core::bucket::Bucket;
use arpk_core::codes::Code;
use arpk_core::eip712::{digest, hash_value_action, Domain, Receipt as CoreReceipt};
use arpk_core::{class, verdict, Keccak, ValueCaps, MAX_RECEIPT_TTL_MS, SKEW_MS};
use near_sdk::json_types::{U128, U64};
use near_sdk::store::{IterableMap, LookupMap, UnorderedSet};
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

pub const NS_PER_MS: u64 = 1_000_000;

/// Keccak-256 backed by the NEAR host function.
struct HostKeccak;

impl Keccak for HostKeccak {
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        env::keccak256(data)
            .try_into()
            .expect("host keccak256 returns 32 bytes")
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner: AccountId,
    /// Total deposited value. Direct transfers to the account do not raise this.
    ledger: u128,
    agents: LookupMap<Vec<u8>, Agent>,
    kernel_keys: LookupMap<Vec<u8>, KernelKey>,
    used_nonces: IterableMap<Vec<u8>, u64>,
    approvals: LookupMap<Vec<u8>, Approval>,
    paused_venues: UnorderedSet<String>,
}

#[near(serializers = [json, borsh])]
#[derive(PanicOnDefault, Clone)]
pub struct Agent {
    pub manifest_hash: [u8; 32],
    pub expiry_ms: u64,
    pub revoked: bool,
    pub assets: Vec<AssetCaps>,
    pub venues: Vec<VenueCap>,
}

#[near(serializers = [json, borsh])]
#[derive(PanicOnDefault, Clone)]
pub struct AssetCaps {
    pub asset: String,
    pub per_call_cap: u128,
    pub pct_cap_bps: u128,
    pub approval_threshold: u128,
    pub bucket_capacity: u128,
    pub bucket_refill_per_s: u128,
    pub bucket_tokens: u128,
    pub bucket_t_last_ms: u64,
}

#[near(serializers = [json, borsh])]
#[derive(PanicOnDefault, Clone)]
pub struct VenueCap {
    pub venue: String,
    pub exposure_cap: u128,
    pub exposure: u128,
}

#[near(serializers = [json, borsh])]
#[derive(PanicOnDefault, Clone)]
pub struct KernelKey {
    pub expiry_ms: u64,
    pub revoked: bool,
}

#[near(serializers = [json, borsh])]
#[derive(PanicOnDefault, Clone)]
pub struct Approval {
    pub expiry_ms: u64,
    pub consumed: bool,
}

// ---------------------------------------------------------------------------
// JSON DTOs (contract API surface)
// ---------------------------------------------------------------------------

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ValueActionDto {
    pub chain: String,
    pub venue: String,
    pub to: String,
    pub asset: String,
    pub amount: U128,
    pub memo_hash: Vec<u8>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ReceiptDto {
    pub agent_id: Vec<u8>,
    pub session_id: Vec<u8>,
    pub class: u8,
    pub action_hash: Vec<u8>,
    pub manifest_hash: Vec<u8>,
    pub context_hash: Vec<u8>,
    pub verdict: u8,
    pub nonce: Vec<u8>,
    pub issued_ms: U64,
    pub expiry_ms: U64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AssetCapsDto {
    pub asset: String,
    pub per_call_cap: U128,
    pub pct_cap_bps: U128,
    pub approval_threshold: U128,
    pub bucket_capacity: U128,
    pub bucket_refill_per_s: U128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct VenueCapDto {
    pub venue: String,
    pub exposure_cap: U128,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_array32(v: &[u8]) -> Result<[u8; 32], Code> {
    v.try_into().map_err(|_| Code::Malformed)
}

fn to_array16(v: &[u8]) -> Result<[u8; 16], Code> {
    v.try_into().map_err(|_| Code::Malformed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Vault {
    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner,
            "ARPK:owner.required"
        );
    }

    /// Domain separator salt binds the chain and the contract instance.
    fn domain() -> Domain {
        let mut buf = Vec::new();
        buf.extend_from_slice(env::chain_id().as_bytes());
        buf.extend_from_slice(env::current_account_id().as_bytes());
        Domain {
            name: "ARPK".to_string(),
            version: "1".to_string(),
            salt: HostKeccak.keccak256(&buf),
        }
    }

    /// Bound the GC work per call: inspect at most 5 expired entries.
    fn gc_expired_nonces(&mut self, now_ms: u64) {
        let candidates: Vec<Vec<u8>> = self
            .used_nonces
            .iter()
            .filter(|(_, expiry)| **expiry <= now_ms)
            .take(5)
            .map(|(k, _)| k.clone())
            .collect();
        for k in candidates {
            self.used_nonces.remove(&k);
        }
    }
}

// ---------------------------------------------------------------------------
// Contract methods
// ---------------------------------------------------------------------------

#[near]
impl Vault {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            ledger: 0,
            agents: LookupMap::new(b"a"),
            kernel_keys: LookupMap::new(b"k"),
            used_nonces: IterableMap::new(b"n"),
            approvals: LookupMap::new(b"p"),
            paused_venues: UnorderedSet::new(b"v"),
        }
    }

    // -------- owner methods: 1 yocto, so a function-call key can never call them --------

    #[payable]
    pub fn register_manifest(
        &mut self,
        agent_id: Vec<u8>,
        manifest_hash: [u8; 32],
        expiry_ms: U64,
        assets: Vec<AssetCapsDto>,
        venues: Vec<VenueCapDto>,
    ) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        let assets = assets
            .into_iter()
            .map(|a| AssetCaps {
                asset: a.asset,
                per_call_cap: a.per_call_cap.0,
                pct_cap_bps: a.pct_cap_bps.0,
                approval_threshold: a.approval_threshold.0,
                bucket_capacity: a.bucket_capacity.0,
                bucket_refill_per_s: a.bucket_refill_per_s.0,
                bucket_tokens: a.bucket_capacity.0,
                bucket_t_last_ms: 0,
            })
            .collect();
        let venues = venues
            .into_iter()
            .map(|v| VenueCap {
                venue: v.venue,
                exposure_cap: v.exposure_cap.0,
                exposure: 0,
            })
            .collect();
        self.agents.insert(
            agent_id,
            Agent {
                manifest_hash,
                expiry_ms: expiry_ms.0,
                revoked: false,
                assets,
                venues,
            },
        );
    }

    #[payable]
    pub fn revoke_agent(&mut self, agent_id: Vec<u8>) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        match self.agents.get(&agent_id).cloned() {
            Some(mut a) => {
                a.revoked = true;
                self.agents.insert(agent_id, a);
            }
            None => panic!("{}", Code::ManifestMissing),
        }
    }

    #[payable]
    pub fn revoke_kernel_key(&mut self, public_key: Vec<u8>) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        if let Some(mut k) = self.kernel_keys.get(&public_key).cloned() {
            k.revoked = true;
            self.kernel_keys.insert(public_key, k);
        }
    }

    #[payable]
    pub fn register_kernel_key(&mut self, public_key: Vec<u8>, expiry_ms: U64) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        self.kernel_keys.insert(
            public_key,
            KernelKey {
                expiry_ms: expiry_ms.0,
                revoked: false,
            },
        );
    }

    #[payable]
    pub fn approve_action(&mut self, action_hash: Vec<u8>, expiry_ms: U64) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        self.approvals.insert(
            action_hash,
            Approval {
                expiry_ms: expiry_ms.0,
                consumed: false,
            },
        );
    }

    #[payable]
    pub fn pause_venue(&mut self, venue: String) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        self.paused_venues.insert(venue);
    }

    #[payable]
    pub fn unpause_venue(&mut self, venue: String) {
        near_sdk::utils::assert_one_yocto();
        self.assert_owner();
        self.paused_venues.remove(&venue);
    }

    // -------- public --------

    /// Deposit into the ledger. Direct transfers to the account do not raise the ledger,
    /// so the %-of-balance cap cannot be inflated by accident.
    #[payable]
    pub fn deposit(&mut self) {
        self.ledger = self
            .ledger
            .saturating_add(env::attached_deposit().as_yoctonear());
    }

    /// Execute a value movement. Any failure panics with an exact `ARPK:*` code and
    /// leaves no effect.
    pub fn execute_value(
        &mut self,
        agent_id: Vec<u8>,
        action: ValueActionDto,
        receipt: ReceiptDto,
        signature: Vec<u8>,
        v: u8,
    ) -> Promise {
        let now_ms = env::block_timestamp_ms();
        let now_ns = match now_ms.checked_mul(NS_PER_MS) {
            Some(t) => t,
            None => panic!("{}", Code::ValueOverflow),
        };

        // 1. agent exists, not revoked, not expired; venue not paused
        let mut agent = match self.agents.get(&agent_id).cloned() {
            Some(a) => a,
            None => panic!("{}", Code::ManifestMissing),
        };
        if agent.revoked {
            panic!("{}", Code::ManifestRevoked);
        }
        if agent.expiry_ms < now_ms {
            panic!("{}", Code::ManifestExpired);
        }
        if self.paused_venues.contains(&action.venue) {
            panic!("{}", Code::VenuePaused);
        }

        // 2. receipt binding: agent, class, verdict
        if receipt.agent_id != agent_id {
            panic!("{}", Code::ReceiptClassMismatch);
        }
        if receipt.class != class::VALUE || receipt.verdict != verdict::ALLOW {
            panic!("{}", Code::ReceiptClassMismatch);
        }

        // 3. signature recovers a registered, unexpired kernel key
        let core_receipt = CoreReceipt {
            agent_id: match to_array32(&receipt.agent_id) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            session_id: match to_array16(&receipt.session_id) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            class: receipt.class,
            action_hash: match to_array32(&receipt.action_hash) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            manifest_hash: match to_array32(&receipt.manifest_hash) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            context_hash: match to_array32(&receipt.context_hash) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            verdict: receipt.verdict,
            nonce: match to_array16(&receipt.nonce) {
                Ok(x) => x,
                Err(e) => panic!("{}", e),
            },
            issued_ms: receipt.issued_ms.0,
            expiry_ms: receipt.expiry_ms.0,
        };
        let d = digest(&HostKeccak, &Self::domain(), &core_receipt);
        let pubkey = match env::ecrecover(&d, &signature, v, true) {
            Some(p) => p.to_vec(),
            None => panic!("{}", Code::ReceiptBadSignature),
        };
        let key = match self.kernel_keys.get(&pubkey).cloned() {
            Some(k) => k,
            None => panic!("{}", Code::ReceiptKeyInvalid),
        };
        if key.revoked || key.expiry_ms < now_ms {
            panic!("{}", Code::ReceiptKeyInvalid);
        }

        // 4. manifest hash matches the record
        if core_receipt.manifest_hash != agent.manifest_hash {
            panic!("{}", Code::ManifestHashMismatch);
        }

        // 5. action hash recomputed from the action
        let memo_hash = match to_array32(&action.memo_hash) {
            Ok(x) => x,
            Err(e) => panic!("{}", e),
        };
        let core_action = arpk_core::eip712::ValueAction {
            chain: action.chain.clone(),
            venue: action.venue.clone(),
            to: action.to.clone(),
            asset: action.asset.clone(),
            amount: action.amount.0,
            memo_hash,
        };
        if hash_value_action(&HostKeccak, &core_action) != core_receipt.action_hash {
            panic!("{}", Code::ReceiptActionHashMismatch);
        }

        // 6. time window, TTL, nonce
        if core_receipt.issued_ms > now_ms.saturating_add(SKEW_MS) {
            panic!("{}", Code::ReceiptNotYetValid);
        }
        if core_receipt.expiry_ms <= now_ms {
            panic!("{}", Code::ReceiptExpired);
        }
        if core_receipt
            .expiry_ms
            .saturating_sub(core_receipt.issued_ms)
            > MAX_RECEIPT_TTL_MS
        {
            panic!("{}", Code::ReceiptTtlTooLong);
        }
        if self.used_nonces.contains_key(core_receipt.nonce.as_slice()) {
            panic!("{}", Code::ReceiptReplayed);
        }

        // 7. caps
        let amount = action.amount.0;
        let asset_idx = match agent.assets.iter().position(|a| a.asset == action.asset) {
            Some(i) => i,
            None => panic!("{}", Code::ValuePerCallExceeded),
        };
        let mut caps = ValueCaps {
            per_call_cap: agent.assets[asset_idx].per_call_cap,
            pct_of_balance_cap_bps: agent.assets[asset_idx].pct_cap_bps,
            approval_threshold: agent.assets[asset_idx].approval_threshold,
            bucket: Bucket {
                capacity: agent.assets[asset_idx].bucket_capacity,
                refill_per_s: agent.assets[asset_idx].bucket_refill_per_s,
                tokens: agent.assets[asset_idx].bucket_tokens,
                t_last_ns: agent.assets[asset_idx]
                    .bucket_t_last_ms
                    .saturating_mul(NS_PER_MS),
            },
        };
        if let Err(e) = caps.check(self.ledger, amount, now_ns) {
            panic!("{}", e);
        }

        // approval for large amounts
        if amount >= agent.assets[asset_idx].approval_threshold {
            match self
                .approvals
                .get(core_receipt.action_hash.as_slice())
                .cloned()
            {
                Some(a) if !a.consumed && a.expiry_ms >= now_ms => {
                    let mut a = a;
                    a.consumed = true;
                    self.approvals.insert(core_receipt.action_hash.to_vec(), a);
                }
                _ => panic!("{}", Code::ValueApprovalRequired),
            }
        }

        // venue exposure
        let venue_idx = match agent.venues.iter().position(|v| v.venue == action.venue) {
            Some(i) => i,
            None => panic!("{}", Code::VenuePaused),
        };
        if agent.venues[venue_idx].exposure.saturating_add(amount)
            > agent.venues[venue_idx].exposure_cap
        {
            panic!("{}", Code::VenueExposureCap);
        }

        // destination must be a real account
        let to: AccountId = match action.to.parse() {
            Ok(a) => a,
            Err(_) => panic!("{}", Code::Malformed),
        };

        // 8. commit before effect
        agent.assets[asset_idx].bucket_tokens = caps.bucket.tokens;
        agent.assets[asset_idx].bucket_t_last_ms = caps.bucket.t_last_ns / NS_PER_MS;
        agent.venues[venue_idx].exposure = agent.venues[venue_idx].exposure.saturating_add(amount);
        self.agents.insert(agent_id.clone(), agent);
        self.used_nonces
            .insert(core_receipt.nonce.to_vec(), core_receipt.expiry_ms);
        self.gc_expired_nonces(now_ms);

        env::log_str(&format!(
            "ValueExecuted{{agent_id:{},action_hash:{},context_hash:{}}}",
            hex(&agent_id),
            hex(&core_receipt.action_hash),
            hex(&core_receipt.context_hash)
        ));

        // 9. effect
        Promise::new(to).transfer(NearToken::from_yoctonear(amount))
    }

    // -------- views --------

    pub fn ledger(&self) -> U128 {
        U128(self.ledger)
    }

    pub fn get_agent(&self, agent_id: Vec<u8>) -> Option<Agent> {
        self.agents.get(&agent_id).cloned()
    }

    pub fn is_nonce_used(&self, nonce: Vec<u8>) -> bool {
        self.used_nonces.contains_key(&nonce)
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}
