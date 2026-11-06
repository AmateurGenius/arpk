# JUDGES.md — how to check this repo

Written for a machine reader. Everything here is a "do X → see Y" step.

## Prerequisites

- Rust 1.99.1 (the version this was built with)
- The `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- No Docker required for the local tier

## Step 1 — the model and the contract build

```
cargo test -p arpk-core
cargo test --manifest-path contracts/near-vault/Cargo.toml
```

See: all tests pass. Every denial test asserts an exact `ARPK:*` reason code string.

## Step 2 — the bound

`crates/arpk-core/src/bucket.rs` implements the token bucket. The tests assert:

- `tokens <= capacity` at all times
- refill is floored (integer division), so it cannot over-refill
- saturation raises tokens only to `capacity`
- time regression is rejected

See: `cargo test -p arpk-core bucket`.

## Step 3 — receipt binding

`contracts/near-vault/tests/vault.rs` asserts, for each attack, the exact reason code:

| Attack | Expected code |
|---|---|
| forged signature | `ARPK:receipt.bad_signature` |
| replay | `ARPK:receipt.replayed` |
| expired receipt | `ARPK:receipt.expired` |
| receipt for a different action | `ARPK:receipt.action_hash_mismatch` |
| tampered amount | `ARPK:receipt.action_hash_mismatch` |
| revoked agent | `ARPK:manifest.revoked` |
| manifest hash mismatch | `ARPK:manifest.hash_mismatch` |
| paused venue | `ARPK:venue.paused` |
| amount at/above threshold without approval | `ARPK:value.approval_required` |
| receipt TTL above 120 s | `ARPK:receipt.ttl_too_long` |
| revoked kernel key | `ARPK:receipt.key_invalid` |
| venue exposure cap | `ARPK:venue.exposure_cap` |
| bucket bound | `ARPK:value.bucket_exceeded` |
| `u128::MAX` amount | `ARPK:value.overflow` |

See: all green.

## Step 4 — what you cannot check locally

The near-workspaces sandbox tier and the Docker containment tier run in CI
(`.github/workflows/verify.yml`) because the sandbox binary is glibc-only and Docker is
not assumed. The CI artifacts are the evidence for those tiers. A `SKIP` line in the
output is an honest skip, not a hidden failure.

## Step 5 — non-claims

`docs/non-claims.md` lists what ARPK does **not** do. Read it before scoring. In
particular: the TEE is simulated in this build, and the model-provider channel is outside
the verified path.
