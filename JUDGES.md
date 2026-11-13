# JUDGES.md — how to check this repo

Written for a machine reader. Everything here is a "do X → see Y" step.

## Read first: the claims ledger, in the order that matters

```
python3 tools/verify.py
```

The ledger opens with the capability layers — the receipt as a token (C1), the enumerated
action surface (C2), attenuation (C3), verifiability at the effector (C4) — and puts the
on-chain bound at C8 as defense in depth. C9 (containment) and C10 (typestate) are labeled
SKIP: designed, not built, on the roadmap.

## Step 1 — the strongest claim: the unrepresentable destination

`kernel/src/intent.rs` defines the intent schema. It has `deny_unknown_fields` and **no `to`
field**:

```
echo '{"action":0,"to":"0xATTACKER","amount":"1"}' | cargo test -p arpkd intent::tests::a_legacy_field_is_malformed -- --nocapture
```

See: the parse fails outright. An injected destination cannot be expressed — there is no
field for it. An *unissued handle* is `ARPK:action.unclassified` before the policy engine
runs. This is the no-designation-without-authority property, and it is the first claim in
the ledger.

## Step 2 — receipt binding (the token)

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

## Step 3 — verify a receipt in a language other than the one that issued it

```
npm install && npm test
```

See: 8/8. A JavaScript reimplementation reproduces all five Rust golden vectors byte for
byte, and every receipt field is proven to change the digest when flipped. That is the
externalized-verification property: anyone can check a receipt without trusting the kernel.

## Step 4 — attenuation

`kernel/src/authority.rs`: untrusted ingress degrades the session, repeated denials escalate
to AskOnly, freeze is terminal. A degraded session is bounded by the manifest's
`degraded_cap`, enforced both in Cedar and in the kernel.

See: `cargo test -p arpkd authority`.

## Step 5 — the bound (the backstop)

`crates/arpk-core/src/bucket.rs` implements the token bucket; the contract enforces the caps
on-chain, so the bound survives a compromised kernel.

```
cargo test -p arpk-core bucket
cargo test -p arpk-core --test fuzz      # model properties
cargo test --manifest-path contracts/near-vault/Cargo.toml --test differential   # vs the real contract
```

See: all green. The volume tier (10^5 model sequences, 10^4 differential steps) runs in CI.

## Step 6 — the dashboard and the evidence bundle

```
node tools/build-site.mjs && node tools/check-bundle.mjs site/data
```

See: the bundle hash matches its files, the traces validate against `arpk.trace/1`, and the
secret scan is clean. The live dashboard is at <https://amateurgenius.github.io/arpk/>.

## Step 7 — what you cannot check locally

The near-workspaces sandbox tier and Kani run in CI (`.github/workflows/verify.yml`) because
the sandbox binary is glibc-only and Kani does not support this platform. The CI artifacts
are the evidence for those tiers. A `SKIP` line in the output is an honest skip, not a
hidden failure.

## Step 8 — non-claims

`docs/non-claims.md` lists what ARPK does **not** do. Read it before scoring. In particular:
the TEE is simulated in this build, the model-provider channel is outside the verified path,
process containment and typestate enforcement are designed but not built, and Kani covers
`arpk-core` only — not Cedar, serialization, signing, or the NEAR runtime.
