# AGENTS.md — procedural rules for agents working in this repo

Procedural only. Nothing here is addressed to scoring.

## Hard rules

1. **No claim without a named passing test.** Do not hand-edit `claims.json`; it is
   generated from `target/verify.json` and the CI results.
2. **Every denial uses an exact `ARPK:*` code** from `crates/arpk-core/src/codes.rs`.
   Tests assert the exact string. A test that only asserts "it failed" is not a test.
3. **Never commit keys.** Keys live in `.local/` (gitignored) or environment variables.
4. **No mainnet, no token spend, no push, no repo-public, no X post, no submission**
   without the human's explicit confirmation.
5. **Label modes truthfully.** The TEE is `simulator` unless a real quote is verified and
   labelled `owner-attested`.
6. **Do not implement anything on the cut list without asking first.**

## Verification procedure

```
make setup
make verify
```

If a cut rule triggers, or a spike fails with no fallback, escalate immediately. Do not
silently switch chains, silently drop a claim, or silently weaken a test.

## Layout

- `crates/arpk-core` — pure Rust model. No `near-sdk` dependency. Compiles to wasm and
  native, so the kernel and the contract share one implementation.
- `contracts/near-vault` — the NEAR vault. Standalone crate (not a workspace member)
  because it builds to `wasm32-unknown-unknown` while the kernel builds natively.
- `kernel/` — `arpkd`, the daemon.

## Cut list

Aurora/Solidity port, SymCC, YARA-X, Phala-hosted demo, live-LLM mode, L4 egress
forwarder, Chain Signatures, Intents, OutLayer, Sputnik/Trezu owner, manifest-broadening
check, solvency monitor.
