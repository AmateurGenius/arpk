# Libraries and AI-generated code

Required by the hackathon rules (Q-005) and by honesty.

## Libraries

| Library | Version | What it is used for | Where |
|---|---|---|---|
| `near-sdk` | 5.30.1 | NEAR contract framework (`unstable` for `ecrecover`, `unit-testing` for `testing_env!`) | `contracts/near-vault` |
| `near-sys` | (via near-sdk) | host-function bindings | transitive |
| `k256` | 0.14.0 | secp256k1 signing in tests (and the kernel, WP1b) | `kernel`, `contracts/near-vault` dev |
| `sha3` | 0.10 | Keccak-256 in tests and the kernel | `arpk-core` dev, `kernel` |
| `proptest` | 1.12 | property tests for the bound | `arpk-core` dev |
| `cedar-policy` | 4.14 | policy engine (WP1b) | `kernel` |
| `serde` / `serde_json` | 1 | JSON events and DTOs | `kernel` |

`arpk-core` itself has **no runtime dependencies** — it is pure Rust and compiles to both
native and wasm, which is what lets the kernel and the contract share one implementation.

## AI-generated code

This repository was built with AI assistance (Hermes Agent) on a Android/Termux device.
The task decomposition, test design, and code were produced with AI tooling, and a human
reviewed the plan, the threat model, and the claims.

The golden vectors in `docs/golden-vectors/` were produced by an independent implementation
(`@noble/hashes` in Node.js), not by the Rust code under test, so agreement is real
evidence rather than a tautology.

## Build tooling

Rust 1.99.1, `wasm32-unknown-unknown` target. The build is reproducible from `Makefile` and
the CI workflow.
