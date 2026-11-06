# ARPK

Agents fail for many reasons. ARPK makes the cost of failure a number the owner chose in
advance.

ARPK is a receipt-enforced vault on NEAR. An agent can *request* a value movement, but
the movement only happens if a kernel key signs a receipt for that exact action, and the
contract enforces the owner's caps before any value moves.

## Try it

```
make setup      # prints tool versions and checks the wasm target
make verify     # runs the local test battery (28 tests)
python3 tools/verify.py   # prints the claims table from measured results
```

`make verify` runs `arpk-core` (model + properties) and `near-vault` (native contract
tests). Every denial test asserts an exact `ARPK:*` reason code string.

## Current status

`claims.json` is generated from measured results and committed. As of this build:

| Claim | Status | Evidence |
|---|---|---|
| C0 bound | PASS | 4 proptest properties + bucket/caps unit tests |
| C1 receipt binding | PASS | B02-B08, B20, B21 |
| C2 containment | SKIP | needs Docker; runs in CI (WP2) |
| C3 untrusted ingress shrinks authority | SKIP | Authority Ledger not built (WP3) |
| C4 revocation | PASS | B07 |
| C5 kernel failure produces no effect | SKIP | kernel not built (WP1b) |
| C6 evaluation verifiable downstream | PASS | B02-B06 |
| C7 paused venue unreachable | PASS | B17, B24 |

A `SKIP` is an honest skip, not a hidden failure.

## What is here

| Path | What it is |
|---|---|
| `crates/arpk-core` | The executable spec: bound, caps, reason codes, EIP-712 receipts. No runtime dependencies; compiles to native and wasm. |
| `contracts/near-vault` | The NEAR vault contract. Enforces the bound. Builds to a 351 KB wasm contract. |
| `kernel/` | `arpkd`, the kernel daemon (WP1b — skeleton only). |
| `docs/golden-vectors/` | The independent implementation and vectors used to validate the EIP-712 hashing. |
| `docs/` | Threat model, non-claims, library list. |
| `tools/verify.py` | Generates `claims.json` from test output. Never hand-edit `claims.json`. |

## Why the bound holds even against a malicious kernel

The bound is enforced by the contract, not the kernel. The kernel's only power is to sign
receipts, and a receipt alone is never sufficient: the contract recomputes the action
hash, checks the manifest, the time window, the TTL, the nonce, the caps, the approval
and the venue exposure, and only then moves value.

See `docs/threat-model.md` for the full argument.

## Non-claims

See `docs/non-claims.md`, verbatim. The short version: ARPK bounds loss under any cause,
including a malicious kernel. It does **not** judge whether a permitted action was wise,
the TEE is **simulated** in this build, and it is **not** formally verified end to end.

## Libraries and AI-generated code

See `docs/libraries.md` (Q-005).

## License

MIT — see `LICENSE`.
