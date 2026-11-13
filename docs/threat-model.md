# Threat model

## Problem class

An agent holds standing capability whose exercise is governed only by its own judgment —
Hardy's **confused deputy** (1988), at machine speed.

Causes in the record: adversarial input, compromised control planes, supply chain,
honest error and state loss, runaway loops, containment failure.

The common missing control: *the effect requires a precondition checked by the thing that
acts, not by the thing that wants to act.*

## What each rung does — and does not do

| Rung | Mechanism | Does | Does **not** |
|---|---|---|---|
| **3 Bound** | On-chain caps: per-call, token bucket, %-of-balance, venue exposure, approval threshold | Caps loss at an owner-chosen number under *any* cause, even a malicious kernel | Say whether a permitted action was wise |
| **2 Containment** | Agent plane holds no value-bearing credential, no network, one socket | Removes the credential-theft class; makes the kernel the only path | Protect against a kernel bug |
| **1 Degradation** | Authority Ledger: untrusted ingress shrinks caps | Lowers expected loss inside the bound | Detect injections; provide per-token noninterference |
| **0 Verifiability** | EIP-712 receipts, nonces, hash-chained audit, on-chain events | Lets a third party check what was authorized | Prove the kernel was honest |

Only Rung 3 bounds loss. Rungs 2, 1, 0 determine how often the bound is approached and
whether anyone can check.

## Why the bound holds even against a malicious kernel

The bound is enforced by the contract, not the kernel. The kernel's only power is to sign
receipts; a receipt is required, but a receipt alone is never sufficient. The contract
recomputes the action hash, checks the manifest, the time window, the TTL, the nonce, the
caps, the approval and the venue exposure, and only then moves value.

So a kernel that signs everything an attacker asks for produces receipts that the contract
still refuses once the caps are reached. This is the central claim (C8) and it is what the
property tests in `crates/arpk-core/tests/fuzz.rs` exercise: the same bound holds in both
honest and malicious-kernel modes because the kernel's behaviour is not an input to the
bound.

## What is explicitly out of scope

See `docs/non-claims.md` for the verbatim list. The most important: a malicious owner, a
compromised TEE, harmful-but-in-scope actions, and social engineering of humans.

## Residual risk after ARPK

- A malicious owner with a permissive manifest: enforced, not judged.
- A kernel bug that signs an incorrect receipt: the contract still refuses out-of-cap
  actions, but a bug that signs a *in-cap* action the owner did not intend is not caught.
- Block timestamp manipulation within the skew window: the bound relaxes by `r·ε`.
- Contract bugs: mitigated only by the test battery and, eventually, an external audit.
