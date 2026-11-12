# ARPK

Agents fail for many reasons. ARPK makes the cost of failure a number the owner chose in
advance.

ARPK is a capability kernel for agent actions with an on-chain bound. The agent holds no
authority and can only name actions and destinations the owner's manifest issued. Every
effect needs a one-shot, action-bound receipt that the vault verifies. The vault caps loss
on its own, so the bound holds even if the kernel is wrong. The cap arithmetic that both
run is machine-checked.

Concretely: ARPK is a receipt-enforced vault on NEAR. An agent can *request* a value
movement, but the movement only happens if a kernel key signs a receipt for that exact
action, and the contract enforces the owner's caps before any value moves.

## Try it

**Dashboard** — <https://amateurgenius.github.io/arpk/> — the claim, the proof strip, the
scenario theater, and the evidence. No login, no wallet, no install; works with the RPC
blocked.

**From the terminal** — an independent JavaScript implementation of the receipt format:

```
npx arpk demo bankr                  # replay the Grok/Bankr reconstruction
npx arpk verify bundle               # recompute the bundle hash, validate every trace
npx arpk bound --capacity 5000 --refill 10 --seconds 60
npx arpk claims                      # the claims matrix with its env tags
```

**From the repo**:

```
make setup        # prints tool versions and checks the wasm target
make verify       # runs the local test battery (69 tests)
make judge-check  # build the evidence bundle, then validate it
python3 tools/verify.py   # prints the claims table from measured results
```

`make verify` runs `arpk-core` (model + properties), `arpkd` (the kernel: Cedar PDP,
receipt signer, monitors, `serve`) and `near-vault` (native contract tests). Every denial
test asserts an exact `ARPK:*` reason code string.

Some evidence cannot run on this device (Termux/Bionic): the near-workspaces sandbox
binary is glibc-only, Kani does not support the platform, and Docker is absent. Those
tiers run in GitHub Actions on Ubuntu, and `make verify` prints `SKIP (CI-only)` for them.

Latest green run: <https://github.com/AmateurGenius/arpk/actions/runs/42881278133>
(`native`, `wasm`, `e2e`). The `e2e` job deploys the wasm to a sandbox, has the kernel
library sign a receipt, and submits it with a function-call key — the P0 path, green.

## Current status

`claims.json` is generated from measured results and committed. Each claim carries the
environment its evidence ran in (`local`, `ci`, `testnet`). As of this build:

| Claim | Status | Env | Evidence |
|---|---|---|---|
| C0 bound | PASS | local, ci | 4 proptest properties + bucket/caps unit tests; fuzz volume below target |
| C1 receipt binding | PASS | local, ci | B02-B08, B20, B21; on-chain e2e green in CI |
| C2 containment | SKIP | ci | not built — needs Docker (Block B3) |
| C3 untrusted ingress shrinks authority | SKIP | local | not built — Authority Ledger (Block B4) |
| C4 revocation | PASS | local, ci | B07 |
| C5 kernel failure produces no effect | PASS | local | Cedar diagnostics → deny; B15 (kernel death) not built |
| C6 evaluation verifiable downstream | PASS | local, ci | B02-B06 |
| C7 paused venue unreachable | PASS | local, ci | B17, B24 |
| C8 enumerated intents | SKIP | local | not built (Block B1; B28/B29) |
| C9 typestate gate | SKIP | local | not built (Block B2; B30) |
| C10 Kani on the cap arithmetic | SKIP | ci | not built (Block A4; 6 harnesses) |

A `SKIP` is an honest skip, not a hidden failure.

**Only C0 bounds loss independently of the kernel.** C8, C9, C2 and C3 reduce how often
the bound is approached. C1 and C6 make decisions attributable and checkable. C10 backs
C0. This is the claim hierarchy: the on-chain bound is the only property that survives a
kernel bug or a compromised kernel; the other layers reduce how often it is approached.

## What is here

| Path | What it is |
|---|---|
| `crates/arpk-core` | The executable spec: bound, caps, reason codes, EIP-712 receipts. No runtime dependencies; compiles to native and wasm. |
| `contracts/near-vault` | The NEAR vault contract. Enforces the bound. Builds to a 351 KB wasm contract. |
| `kernel/` | `arpkd`, the kernel daemon: Cedar PDP, k256 receipt signer, four monitors, `serve` (JSON lines over a unix socket) and the one-shot `sign` CLI. |
| `docs/golden-vectors/` | The independent implementation and vectors used to validate the EIP-712 hashing. |
| `docs/` | Threat model, non-claims, library list. |
| `tools/verify.py` | Generates `claims.json` from test output. Never hand-edit `claims.json`. |

## Why the bound holds even against a malicious kernel

The bound is enforced by the contract, not the kernel. The kernel's only power is to sign
receipts, and a receipt alone is never sufficient: the contract recomputes the action
hash, checks the manifest, the time window, the TTL, the nonce, the caps, the approval
and the venue exposure, and only then moves value.

See `docs/threat-model.md` for the full argument.

## Prior art

ARPK is not the first system in this space, and the README says so. Closest prior work:
the **Unfireable Safety Kernel** (Dobrin & Chmiel, Jun 2026) — separate process,
fail-closed, signed evidence, Kani on the gate; **Symbiont/ORGA** (ThirdKey, Apr 2026) —
typestate agent loop with a Cedar gate and audit; the **Sondera** harness (hook-based
Cedar), **OutLayer** (TEE-side policy), **ERC-7710** caveat enforcers, and AWS's
Cedar-based agent policy.

ARPK's delta, stated narrowly: receipts are verified by an **on-chain effector** that
independently caps loss, and the kernel and the contract share one arithmetic core. We
found no prior system that combines these; if that is wrong, say so.

## Non-claims

See `docs/non-claims.md`, verbatim. The short version: ARPK bounds loss under any cause,
including a malicious kernel. It does **not** judge whether a permitted action was wise,
the TEE is **simulated** in this build, and it is **not** formally verified end to end.

Specifically:

- Kani proves **bounded** properties of `arpk-core` only — not Cedar, serialization,
  signing, the RPC loop, the Authority Ledger, the TEE, or NEAR's runtime. This is not a
  seL4-class verification and the README does not compare it to one.
- The typestate gate holds under assumptions A1–A5 only.
- Enumeration closes the mediation gap **only for the enumerated action set**; semantic
  misuse of an allowed action (right destination, wrong reason) is not detected.
- Some evidence runs only in CI (Kani, sandbox, docker). The table above says which.

## Libraries and AI-generated code

See `docs/libraries.md` (Q-005).

## License

MIT — see `LICENSE`.
