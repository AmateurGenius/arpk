# ARPK — Agentic Runtime Policy Kernel

**What this is.** ARPK is a capability kernel for AI agent actions. Every effect requires a
capability the agent cannot forge: a signed receipt bound to the exact action, the
owner-signed manifest, and a nonce. The action surface is enumerated — the manifest declares
the permitted actions, destinations and venues, and the daemon resolves the agent's handles
against it. The intent schema has `deny_unknown_fields` and no `to` field, so an intent the
manifest never issued cannot even be expressed: an injected "send to 0xATTACKER" fails as
`ARPK:malformed` before the policy engine sees it, and an unissued handle is
`ARPK:action.unclassified`. Authority attenuates with provenance: untrusted ingress degrades
the session through the Authority Ledger, shrinking the caps. The contract bounds loss as
the fourth layer — defense in depth, so a compromised kernel is still a bounded event.

**Why this matters.** The attack class the field is documenting is the confused deputy: an
agent holding standing authority, manipulated into spending it. The capability model is the
fifty-year-old answer. ARPK implements three of its four properties — enumerated designation,
capability verification at the effector, and attenuation — plus an on-chain bound as defense
in depth. Process containment and compile-time typestate enforcement are the two remaining
implementation details; their design is complete and they are on the roadmap.

**What it does not claim.** It does not claim formal verification of the kernel (Kani is 5
of 6 harnesses green; one proof cancelled at timeout). It does not claim process containment
or compile-time typestate enforcement (both are scaffolding, labeled SKIP in the claims
ledger). It does not detect injections. It does not prevent a malicious owner. It bounds what
the agent can cause and caps the loss if the kernel is compromised. The non-claims list is
published verbatim below.

## Try it

**Dashboard** — <https://amateurgenius.github.io/arpk/> — the claim, the proof strip, the
scenario theater, and the evidence. No login, no wallet, no install; works with the RPC
blocked.

**From the terminal** — an independent JavaScript implementation of the receipt format:

```
npx arpk-cli demo bankr              # replay the Grok/Bankr reconstruction
npx arpk-cli verify bundle           # recompute the bundle hash, validate every trace
npx arpk-cli bound --capacity 5000 --refill 10 --seconds 60
npx arpk-cli claims                  # the claims matrix with its env tags
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

| # | Claim | Status | Evidence |
|---|---|---|---|
| C1 | Receipt is a capability token | PASS | B02–B08, B20, B21; on-chain e2e green in CI |
| C2 | Enumerated action surface | PASS | daemon + library: an injected destination is `ARPK:malformed`; an unissued action/destination/venue handle is `ARPK:action.unclassified`; a manifest that does not hash to the on-chain value is `ARPK:manifest.hash_mismatch` |
| C3 | Authority attenuates with provenance | PASS | Authority Ledger: 7 tests; degraded cap enforced in Cedar and in the kernel |
| C4 | Verifiable at the effector | PASS | JS reimplementation reproduces 5/5 Rust golden vectors byte for byte |
| C5 | Revocation is immediate on-chain | PASS | B07 |
| C6 | Kernel failure produces no effect | PASS | Cedar diagnostics → deny; B15 tracked separately |
| C7 | Venue pause + exposure cap | PASS | B17, B24 |
| C8 | The contract bounds loss | PASS | fuzz 10^5 sequences · differential 10^4 steps · B18/B25/B26 |
| C9 | Process containment | SKIP | not built — design complete, roadmap |
| C10 | Typestate gate | SKIP | not built — design complete, roadmap |
| C11 | Kani formal verification | 5/6 | `bucket_step_lemma` cancelled at its 60-minute timeout |

A `SKIP` is an honest skip, not a hidden failure.

**C8 is the backstop; C1–C4 are the discipline.** The capability layers are what make an
attack unrepresentable or unattributable in the first place. The on-chain bound is the one
property that survives a kernel bug or a compromised kernel — it is defense in depth, not the
primary mechanism. C9 and C10 (containment, typestate) are the two implementation details
that make the discipline unbreakable; their design is complete and they are on the roadmap.

## What is here

| Path | What it is |
|---|---|
| `crates/arpk-core` | The executable spec: bound, caps, reason codes, EIP-712 receipts. No runtime dependencies; compiles to native and wasm. |
| `contracts/near-vault` | The NEAR vault contract. Enforces the bound. Builds to a 351 KB wasm contract. |
| `kernel/` | `arpkd`, the kernel daemon: Cedar PDP, k256 receipt signer, four monitors, `serve` (JSON lines over a unix socket) and the one-shot `sign` CLI. Both resolve the agent's handles against the owner's manifest. |
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
