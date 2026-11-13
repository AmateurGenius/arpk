# Submission description (paste into the form field)

**Field constraint:** 20–2,000 characters. **This is 1,116 characters.**

---

ARPK is a capability kernel for AI agent actions. Every effect requires a capability the agent cannot forge: a signed receipt bound to the exact action, an owner-signed manifest, and a nonce. The action surface is enumerated — the daemon resolves the agent's handles against the manifest, and the schema cannot represent a destination the manifest did not issue, so an injected "send to 0xATTACKER" fails as malformed before the policy engine runs. Authority attenuates with provenance: untrusted ingress degrades the session and shrinks the caps. A NEAR contract bounds loss as the fourth layer — defense in depth, so a compromised kernel is still a bounded event. Three capability layers are enforced and tested (the daemon's enumerated-surface gate, 21 tests on receipt binding, 7 tests on attenuation); a cross-language conformance layer reproduces the Rust golden vectors in JavaScript so anyone can verify the receipt without trusting the kernel. Formal verification (Kani, 5 of 6 harnesses) and process containment are on the roadmap, labeled honestly in the claims ledger. The kernel is open source, the evidence bundle is one hash, and make verify runs every claim in one command.

---

# X post draft (603 chars)

ARPK is a capability kernel for AI agent actions.

The action surface is enumerated. The daemon resolves the agent's handles against the owner's manifest; the schema has deny_unknown_fields and no `to` field — an injected "send to 0xATTACKER" cannot even be written. It fails as ARPK:malformed before the policy engine runs.

Every effect needs a receipt the agent cannot forge. The contract verifies it (ecrecover) and bounds the loss as the fourth layer.

Live: https://amateurgenius.github.io/arpk/
Repo: https://github.com/AmateurGenius/arpk

Three capability layers enforced and tested. The bound is the backstop. Containment and typestate are roadmap.

#NEARHACKATHON

---

# Demo beat order (re-cut the video to this)

| Time | Beat | Claim | Capability property |
|---|---|---|---|
| 0:00 | "ARPK is a capability kernel. Every effect requires a capability the agent cannot forge. Here's what that means." | — | — |
| 0:20 | **The unrepresentable destination.** The daemon resolves the agent's handles against the owner's manifest; the schema has `deny_unknown_fields` and no `to` field. Attempt `{to: "0xATTACKER"}` → `ARPK:malformed` before the PDP. Show the recorded `enumerated` trace. | C2 | No designation without authority |
| 0:45 | **The receipt as token.** Baseline transfer: intent → receipt → vault verifies → funds move. Show the EIP-712 structure. | C1 | Capability verification at the effector |
| 1:10 | **Attenuation.** Bankr replay: untrusted content enters → Authority Ledger drops Full → Degraded → transfer denied → funds out = 0. | C3 | Capability attenuates |
| 1:35 | **Externalized verification.** The JS reimplementation reproduces the Rust golden vectors byte for byte. | C4 | Verifiable outside the trust boundary |
| 1:55 | **Defense in depth.** Fuzzer: 10^5 sequences + 10^4 differential + malicious-kernel mode; bound holds. | C8 | Fourth-layer backstop |
| 2:20 | `make verify` table; non-claims on screen. | — | Reproducibility |
| 2:35 | Close: "Three capability layers enforced and tested. The bound is the fourth layer." | — | — |

**Closing sentence:** *"Three capability layers are enforced and tested. The bound is the fourth layer. That is why the attack class is preventable, not just survivable."*

**Rehearse the 0:20 beat hardest.** "The injected destination cannot even be written" is the sentence judges repeat.
