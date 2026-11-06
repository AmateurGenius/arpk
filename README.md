# ARPK

Agents fail for many reasons. ARPK makes the cost of failure a number the owner chose in
advance.

ARPK is a receipt-enforced vault on NEAR. An agent can *request* a value movement, but
the movement only happens if a kernel key signs a receipt for that exact action, and the
contract enforces the owner's caps before any value moves.

## Try it

```
make setup      # prints the tool versions
make verify     # runs the local test battery; every claim prints PASS/FAIL
make demo       # alias for make verify
```

Expected output: a table of claims C0-C7 with the evidence that supports each one.

## What is here

| Path | What it is |
|---|---|
| `crates/arpk-core` | The executable spec: bound, caps, reason codes, EIP-712 receipts. Shared verbatim by kernel and contract. |
| `contracts/near-vault` | The NEAR vault contract. Enforces the bound. |
| `kernel/` | `arpkd`, the kernel daemon (WP1b). |
| `policies/` | Cedar policies. |
| `tests/` | Property and differential tests. |
| `docs/` | Threat model, non-claims, evidence. |

## Claims and non-claims

See `docs/non-claims.md` for the verbatim non-claims. The short version: ARPK bounds loss
under any cause, including a malicious kernel. It does **not** judge whether a permitted
action was wise, and it is **not** formally verified end to end.

## Libraries and AI-generated code

Listed in `docs/libraries.md` (populated before submission, per Q-005).

## License

MIT — see `LICENSE`.
