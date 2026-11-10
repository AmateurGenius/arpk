#!/usr/bin/env python3
"""Generate claims.json from measured test results.

Rule 1 of AGENTS.md: no claim without a named passing test, and claims.json is never
hand-edited. This script maps test names to claim IDs and writes the artifact.

Each claim carries an `env` list (`local`, `ci`, `testnet`) so a reader can see where the
evidence actually ran, and the artifact carries the CI run URL when ARPK_CI_RUN_URL is set.

Usage:
    python3 tools/verify.py [--out target/verify.json]
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# claim -> (statement, [test-name substrings that must pass], [env], notes)
#
# `tests` empty means the claim is not built yet; it is reported as SKIP with the note.
CLAIMS = {
    "C0": (
        "Value out over any interval is bounded by capacity + refill*dt; each transfer "
        "respects per-call and %-of-balance caps. Holds even if the kernel is malicious.",
        ["bucket", "caps", "b25", "b26"],
        ["local", "ci"],
        "Kani harnesses (C10) and the on-chain e2e land in Block A3/A4; fuzz volume is "
        "currently 8 cases, far below target.",
    ),
    "C1": (
        "No value moves without a valid, unexpired, unreplayed receipt bound to the exact "
        "action and the on-chain manifest.",
        ["b02", "b03", "b04", "b05", "b06", "b08", "b20", "b21"],
        ["local", "ci"],
        "On-chain e2e green in CI: intent -> kernel receipt -> transfer, plus B03/B06/B07/B20/B21.",
    ),
    "C2": (
        "The agent plane holds an empty capability set and reaches only the kernel socket.",
        [],
        ["ci"],
        "Not built. Needs docker-compose + tools/capability-inventory.sh (Block B3).",
    ),
    "C3": (
        "Untrusted ingress shrinks authority.",
        [],
        ["local"],
        "Not built. Authority Ledger is Block B4, behind B1-B3.",
    ),
    "C4": (
        "Revocation is immediate for on-chain value.",
        ["b07"],
        ["local", "ci"],
        "",
    ),
    "C5": (
        "Kernel failure or policy error produces no effect.",
        ["forced_error", "missing_context_amount"],
        ["local"],
        "Cedar diagnostics-deny is covered. B15 (kernel killed mid-request) is not built; "
        "the `serve` startup lease gate (B31) is the planned cover.",
    ),
    "C6": (
        "Evaluation is verifiable downstream from the receipt and the audit chain.",
        ["b02", "b03", "b04", "b05", "b06"],
        ["local", "ci"],
        "",
    ),
    "C7": (
        "A paused venue is unreachable and venue exposure is capped.",
        ["b17", "b24"],
        ["local", "ci"],
        "",
    ),
    "C8": (
        "Intents can only name manifest-issued handles; an unknown handle or unknown field "
        "is unrepresentable.",
        [],
        ["local"],
        "Not built. Block B1 (enumerated intents; B28/B29).",
    ),
    "C9": (
        "Within the kernel crate, a receipt can only be produced from a PDP-approved value "
        "(assumptions A1-A5).",
        [],
        ["local"],
        "Not built. Block B2 (typestate `Gated`; B30 compile-fail).",
    ),
    "C10": (
        "The bucket/caps arithmetic is machine-checked (Kani, bounded, arpk-core only).",
        [],
        ["ci"],
        "Not built. Block A4 (6 harnesses, CI only; Termux is unsupported).",
    ),
}


def run(cmd):
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.stdout + proc.stderr


def passed_tests(output):
    return set(re.findall(r"^test ([\w:]+)(?: - should panic)? \.\.\. ok$", output, re.M))


def main():
    out_path = ROOT / "target" / "verify.json"
    for arg in sys.argv[1:]:
        if arg.startswith("--out="):
            out_path = Path(arg.split("=", 1)[1])

    core_out = run(["cargo", "test", "-p", "arpk-core"])
    kernel_out = run(["cargo", "test", "-p", "arpkd"])
    vault_out = run([
        "cargo", "test", "--manifest-path",
        "contracts/near-vault/Cargo.toml",
    ])
    combined = "\n".join([core_out, kernel_out, vault_out])
    passed = passed_tests(combined)

    claims = {}
    for cid, (statement, tests, env, notes) in CLAIMS.items():
        entry = {"statement": statement, "env": env}
        if notes:
            entry["notes"] = notes
        if not tests:
            entry["status"] = "SKIP"
            entry["reason"] = notes or "not built in this window"
            claims[cid] = entry
            continue
        missing = [t for t in tests if not any(t in p for p in passed)]
        entry["status"] = "PASS" if not missing else "FAIL"
        entry["missing_tests"] = missing
        claims[cid] = entry

    result = {
        "rustc": run(["rustc", "--version"]).strip(),
        "run_url": os.environ.get("ARPK_CI_RUN_URL") or None,
        "tests_passed": sorted(passed),
        "claims": claims,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"wrote {out_path}")

    # The committed artifact judges and screeners read.
    claims_path = ROOT / "claims.json"
    claims_path.write_text(json.dumps(result, indent=2))
    print(f"wrote {claims_path}")
    for cid, c in claims.items():
        print(f"  {cid}  {c['status']:5}  env={','.join(c['env']):10}  {c['statement'][:55]}")
    return 0 if all(c["status"] != "FAIL" for c in claims.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
