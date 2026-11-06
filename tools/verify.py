#!/usr/bin/env python3
"""Generate claims.json from measured test results.

Rule 1 of AGENTS.md: no claim without a named passing test, and claims.json is never
hand-edited. This script maps test names to claim IDs and writes the artifact.

Usage:
    python3 tools/verify.py [--out target/verify.json]
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# claim -> (statement, [test-name substrings that must pass], tier)
CLAIMS = {
    "C0": (
        "Value out over any interval is bounded by capacity + refill*dt; each transfer "
        "respects per-call and %-of-balance caps. Holds even if the kernel is malicious.",
        ["bucket", "caps", "b25", "b26"],
        "local",
    ),
    "C1": (
        "No value moves without a valid, unexpired, unreplayed receipt bound to the exact "
        "action and the on-chain manifest.",
        ["b02", "b03", "b04", "b05", "b06", "b08", "b20", "b21"],
        "local",
    ),
    "C2": (
        "The agent plane holds an empty capability set and reaches only the kernel socket.",
        [],
        "ci-containment",
    ),
    "C3": (
        "Untrusted ingress shrinks authority.",
        [],
        "ci-sandbox",
    ),
    "C4": (
        "Revocation is immediate for on-chain value.",
        ["b07"],
        "local",
    ),
    "C5": (
        "Kernel failure or policy error produces no effect.",
        [],
        "ci-sandbox",
    ),
    "C6": (
        "Evaluation is verifiable downstream from the receipt and the audit chain.",
        ["b02", "b03", "b04", "b05", "b06"],
        "local",
    ),
    "C7": (
        "A paused venue is unreachable and venue exposure is capped.",
        ["b17", "b24"],
        "local",
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
    vault_out = run([
        "cargo", "test", "--manifest-path",
        "contracts/near-vault/Cargo.toml",
    ])
    combined = core_out + "\n" + vault_out
    passed = passed_tests(combined)

    claims = {}
    for cid, (statement, tests, tier) in CLAIMS.items():
        if not tests:
            claims[cid] = {
                "statement": statement,
                "status": "SKIP",
                "reason": "not built in this window" if tier != "local" else "no tests",
                "tier": tier,
            }
            continue
        missing = [t for t in tests if not any(t in p for p in passed)]
        claims[cid] = {
            "statement": statement,
            "status": "PASS" if not missing else "FAIL",
            "missing_tests": missing,
            "tier": tier,
        }

    result = {
        "rustc": run(["rustc", "--version"]).strip(),
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
        print(f"  {cid}  {c['status']:5}  {c['statement'][:60]}")
    return 0 if all(c["status"] != "FAIL" for c in claims.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
