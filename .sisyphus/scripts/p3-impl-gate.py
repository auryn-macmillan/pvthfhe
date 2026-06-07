#!/usr/bin/env python3
"""p3-impl-gate gate."""
import argparse
import os
import re
import sys
sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "p3-impl-gate"

SUBCHECKS = ['tests-red', 'impl-green', 'surrogate-retired', 'proofs', 'bench']

SURROGATES = {
    "on-chain-verifier": "contracts/src/generated/HonkVerifier.sol",
    "api-leakage": "crates/pvthfhe-aggregator/src/keygen/protocol.rs",
    "aggregator-circuit": "circuits/aggregator_final/src/main.nr",
    "decrypt-circuit": "circuits/decrypt_share/src/main.nr",
}

FEATURE_FLAG_PAT = re.compile(r'#\[cfg\((not\()?feature\s*=\s*"real-')
SURROGATE_HEADER_PAT = re.compile(r'//\s*SURROGATE', re.IGNORECASE)


def check_tests_red():
    path = ".sisyphus/evidence/p3-impl/red-tests.txt"
    if not os.path.exists(path):
        return False, [f"[FAIL] evidence not found: {path}"]
    content = open(path).read()
    if "6 failed" in content:
        return True, [f"[OK] red-tests: 6 failed confirmed ({path})"]
    return False, [f"[FAIL] red-tests: '6 failed' not found in {path}"]


def check_impl_green():
    path = ".sisyphus/evidence/p3-impl/green-tests.txt"
    if not os.path.exists(path):
        return False, [f"[FAIL] evidence not found: {path}"]
    content = open(path).read()
    if "6 tests passed" in content or "6 passed" in content:
        return True, [f"[OK] impl-green: 6 tests passed confirmed ({path})"]
    return False, [f"[FAIL] impl-green: '6 tests passed' or '6 passed' not found in {path}"]


def check_surrogate_retired():
    """Check that all formerly-surrogate files are either retired (removed)
    or promoted to real implementations (no SURROGATE marker, no feature flag).

    PASS: file missing (retired) OR file exists without surrogate markers (real impl).
    FAIL: file exists AND still has SURROGATE annotation or feature gate (not yet retired).
    """
    details = []
    ok = True
    retired = 0
    promoted = 0
    for name, path in SURROGATES.items():
        if not os.path.exists(path):
            retired += 1
            details.append(f"[OK] {name}: retired (file removed)")
            continue
        content = open(path).read()
        has_feature_flag = bool(FEATURE_FLAG_PAT.search(content))
        has_surrogate_header = bool(SURROGATE_HEADER_PAT.search(content))
        if has_surrogate_header:
            details.append(f"[FAIL] {name}: {path} — still has SURROGATE marker (not yet retired)")
            ok = False
        elif has_feature_flag:
            details.append(f"[FAIL] {name}: {path} — still feature-gated (not yet promoted)")
            ok = False
        else:
            promoted += 1
            details.append(f"[OK] {name}: {path} — real implementation (no surrogate markers)")
    total = len(SURROGATES)
    details.append(f"[{'OK' if ok else 'FAIL'}] surrogate-retired: {retired} retired, {promoted} promoted, {total - retired - promoted} remaining surrogates out of {total}")
    return ok, details


def check_proofs():
    path = "docs/security-proofs/p3/advisor-verdict.md"
    if not os.path.exists(path):
        return False, [f"[FAIL] proofs verdict not found: {path}"]
    content = open(path).read()
    if "## VERDICT: APPROVE" in content:
        return True, [f"[OK] proofs: advisor verdict APPROVE found ({path})"]
    return False, [f"[FAIL] proofs: '## VERDICT: APPROVE' not found in {path}"]


def check_bench():
    path = "bench/p3/results-128-local.json"
    if not os.path.exists(path):
        return False, [f"[FAIL] bench results not found: {path}"]
    return True, [f"[OK] bench: {path} exists"]


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map = {
        'tests-red': check_tests_red,
        'impl-green': check_impl_green,
        'surrogate-retired': check_surrogate_retired,
        'proofs': check_proofs,
        'bench': check_bench,
    }
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
