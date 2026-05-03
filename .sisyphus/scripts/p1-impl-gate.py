#!/usr/bin/env python3
"""p1-impl-gate gate — real subchecks for P1 implementation gate."""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate  # noqa: E402 (local import after path fix)


GATE_NAME = "p1-impl-gate"

SUBCHECKS = [
    "tests-pass",
    "adversarial-tests-pass",
    "bench-results-exist",
    "proofs-exist",
    "review-approve",
    "bundle-exists",
]


# ---------------------------------------------------------------------------
# Subcheck implementations
# ---------------------------------------------------------------------------

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def check_tests_pass():
    details = []
    result = _run(
        ["cargo", "test", "-p", "pvthfhe-fhe", "--features=real-nizk"],
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    )
    ok = result.returncode == 0
    details.append(f"exit code: {result.returncode}")
    if result.stdout:
        details.extend(result.stdout.splitlines()[-20:])
    if result.stderr:
        details.extend(result.stderr.splitlines()[-20:])
    return ok, details


def check_adversarial_tests_pass():
    details = []
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    adv_file = os.path.join(
        repo_root, "crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs"
    )
    if not os.path.exists(adv_file):
        return False, [f"[FAIL] adversarial test file not found: {adv_file}"]
    details.append(f"[OK] adversarial test file exists: {adv_file}")

    result = _run(
        [
            "cargo",
            "test",
            "-p",
            "pvthfhe-fhe",
            "--features=real-nizk",
            "lattice_nizk_adversarial",
        ],
        cwd=repo_root,
    )
    ok = result.returncode == 0
    details.append(f"exit code: {result.returncode}")
    if result.stdout:
        details.extend(result.stdout.splitlines()[-20:])
    if result.stderr:
        details.extend(result.stderr.splitlines()[-20:])
    return ok, details


def check_bench_results_exist():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    required = [
        "bench/p1/results-128.json",
        "bench/p1/results-512.json",
        "bench/p1/results-1024.json",
    ]
    details = []
    ok = True
    for rel in required:
        path = os.path.join(repo_root, rel)
        if os.path.exists(path):
            details.append(f"[OK] {rel}")
        else:
            details.append(f"[FAIL] missing: {rel}")
            ok = False
    return ok, details


def check_proofs_exist():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    required = [
        "docs/security-proofs/p1/T1.md",
        "docs/security-proofs/p1/T2.md",
        "docs/security-proofs/p1/T3.md",
        "docs/security-proofs/p1/T4.md",
        "docs/security-proofs/p1/T5.md",
    ]
    details = []
    ok = True
    for rel in required:
        path = os.path.join(repo_root, rel)
        if os.path.exists(path):
            details.append(f"[OK] {rel}")
        else:
            details.append(f"[FAIL] missing: {rel}")
            ok = False
    return ok, details


def check_review_approve():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    review_path = os.path.join(
        repo_root, ".sisyphus/reviews/p1-proofs-review.md"
    )
    if not os.path.exists(review_path):
        return False, [f"[FAIL] review file not found: {review_path}"]
    with open(review_path, encoding="utf-8") as f:
        content = f.read()
    if "VERDICT: APPROVE" in content:
        return True, [f"[OK] VERDICT: APPROVE found in {review_path}"]
    return False, [f"[FAIL] VERDICT: APPROVE not found in {review_path}"]


def check_bundle_exists():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    bundle_path = os.path.join(
        repo_root, ".sisyphus/contracts/p1-to-p2-bundle.md"
    )
    if os.path.exists(bundle_path):
        return True, [f"[OK] bundle exists: {bundle_path}"]
    return False, [f"[FAIL] bundle not found: {bundle_path}"]


# ---------------------------------------------------------------------------
# Build subchecks_map
# ---------------------------------------------------------------------------

def build_subchecks():
    return {
        "tests-pass": check_tests_pass,
        "adversarial-tests-pass": check_adversarial_tests_pass,
        "bench-results-exist": check_bench_results_exist,
        "proofs-exist": check_proofs_exist,
        "review-approve": check_review_approve,
        "bundle-exists": check_bundle_exists,
    }


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map = build_subchecks()
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
