#!/usr/bin/env python3
"""p2-impl-gate — Implementation completeness gate for P2 (LatticeFold+ surrogate)."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "p2-impl-gate"

ROOT = Path(__file__).resolve().parents[2]

SUBCHECKS = [
    "tests-pass",
    "adversarial-tests-pass",
    "proofs-exist",
    "bench-results-exist",
    "downstream-bundle",
]

BUNDLE_SECTION_HEADERS = [
    "## 1. Frozen Accumulator Format",
    "## 2. On-Chain Verifier Op-Budget",
    "## 3. Public-Input Encoding",
    "## 4. Security Caveats",
    "## 5. Regression Baseline",
    "## 6. Gas Projections",
    "## 7. Recursion Path",
]


def check_tests_pass() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: tests-pass"]
    cmd = [
        "cargo", "test",
        "-p", "pvthfhe-aggregator",
        "--features=real-folding",
        "--",
        "--test-threads=4",
    ]
    details.append(f"[RUN] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    if result.returncode == 0:
        details.append("[OK] cargo test -p pvthfhe-aggregator --features=real-folding exited 0")
        return True, details
    details.append(f"[FAIL] exit code {result.returncode}")
    if result.stdout:
        details.append(f"[stdout] {result.stdout[-2000:]}")
    if result.stderr:
        details.append(f"[stderr] {result.stderr[-2000:]}")
    return False, details


def check_adversarial_tests_pass() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: adversarial-tests-pass"]
    evidence_path = ROOT / ".sisyphus/evidence/p2-impl/adversarial.txt"
    if not evidence_path.exists():
        details.append(f"[FAIL] missing evidence file: {evidence_path}")
        return False, details
    details.append(f"[OK] found: {evidence_path}")
    content = evidence_path.read_text(encoding="utf-8")
    if "15 passed" in content:
        details.append("[OK] adversarial.txt contains '15 passed'")
        return True, details
    details.append("[FAIL] adversarial.txt does not contain '15 passed'")
    details.append(f"[content excerpt] {content[:500]}")
    return False, details


def check_proofs_exist() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: proofs-exist"]
    ok = True
    for i in range(1, 6):
        path = ROOT / f"docs/security-proofs/p2/T{i}.md"
        if not path.exists():
            details.append(f"[FAIL] missing: {path}")
            ok = False
            continue
        content = path.read_text(encoding="utf-8")
        if "VERDICT: APPROVE" in content:
            details.append(f"[OK] T{i}.md exists and contains VERDICT: APPROVE")
        else:
            details.append(f"[FAIL] T{i}.md exists but missing VERDICT: APPROVE")
            ok = False
    return ok, details


def check_bench_results_exist() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: bench-results-exist"]
    ok = True
    for size in ["128", "512", "1024"]:
        path = ROOT / f"bench/p2/results-{size}.json"
        if path.exists():
            details.append(f"[OK] {path}")
        else:
            details.append(f"[FAIL] missing: {path}")
            ok = False
    return ok, details


def check_downstream_bundle() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: downstream-bundle"]
    bundle_path = ROOT / ".sisyphus/contracts/p2-to-p3-bundle.md"
    if not bundle_path.exists():
        details.append(f"[FAIL] missing: {bundle_path}")
        return False, details
    details.append(f"[OK] found: {bundle_path}")
    content = bundle_path.read_text(encoding="utf-8")
    ok = True
    for header in BUNDLE_SECTION_HEADERS:
        if header in content:
            details.append(f"[OK] section present: {header!r}")
        else:
            details.append(f"[FAIL] missing section: {header!r}")
            ok = False
    if "VERDICT: APPROVE" in content:
        details.append("[OK] bundle contains VERDICT: APPROVE")
    else:
        details.append("[FAIL] bundle missing VERDICT: APPROVE")
        ok = False
    return ok, details


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, object] = {
        "tests-pass": check_tests_pass,
        "adversarial-tests-pass": check_adversarial_tests_pass,
        "proofs-exist": check_proofs_exist,
        "bench-results-exist": check_bench_results_exist,
        "downstream-bundle": check_downstream_bundle,
    }
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
