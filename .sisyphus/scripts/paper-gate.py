#!/usr/bin/env python3
"""paper-gate gate."""
import argparse
import glob
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "paper-gate"

SUBCHECKS = [
    'claims-table',
    'theorem-consistency',
    'figures',
    'internal-reviews',
    'external-reviews',
    'submission-bundle',
]


def check_claims_table():
    details = []
    path = "paper/claims-table.md"
    if not os.path.exists(path):
        details.append(f"[FAIL] {path} missing")
        return False, details
    with open(path) as f:
        content = f.read()
    lines = [l for l in content.splitlines() if l.strip().startswith("|") and "Theorem-ID" not in l and "---" not in l]
    data_rows = [l for l in lines if "PROVED" in l.upper() or "proved" in l]
    if len(data_rows) < 10:
        details.append(f"[FAIL] claims-table has {len(data_rows)} PROVED rows, need ≥10")
        return False, details
    details.append(f"[OK] claims-table: {len(data_rows)} PROVED rows found")
    return True, details


def check_theorem_consistency():
    details = []
    path = "paper/main.tex"
    if not os.path.exists(path):
        details.append(f"[FAIL] {path} missing")
        return False, details
    with open(path) as f:
        content = f.read()
    count = content.count(r"\begin{theorem}")
    if count < 5:
        details.append(f"[FAIL] main.tex has {count} \\begin{{theorem}} environments, need ≥5")
        return False, details
    details.append(f"[OK] theorem-consistency: {count} theorem environments found")
    return True, details


def check_figures():
    details = []
    required = [
        "paper/figures/p4-bench.tex",
        "paper/figures/p1-bench.tex",
        "paper/figures/p2-bench.tex",
        "paper/figures/p3-bench.tex",
    ]
    ok = True
    for p in required:
        if os.path.exists(p):
            details.append(f"[OK] {p}")
        else:
            details.append(f"[FAIL] {p} missing")
            ok = False
    return ok, details


def check_internal_reviews():
    details = []
    files = glob.glob(".sisyphus/reviews/internal-*-final.md")
    passing = []
    for f in files:
        with open(f) as fh:
            if "VERDICT:" in fh.read():
                passing.append(f)
                details.append(f"[OK] {f} has VERDICT:")
            else:
                details.append(f"[WARN] {f} missing VERDICT:")
    if len(passing) < 3:
        details.append(f"[FAIL] need ≥3 internal reviews with VERDICT:, found {len(passing)}")
        return False, details
    details.append(f"[OK] internal-reviews: {len(passing)} reviews passed")
    return True, details


def check_external_reviews():
    details = []
    files = glob.glob(".sisyphus/reviews/external-*-final.md")
    passing = []
    for f in files:
        with open(f) as fh:
            if "VERDICT:" in fh.read():
                passing.append(f)
                details.append(f"[OK] {f} has VERDICT:")
            else:
                details.append(f"[WARN] {f} missing VERDICT:")
    if len(passing) < 1:
        details.append(f"[FAIL] need ≥1 external review with VERDICT:, found {len(passing)}")
        return False, details
    details.append(f"[OK] external-reviews: {len(passing)} reviews passed")
    return True, details


def check_submission_bundle():
    details = []
    path = "paper/submission"
    if os.path.isdir(path):
        contents = os.listdir(path)
        details.append(f"[OK] {path}/ exists ({len(contents)} files)")
        return True, details
    details.append(f"[FAIL] {path}/ directory missing")
    return False, details


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map = {
        'claims-table': check_claims_table,
        'theorem-consistency': check_theorem_consistency,
        'figures': check_figures,
        'internal-reviews': check_internal_reviews,
        'external-reviews': check_external_reviews,
        'submission-bundle': check_submission_bundle,
    }
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
