#!/usr/bin/env python3
"""Phase 0 gate: governance, paper, proofs, tooling."""
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "phase0-gate"

GOVERNANCE_FILES = [
    "docs/governance/program-charter.md",
    "docs/governance/problem-charter-template.md",
    "docs/governance/downstream-contract-bundle-template.md",
    "docs/governance/reviewer-roster.md",
    "docs/governance/reviewer-memo-template.md",
]

PAPER_FILES = [
    "paper/main.tex",
    "paper/claims-table.md",
]

PROOF_FILES = [
    "docs/security-proofs/obligations.md",
    "docs/security-proofs/README.md",
]

TOOLING_FILES = [
    ".sisyphus/scripts/validate-obligations-schema.py",
    ".sisyphus/scripts/validate-prior-art.py",
    ".sisyphus/scripts/validate-pins.py",
    ".sisyphus/scripts/validate-proof-skeletons.py",
    ".sisyphus/scripts/validate-bundle.py",
    ".sisyphus/scripts/validate-reviewer-memo.py",
]


def check_files(file_list):
    details = []
    ok = True
    for path in file_list:
        if os.path.exists(path):
            details.append(f"[OK] {path}")
        else:
            details.append(f"[MISSING] {path}")
            ok = False
    return ok, details


def subcheck_governance():
    return check_files(GOVERNANCE_FILES)


def subcheck_paper():
    return check_files(PAPER_FILES)


def subcheck_proofs():
    return check_files(PROOF_FILES)


def subcheck_tooling():
    return check_files(TOOLING_FILES)


def main():
    parser = argparse.ArgumentParser(description="Phase 0 gate")
    parser.add_argument("--check", default=None, choices=["governance", "paper", "proofs", "tooling"])
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks = {
        "governance": subcheck_governance,
        "paper": subcheck_paper,
        "proofs": subcheck_proofs,
        "tooling": subcheck_tooling,
    }

    run_gate(GATE_NAME, subchecks, args)


if __name__ == "__main__":
    main()
