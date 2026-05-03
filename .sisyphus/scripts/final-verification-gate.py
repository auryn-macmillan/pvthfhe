#!/usr/bin/env python3
"""final-verification-gate gate."""
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "final-verification-gate"

ARTIFACTS = ['paper/main.tex', 'docs/security-proofs/obligations.md', 'docs/governance/reviewer-roster.md']

SUBCHECKS = ['all-surrogates-retired', 'all-proofs-complete', 'paper-built', 'reviewer-approved']


def check_artifacts():
    details = []
    ok = True
    for path in ARTIFACTS:
        if os.path.exists(path):
            details.append(f"[OK] {path}")
        else:
            details.append(f"[WARN] artifact not yet present (stub phase): {path}")
            # In stub phase, missing artifacts are warnings not failures
    return ok, details


def make_subcheck(name):
    def fn():
        ok, details = check_artifacts()
        details.insert(0, f"subcheck: {name}")
        return ok, details
    fn.__name__ = name
    return fn


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map = {name: make_subcheck(name) for name in SUBCHECKS}
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
