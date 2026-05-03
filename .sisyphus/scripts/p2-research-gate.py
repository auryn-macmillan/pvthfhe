#!/usr/bin/env python3
"""p2-research-gate gate."""
import argparse
import importlib
import os
from pathlib import Path
import sys
from typing import Callable
sys.path.insert(0, os.path.dirname(__file__))

run_gate = importlib.import_module("_gate_utils").run_gate

GATE_NAME = "p2-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_PATH = Path('.sisyphus/research/p2/prior-art.md')
NOVELTY_MEMO_PATH = Path('.sisyphus/research/p2/novelty-memo.md')

SUBCHECKS = ['prior-art', 'novelty-gap', 'threat-model', 'prior-art-matrix', 'novelty-memo']


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


def prior_art_matrix():
    details = ["subcheck: prior-art-matrix"]
    ok = True

    if not PRIOR_ART_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {PRIOR_ART_PATH}"]

    details.append(f"[OK] found artifact: {PRIOR_ART_PATH}")
    content = PRIOR_ART_PATH.read_text(encoding="utf-8")
    lines = content.splitlines()

    header_index = next((i for i, line in enumerate(lines) if line.startswith('| Scheme |')), -1)
    separator_index = header_index + 1 if header_index >= 0 else -1
    table_rows = []
    if header_index >= 0 and separator_index < len(lines):
        for line in lines[separator_index + 1:]:
            if not line.startswith('|'):
                break
            table_rows.append(line)

    if len(table_rows) >= 8:
        details.append(f"[OK] data rows in matrix: {len(table_rows)}")
    else:
        details.append(f"[FAIL] expected at least 8 data rows, found {len(table_rows)}")
        ok = False

    header_line = lines[header_index] if header_index >= 0 else ''
    required_columns = ['RLWE-native?', 'Verifier-cost-on-chain']
    for column in required_columns:
        if column in header_line:
            details.append(f"[OK] required column present: {column}")
        else:
            details.append(f"[FAIL] missing required column: {column}")
            ok = False

    if any('Rust-in-zkVM' in row for row in table_rows):
        details.append('[OK] Rust-in-zkVM row present')
    else:
        details.append('[FAIL] Rust-in-zkVM row missing')
        ok = False

    return ok, details


def novelty_memo():
    details = ["subcheck: novelty-memo"]
    ok = True

    if not NOVELTY_MEMO_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {NOVELTY_MEMO_PATH}"]

    details.append(f"[OK] found artifact: {NOVELTY_MEMO_PATH}")
    content = NOVELTY_MEMO_PATH.read_text(encoding="utf-8")
    
    required_sections = [
        "Required Novelty",
        "Aggressive Bets",
        "Risk Register",
        "Pivot Triggers"
    ]
    for section in required_sections:
        if section in content:
            details.append(f"[OK] required section present: {section}")
        else:
            details.append(f"[FAIL] missing required section: {section}")
            ok = False

    if "1. **" in content:
        details.append("[OK] found >=1 aggressive bet")
    else:
        details.append("[FAIL] aggressive bet missing")
        ok = False

    return ok, details


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    parser.add_argument("--check", default=None, choices=SUBCHECKS)
    parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name)
        for name in SUBCHECKS
        if name not in ['prior-art-matrix', 'novelty-memo']
    }
    subchecks_map['prior-art-matrix'] = prior_art_matrix
    subchecks_map['novelty-memo'] = novelty_memo
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
