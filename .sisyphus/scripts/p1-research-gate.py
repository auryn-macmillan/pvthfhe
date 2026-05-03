#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false
"""p1-research-gate gate."""
import argparse
import os
import re
import sys
from typing import Callable, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate  # type: ignore[reportMissingImports]

GATE_NAME = "p1-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_MATRIX = '.sisyphus/research/p1/prior-art.md'

SUBCHECKS = ['prior-art', 'prior-art-matrix', 'novelty-gap', 'threat-model']


def check_artifacts() -> Tuple[bool, List[str]]:
    details: List[str] = []
    ok = True
    for path in ARTIFACTS:
        if os.path.exists(path):
            details.append(f"[OK] {path}")
        else:
            details.append(f"[WARN] artifact not yet present (stub phase): {path}")
            # In stub phase, missing artifacts are warnings not failures
    return ok, details


def count_markdown_table_rows(path: str) -> int:
    with open(path, 'r', encoding='utf-8') as f:
        lines = [line.rstrip('\n') for line in f]

    in_table = False
    row_count = 0
    separator_seen = False
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith('|'):
            if in_table and separator_seen:
                break
            continue
        if not in_table:
            in_table = True
            continue
        if re.fullmatch(r"\|(?:\s*:?-{3,}:?\s*\|)+", stripped):
            separator_seen = True
            continue
        if separator_seen:
            row_count += 1
    return row_count


def check_prior_art_matrix() -> Tuple[bool, List[str]]:
    details: List[str] = ["subcheck: prior-art-matrix"]
    if not os.path.exists(PRIOR_ART_MATRIX):
        return False, details + [f"[FAIL] missing required artifact: {PRIOR_ART_MATRIX}"]

    row_count = count_markdown_table_rows(PRIOR_ART_MATRIX)
    details.append(f"[OK] found matrix artifact: {PRIOR_ART_MATRIX}")
    if row_count < 10:
        details.append(f"[FAIL] prior-art matrix must contain at least 10 data rows; found {row_count}")
        return False, details

    details.append(f"[OK] prior-art matrix rows: {row_count}")
    return True, details


def check_novelty_gap() -> Tuple[bool, List[str]]:
    details: List[str] = ["subcheck: novelty-gap"]
    memo_path = ".sisyphus/research/p1/novelty-memo.md"
    if not os.path.exists(memo_path):
        return False, details + [f"[FAIL] missing required artifact: {memo_path}"]
    
    with open(memo_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    required_headings = ["## Required Novelty", "## Aggressive Bets", "## Risk Register", "## Pivot Triggers"]
    ok = True
    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")
            
    if ok:
        details.append(f"[OK] {memo_path} meets requirements")
        
    return ok, details

def make_subcheck(name: str) -> Callable[[], Tuple[bool, List[str]]]:
    def fn() -> Tuple[bool, List[str]]:
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

    subchecks_map: Dict[str, Callable[[], Tuple[bool, List[str]]]] = {
        name: make_subcheck(name) for name in SUBCHECKS
    }
    _ = subchecks_map.__setitem__('prior-art', check_prior_art_matrix)
    _ = subchecks_map.__setitem__('prior-art-matrix', check_prior_art_matrix)
    _ = subchecks_map.__setitem__('novelty-gap', check_novelty_gap)
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
