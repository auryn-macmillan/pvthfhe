#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
"""p1-research-gate gate."""
import argparse
import importlib.util
import os
import re
from typing import Callable, cast

RunGate = Callable[[str, dict[str, Callable[[], tuple[bool, list[str]]]], argparse.Namespace], None]

_GATE_UTILS_PATH = os.path.join(os.path.dirname(__file__), '_gate_utils.py')
_GATE_UTILS_SPEC = importlib.util.spec_from_file_location('_gate_utils', _GATE_UTILS_PATH)
if _GATE_UTILS_SPEC is None or _GATE_UTILS_SPEC.loader is None:
    raise ImportError(f"unable to load gate utilities from {_GATE_UTILS_PATH}")
_gate_utils = importlib.util.module_from_spec(_GATE_UTILS_SPEC)
_GATE_UTILS_SPEC.loader.exec_module(_gate_utils)
run_gate = cast(RunGate, getattr(_gate_utils, 'run_gate'))

GATE_NAME = "p1-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_MATRIX = '.sisyphus/research/p1/prior-art.md'
THREAT_MODEL_PATH = '.sisyphus/research/p1/threat-model.md'
THEOREM_INVENTORY_PATH = 'docs/security-proofs/p1/theorem-inventory.md'
SCORECARD_PATH = '.sisyphus/research/p1/scorecard.md'

SUBCHECKS = ['prior-art', 'prior-art-matrix', 'novelty-gap', 'threat-model', 'theorem-inventory', 'scorecard']


def check_artifacts() -> tuple[bool, list[str]]:
    details: list[str] = []
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


def check_prior_art_matrix() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: prior-art-matrix"]
    if not os.path.exists(PRIOR_ART_MATRIX):
        return False, details + [f"[FAIL] missing required artifact: {PRIOR_ART_MATRIX}"]

    row_count = count_markdown_table_rows(PRIOR_ART_MATRIX)
    details.append(f"[OK] found matrix artifact: {PRIOR_ART_MATRIX}")
    if row_count < 10:
        details.append(f"[FAIL] prior-art matrix must contain at least 10 data rows; found {row_count}")
        return False, details

    details.append(f"[OK] prior-art matrix rows: {row_count}")
    return True, details


def check_novelty_gap() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: novelty-gap"]
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


def check_threat_model() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: threat-model"]
    if not os.path.exists(THREAT_MODEL_PATH):
        return False, details + [f"[FAIL] missing required artifact: {THREAT_MODEL_PATH}"]

    with open(THREAT_MODEL_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_sections = [
        "## Goal",
        "## Non-Goals",
        "## Required Theorems",
        "## Allowed Assumptions",
        "## Threat Model Matrix",
        "## Success Metrics",
        "## Downstream Outputs",
    ]
    required_markers = [
        "Adversary model",
        "Static corruption",
        "ROM",
        "QROM",
        "Simulation-soundness",
        "Knowledge soundness",
        "Extractor model",
        "Rewinding",
        "Straight-line",
        "P2",
        "P4",
        "q",
        "ring degree",
        "error bound",
    ]
    required_rows = [
        "| Adversary model |",
        "| Simulation-soundness |",
        "| Extractor model |",
    ]

    ok = True
    for section in required_sections:
        if section not in content:
            details.append(f"[FAIL] missing required section: {section}")
            ok = False
        else:
            details.append(f"[OK] found section: {section}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required threat-model marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found marker: {marker}")

    for row in required_rows:
        if row not in content:
            details.append(f"[FAIL] missing required threat-model row: {row}")
            ok = False
        else:
            details.append(f"[OK] found row: {row}")

    if ok:
        details.append(f"[OK] {THREAT_MODEL_PATH} meets requirements")

    return ok, details


def count_theorem_headings(path: str) -> int:
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    return len(re.findall(r'^##\s+T\d+\s*:', content, flags=re.MULTILINE))


def check_theorem_inventory() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: theorem-inventory"]
    if not os.path.exists(THEOREM_INVENTORY_PATH):
        return False, details + [f"[FAIL] missing required artifact: {THEOREM_INVENTORY_PATH}"]

    heading_count = count_theorem_headings(THEOREM_INVENTORY_PATH)
    details.append(f"[OK] found theorem inventory artifact: {THEOREM_INVENTORY_PATH}")
    if heading_count < 5:
        details.append(f"[FAIL] theorem inventory must contain at least 5 theorem headings; found {heading_count}")
        return False, details

    details.append(f"[OK] theorem heading count: {heading_count}")
    return True, details


def check_scorecard() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: scorecard"]
    if not os.path.exists(SCORECARD_PATH):
        return False, details + [f"[FAIL] missing required artifact: {SCORECARD_PATH}"]

    with open(SCORECARD_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        "## Weighted Criteria",
        "## Weighted Scores",
        "## Freeze Decision",
    ]
    required_markers = [
        "Primary:",
        "Fallback:",
    ]

    ok = True
    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required scorecard marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found marker: {marker}")

    if ok:
        details.append(f"[OK] {SCORECARD_PATH} meets requirements")

    return ok, details

def make_subcheck(name: str) -> Callable[[], tuple[bool, list[str]]]:
    def fn() -> tuple[bool, list[str]]:
        ok, details = check_artifacts()
        details.insert(0, f"subcheck: {name}")
        return ok, details
    fn.__name__ = name
    return fn


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name) for name in SUBCHECKS
    }
    subchecks_map['prior-art'] = check_prior_art_matrix
    subchecks_map['prior-art-matrix'] = check_prior_art_matrix
    subchecks_map['novelty-gap'] = check_novelty_gap
    subchecks_map['threat-model'] = check_threat_model
    subchecks_map['theorem-inventory'] = check_theorem_inventory
    subchecks_map['scorecard'] = check_scorecard
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
