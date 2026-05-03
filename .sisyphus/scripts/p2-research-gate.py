#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
"""p2-research-gate gate."""
import argparse
import importlib.util
import os
from pathlib import Path
from typing import Callable, cast

RunGate = Callable[[str, dict[str, Callable[[], tuple[bool, list[str]]]], argparse.Namespace], None]

_GATE_UTILS_PATH = os.path.join(os.path.dirname(__file__), '_gate_utils.py')
_GATE_UTILS_SPEC = importlib.util.spec_from_file_location('_gate_utils', _GATE_UTILS_PATH)
if _GATE_UTILS_SPEC is None or _GATE_UTILS_SPEC.loader is None:
    raise ImportError(f"unable to load gate utilities from {_GATE_UTILS_PATH}")
_gate_utils = importlib.util.module_from_spec(_GATE_UTILS_SPEC)
_GATE_UTILS_SPEC.loader.exec_module(_gate_utils)
run_gate = cast(RunGate, getattr(_gate_utils, 'run_gate'))

GATE_NAME = "p2-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_PATH = Path('.sisyphus/research/p2/prior-art.md')
NOVELTY_MEMO_PATH = Path('.sisyphus/research/p2/novelty-memo.md')
THREAT_MODEL_PATH = Path('.sisyphus/research/p2/threat-model.md')
THEOREM_INVENTORY_PATH = Path('docs/security-proofs/p2/theorem-inventory.md')
OBLIGATIONS_PATH = Path('docs/security-proofs/obligations.md')

SUBCHECKS = ['prior-art', 'novelty-gap', 'threat-model', 'prior-art-matrix', 'novelty-memo', 'theorem-inventory']


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


def make_subcheck(name: str) -> Callable[[], tuple[bool, list[str]]]:
    def fn() -> tuple[bool, list[str]]:
        ok, details = check_artifacts()
        details.insert(0, f"subcheck: {name}")
        return ok, details
    fn.__name__ = name
    return fn


def prior_art_matrix() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: prior-art-matrix"]
    ok = True

    if not PRIOR_ART_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {PRIOR_ART_PATH}"]

    details.append(f"[OK] found artifact: {PRIOR_ART_PATH}")
    content = PRIOR_ART_PATH.read_text(encoding="utf-8")
    lines = content.splitlines()

    header_index = next((i for i, line in enumerate(lines) if line.startswith('| Scheme |')), -1)
    separator_index = header_index + 1 if header_index >= 0 else -1
    table_rows: list[str] = []
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


def novelty_memo() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: novelty-memo"]
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


def threat_model() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: threat-model"]
    ok = True

    if not THREAT_MODEL_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {THREAT_MODEL_PATH}"]

    details.append(f"[OK] found artifact: {THREAT_MODEL_PATH}")
    content = THREAT_MODEL_PATH.read_text(encoding="utf-8")

    required_sections = [
        "Corruption Model",
        "Folding-Specific Threats",
        "Knowledge-Soundness",
        "P1 Consistency",
    ]
    for section in required_sections:
        if section in content:
            details.append(f"[OK] required section present: {section}")
        else:
            details.append(f"[FAIL] missing required section: {section}")
            ok = False

    return ok, details


def theorem_inventory() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: theorem-inventory"]
    ok = True

    if not THEOREM_INVENTORY_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {THEOREM_INVENTORY_PATH}"]

    details.append(f"[OK] found artifact: {THEOREM_INVENTORY_PATH}")
    content = THEOREM_INVENTORY_PATH.read_text(encoding="utf-8")

    import re
    thm_sections = re.findall(r'^## Theorem P2-T', content, re.MULTILINE)
    if len(thm_sections) >= 5:
        details.append(f"[OK] theorem sections found: {len(thm_sections)}")
    else:
        details.append(f"[FAIL] expected >=5 P2 theorem sections, found {len(thm_sections)}")
        ok = False

    if OBLIGATIONS_PATH.exists():
        obs_content = OBLIGATIONS_PATH.read_text(encoding="utf-8")
        p2_rows = [line for line in obs_content.splitlines() if line.startswith('| P2 |')]
        if len(p2_rows) >= 5:
            details.append(f"[OK] P2 obligation rows: {len(p2_rows)}")
        else:
            details.append(f"[FAIL] expected >=5 P2 rows in obligations.md, found {len(p2_rows)}")
            ok = False
    else:
        details.append(f"[FAIL] missing obligations file: {OBLIGATIONS_PATH}")
        ok = False

    return ok, details


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name)
        for name in SUBCHECKS
        if name not in ['prior-art-matrix', 'novelty-memo', 'threat-model']
    }
    subchecks_map['prior-art-matrix'] = prior_art_matrix
    subchecks_map['novelty-memo'] = novelty_memo
    subchecks_map['threat-model'] = threat_model
    subchecks_map['theorem-inventory'] = theorem_inventory
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
