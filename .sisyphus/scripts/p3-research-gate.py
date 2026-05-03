#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
"""p3-research-gate gate."""
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

GATE_NAME = "p3-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_PATH = Path('.sisyphus/research/p3/prior-art.md')
NOVELTY_MEMO_PATH = Path('.sisyphus/research/p3/novelty-memo.md')
THREAT_MODEL_PATH = Path('.sisyphus/research/p3/threat-model.md')

SUBCHECKS = ['prior-art', 'novelty-gap', 'threat-model', 'prior-art-matrix', 'novelty-memo']


def check_artifacts() -> tuple[bool, list[str]]:
    details: list[str] = []
    ok = True
    for path in ARTIFACTS:
        if os.path.exists(path):
            details.append(f"[OK] {path}")
        else:
            details.append(f"[WARN] artifact not yet present (stub phase): {path}")
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
    if not PRIOR_ART_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {PRIOR_ART_PATH}"]

    content = PRIOR_ART_PATH.read_text(encoding='utf-8')
    lines = content.splitlines()
    table_lines = [line for line in lines if line.strip().startswith('|')]

    ok = True
    details.append(f"[OK] found artifact: {PRIOR_ART_PATH}")

    if len(table_lines) >= 10:
        details.append(f"[OK] found >=8 matrix entries by pipe-line count: {len(table_lines)}")
    else:
        details.append(f"[FAIL] expected at least 8 matrix entries (>=10 pipe lines incl. header/separator), found {len(table_lines)}")
        ok = False

    if 'Rust-in-zkVM' in content:
        details.append('[OK] Rust-in-zkVM row present')
    else:
        details.append('[FAIL] Rust-in-zkVM row missing')
        ok = False

    if 'VERDICT: APPROVE' in content:
        details.append('[OK] verdict present: VERDICT: APPROVE')
    else:
        details.append('[FAIL] missing required verdict line: VERDICT: APPROVE')
        ok = False

    return ok, details


def novelty_memo() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: novelty-memo"]
    if not NOVELTY_MEMO_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {NOVELTY_MEMO_PATH}"]

    content = NOVELTY_MEMO_PATH.read_text(encoding='utf-8')
    ok = True
    details.append(f"[OK] found artifact: {NOVELTY_MEMO_PATH}")

    required_headers = [
        "## Gap (a): On-chain accumulator verification within gas budget",
        "## Gap (b): Lattice-native EVM operations",
        "## Gap (c): Batched session verification",
        "## Gap (d): Trust assumptions",
        "## Aggressive Bets",
        "## Pivot Triggers"
    ]

    for header in required_headers:
        if header in content:
            details.append(f"[OK] Header present: {header}")
        else:
            details.append(f"[FAIL] Missing header: {header}")
            ok = False

    if 'VERDICT: APPROVE' in content:
        details.append('[OK] verdict present: VERDICT: APPROVE')
    else:
        details.append('[FAIL] missing required verdict line: VERDICT: APPROVE')
        ok = False

    return ok, details


def threat_model() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: threat-model"]
    if not THREAT_MODEL_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {THREAT_MODEL_PATH}"]

    content = THREAT_MODEL_PATH.read_text(encoding='utf-8')
    ok = True
    details.append(f"[OK] found artifact: {THREAT_MODEL_PATH}")

    required_headers = [
        '## Corruption Model (inherited from P2)',
        '## P3-Specific Threats',
        '### Malicious Prover with Chosen Ciphertexts',
        '### MEV / Reorg Interaction',
        '### Calldata Manipulation',
        '### On-Chain Verifier Bug Exploitation',
        '### Trusted Setup Ceremony Assumptions',
        '## P2 Consistency Check',
        '## VERDICT: APPROVE',
    ]
    for header in required_headers:
        if header in content:
            details.append(f"[OK] required heading present: {header}")
        else:
            details.append(f"[FAIL] missing required heading: {header}")
            ok = False

    required_p2_phrases = [
        'q=65537',
        'N=1024',
        'B_e=17',
        'corruption model carried forward',
        'ternary challenge space preserved',
    ]
    for phrase in required_p2_phrases:
        if phrase in content:
            details.append(f"[OK] P2 consistency phrase present: {phrase}")
        else:
            details.append(f"[FAIL] missing P2 consistency phrase: {phrase}")
            ok = False

    return ok, details


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument('--check', default=None, choices=SUBCHECKS)
    _ = parser.add_argument('--stub', action='store_true', help='Always PASS (stub mode)')
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name)
        for name in SUBCHECKS
        if name not in ['prior-art-matrix', 'novelty-memo', 'threat-model']
    }
    subchecks_map['prior-art-matrix'] = prior_art_matrix
    subchecks_map['novelty-memo'] = novelty_memo
    subchecks_map['threat-model'] = threat_model
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == '__main__':
    main()
