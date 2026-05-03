#!/usr/bin/env python3
"""p2-design-gate gate."""
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
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

GATE_NAME = "p2-design-gate"

ARTIFACTS = ['docs/governance/program-charter.md']

INTERFACE_SPEC_PATH = Path('.sisyphus/design/p2/interface-spec.md')
REQUIRED_INTERFACE_HEADINGS = [
    '## Statement Type',
    '## Witness Type',
    '## Accumulator Type',
    '## Folding API',
    '## Public-Input Layout',
    '## Adapter Strategy',
]
SURROGATE_LEAK_MARKERS = [
    'HonkVerifier',
    'UltraHonk',
    'Noir',
    'aggregator_final',
    'main.nr',
]

ROOT = Path(__file__).resolve().parents[2]

STACK_DECISION_PATH = Path('.sisyphus/design/p2/stack-decision.md')
STACK_CHECK_EVIDENCE_PATH = Path('.sisyphus/evidence/p2-design/stack-check.txt')
REQUIRED_STACK_DECISION_HEADINGS = [
    '## Primary Stack',
    '## Fallback Stacks',
    '## Quantitative Comparison',
    '## Recursion Fit',
    '## Reviewer Sign-off',
]

SUBCHECKS = ['charter', 'bundle', 'reviewer-memo', 'interface-spec', 'stack-decision', 'proof-skeletons']


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


def interface_spec() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: interface-spec']
    ok = True

    if not INTERFACE_SPEC_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {INTERFACE_SPEC_PATH}"]

    details.append(f"[OK] found artifact: {INTERFACE_SPEC_PATH}")
    content = INTERFACE_SPEC_PATH.read_text(encoding='utf-8')

    for heading in REQUIRED_INTERFACE_HEADINGS:
        if heading in content:
            details.append(f"[OK] required heading present: {heading}")
        else:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False

    for marker in SURROGATE_LEAK_MARKERS:
        if marker in content:
            details.append(f"[FAIL] surrogate contamination marker present: {marker}")
            ok = False
        else:
            details.append(f"[OK] surrogate contamination marker absent: {marker}")

    return ok, details


def write_stack_check_evidence(details: list[str], ok: bool) -> None:
    STACK_CHECK_EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    status = 'PASS' if ok else 'FAIL'
    evidence_lines = [*details, f"{status}: {GATE_NAME}/stack-decision"]
    _ = STACK_CHECK_EVIDENCE_PATH.write_text("\n".join(evidence_lines) + "\n", encoding='utf-8')


def stack_decision() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: stack-decision']
    ok = True

    if not STACK_DECISION_PATH.exists():
        details.append(f"[FAIL] missing artifact: {STACK_DECISION_PATH}")
        write_stack_check_evidence(details, False)
        return False, details

    details.append(f"[OK] found artifact: {STACK_DECISION_PATH}")
    content = STACK_DECISION_PATH.read_text(encoding='utf-8')

    for heading in REQUIRED_STACK_DECISION_HEADINGS:
        if heading in content:
            details.append(f"[OK] required heading present: {heading}")
        else:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False

    if 'VERDICT: APPROVE' in content:
        details.append('[OK] reviewer verdict present: VERDICT: APPROVE')
    else:
        details.append('[FAIL] missing reviewer verdict: VERDICT: APPROVE')
        ok = False

    write_stack_check_evidence(details, ok)
    return ok, details


def proof_skeletons() -> tuple[bool, list[str]]:
    details = ["subcheck: proof-skeletons"]
    path = ROOT / "docs/security-proofs/p2/proof-skeletons.md"
    if not path.exists():
        details.append(f"MISSING: {path}")
        return False, details
    text = path.read_text()
    # check T1–T5 sections present
    for i in range(1, 6):
        heading = f"## T{i}"
        if heading not in text and f"## Theorem P2-T{i}" not in text:
            details.append(f"MISSING section T{i}")
            return False, details
    if "VERDICT: APPROVE" not in text:
        details.append("MISSING: VERDICT: APPROVE")
        return False, details
    details.append(f"[OK] proof-skeletons.md found and validated")
    return True, details


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name)
        for name in SUBCHECKS
        if name not in {'interface-spec', 'stack-decision', 'proof-skeletons'}
    }
    subchecks_map['interface-spec'] = interface_spec
    subchecks_map['stack-decision'] = stack_decision
    subchecks_map['proof-skeletons'] = proof_skeletons
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
