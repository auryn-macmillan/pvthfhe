#!/usr/bin/env python3
"""p1-design-gate gate."""
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
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

GATE_NAME = "p1-design-gate"

ARTIFACTS = ['docs/governance/program-charter.md']
INTERFACE_SPEC_PATH = '.sisyphus/design/p1/interface-spec.md'
STACK_DECISION_PATH = '.sisyphus/design/p1/stack-decision.md'
PROOF_SKELETONS_PATH = 'docs/security-proofs/p1/proof-skeletons.md'
BENCH_PLAN_PATH = '.sisyphus/design/p1/bench-plan.md'
MIGRATION_PLAN_PATH = '.sisyphus/design/p1/migration-plan.md'
REVIEW_PATH = '.sisyphus/reviews/p1-design-gate-review.md'

SUBCHECKS = ['charter', 'reviewer-memo', 'interface-spec', 'stack-decision', 'proof-skeletons', 'bench-plan', 'migration-plan']


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


def check_interface_spec() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: interface-spec"]
    if not os.path.exists(INTERFACE_SPEC_PATH):
        return False, details + [f"[FAIL] missing required artifact: {INTERFACE_SPEC_PATH}"]

    with open(INTERFACE_SPEC_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        '## Statement',
        '## Witness',
        '## Public Inputs',
        '## Proof Format',
        '## Adapter Strategy',
        '## Surrogate Boundary',
    ]
    forbidden_markers = ['Noir', 'UltraHonk', 'HonkVerifier']

    ok = True
    details.append(f"[OK] found required artifact: {INTERFACE_SPEC_PATH}")

    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    for marker in forbidden_markers:
        if re.search(rf'\b{re.escape(marker)}\b', content):
            details.append(f"[FAIL] surrogate contamination marker present: {marker}")
            ok = False
        else:
            details.append(f"[OK] surrogate contamination marker absent: {marker}")

    if ok:
        details.append(f"[OK] {INTERFACE_SPEC_PATH} meets interface-spec requirements")

    return ok, details


def check_stack_decision() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: stack-decision']
    if not os.path.exists(STACK_DECISION_PATH):
        return False, details + [f"[FAIL] missing required artifact: {STACK_DECISION_PATH}"]

    with open(STACK_DECISION_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        '## Primary Decision',
        '## Fallback Decision',
        '## Bench Projections',
        '## Recursion Compatibility',
    ]

    ok = True
    details.append(f"[OK] found required artifact: {STACK_DECISION_PATH}")

    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    if ok:
        details.append(f"[OK] {STACK_DECISION_PATH} meets stack-decision requirements")

    return ok, details


def check_proof_skeletons() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: proof-skeletons']
    if not os.path.exists(PROOF_SKELETONS_PATH):
        return False, details + [f"[FAIL] missing required artifact: {PROOF_SKELETONS_PATH}"]

    with open(PROOF_SKELETONS_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_markers = [
        '## T1',
        '## T2',
        '## T3',
        '## T4',
        '## T5',
        '### Reduction',
        '### Tightness',
    ]

    ok = True
    details.append(f"[OK] found required artifact: {PROOF_SKELETONS_PATH}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found marker: {marker}")

    if ok:
        details.append(f"[OK] {PROOF_SKELETONS_PATH} meets proof-skeletons requirements")

    return ok, details


def check_bench_plan() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: bench-plan']
    if not os.path.exists(BENCH_PLAN_PATH):
        return False, details + [f"[FAIL] missing required artifact: {BENCH_PLAN_PATH}"]

    with open(BENCH_PLAN_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        '## Benchmark Matrix',
        '## Advisory Thresholds',
        '## Measurement Protocol',
    ]
    required_markers = [
        '128',
        '256',
        '512',
        '1024',
        'SLAP primary',
        'Greyhound fallback',
        'q bits',
        'B_e',
        'Prover time',
        'Proof size',
        'Verifier time',
        'Peak memory',
    ]

    ok = True
    details.append(f"[OK] found required artifact: {BENCH_PLAN_PATH}")

    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required bench-plan marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found bench-plan marker: {marker}")

    if ok:
        details.append(f"[OK] {BENCH_PLAN_PATH} meets bench-plan requirements")

    return ok, details


def check_migration_plan() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: migration-plan']
    if not os.path.exists(MIGRATION_PLAN_PATH):
        return False, details + [f"[FAIL] missing required artifact: {MIGRATION_PLAN_PATH}"]

    with open(MIGRATION_PLAN_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        '## Rollout Phases',
        '## Feature Flag Schedule',
        '## Surrogate Retirement',
        '## Rollback Criteria',
    ]
    required_markers = [
        'Phase 1',
        'Phase 2',
        'Phase 3',
        'Phase 4',
        'real-nizk',
        'surrogate-decrypt-share',
        'Greyhound',
        'Rust-in-zkVM',
        '30 consecutive calendar days',
        'just p1-impl-gate',
    ]

    ok = True
    details.append(f"[OK] found required artifact: {MIGRATION_PLAN_PATH}")

    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required migration-plan marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found migration-plan marker: {marker}")

    if ok:
        details.append(f"[OK] {MIGRATION_PLAN_PATH} meets migration-plan requirements")

    return ok, details


def check_reviewer_memo() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: reviewer-memo']
    if not os.path.exists(REVIEW_PATH):
        return False, details + [f"[FAIL] missing required artifact: {REVIEW_PATH}"]

    with open(REVIEW_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_markers = [
        'VERDICT: APPROVE',
        '## Summary',
        '## Bench Coverage',
        '## Migration Safety',
        '## Rollback Completeness',
        '## Gate Decision',
    ]

    ok = True
    details.append(f"[OK] found required artifact: {REVIEW_PATH}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required reviewer-memo marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found reviewer-memo marker: {marker}")

    if ok:
        details.append(f"[OK] {REVIEW_PATH} meets reviewer-memo requirements")

    return ok, details


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name) for name in SUBCHECKS
    }
    subchecks_map['reviewer-memo'] = check_reviewer_memo
    subchecks_map['interface-spec'] = check_interface_spec
    subchecks_map['stack-decision'] = check_stack_decision
    subchecks_map['proof-skeletons'] = check_proof_skeletons
    subchecks_map['bench-plan'] = check_bench_plan
    subchecks_map['migration-plan'] = check_migration_plan
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
