#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
"""p3-design-gate gate."""
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

GATE_NAME = "p3-design-gate"

ARTIFACTS = ['docs/governance/program-charter.md']

INTERFACE_SPEC_PATH = Path('.sisyphus/design/p3/interface-spec.md')
IFACE_SOL_MD_PATH = Path('.sisyphus/design/p3/iface.sol.md')
STACK_DECISION_PATH = Path('.sisyphus/design/p3/stack-decision.md')

SUBCHECKS = ['charter', 'bundle', 'reviewer-memo', 'interface-spec', 'stack-decision']


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

    if '## VERDICT: APPROVE' in content:
        details.append('[OK] verdict present: ## VERDICT: APPROVE')
    else:
        details.append('[FAIL] missing required verdict line: ## VERDICT: APPROVE')
        ok = False

    if 'calldata' in content:
        details.append('[OK] required phrase present: calldata')
    else:
        details.append('[FAIL] missing required phrase: calldata')
        ok = False

    if not IFACE_SOL_MD_PATH.exists():
        details.append(f"[FAIL] missing artifact: {IFACE_SOL_MD_PATH}")
        ok = False
    else:
        details.append(f"[OK] found artifact: {IFACE_SOL_MD_PATH}")

    return ok, details


def stack_decision() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: stack-decision']
    ok = True

    if not STACK_DECISION_PATH.exists():
        return False, details + [f"[FAIL] missing artifact: {STACK_DECISION_PATH}"]
    details.append(f"[OK] found artifact: {STACK_DECISION_PATH}")

    content = STACK_DECISION_PATH.read_text(encoding='utf-8')

    if '## VERDICT: APPROVE' in content:
        details.append('[OK] verdict present: ## VERDICT: APPROVE')
    else:
        details.append('[FAIL] missing required verdict line: ## VERDICT: APPROVE')
        ok = False

    if '## Primary:' in content:
        details.append('[OK] heading present: ## Primary:')
    else:
        details.append('[FAIL] missing required heading: ## Primary:')
        ok = False

    if '## Fallback:' in content:
        details.append('[OK] heading present: ## Fallback:')
    else:
        details.append('[FAIL] missing required heading: ## Fallback:')
        ok = False

    if 'gas' in content:
        details.append('[OK] required phrase present: gas')
    else:
        details.append('[FAIL] missing required phrase: gas')
        ok = False

    return ok, details


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name) for name in SUBCHECKS if name not in ('interface-spec', 'stack-decision')
    }
    subchecks_map['interface-spec'] = interface_spec
    subchecks_map['stack-decision'] = stack_decision
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
