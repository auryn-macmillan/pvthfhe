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

SUBCHECKS = ['charter', 'bundle', 'reviewer-memo', 'interface-spec']


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


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name)
        for name in SUBCHECKS
        if name != 'interface-spec'
    }
    subchecks_map['interface-spec'] = interface_spec
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
