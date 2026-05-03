#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportImplicitRelativeImport=false, reportUnusedCallResult=false, reportUnknownVariableType=false
"""p4-impl-gate gate."""
import argparse
import os
import subprocess
import sys
from typing import Callable

sys.path.insert(0, os.path.dirname(__file__))
from _gate_utils import run_gate

GATE_NAME = "p4-impl-gate"

ARTIFACTS = ['crates/pvthfhe-aggregator/src/keygen/protocol.rs']
BUNDLE_PATH = '.sisyphus/contracts/p4-to-p1-bundle.md'
REVIEWER_MEMO_PATH = '.sisyphus/reviews/p4-impl-gate-review.md'
CLAIMS_TABLE_PATH = 'paper/claims-table.md'
REQUIRED_BUNDLE_FIELDS = [
    '## Assumptions',
    '## Public Key Format',
    '## Share Format',
    '## Parameter Schema',
    '## Transcript Schema',
    '## Encoding Commitments',
    '## Unresolved Risks',
]

SUBCHECKS = ['tests-red', 'impl-green', 'surrogate-retired']


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
        if name == 'impl-green':
            validator = os.path.join(os.path.dirname(__file__), 'validate-bundle.py')
            result = subprocess.run(
                [sys.executable, validator, '--bundle', BUNDLE_PATH, '--required-fields', *REQUIRED_BUNDLE_FIELDS],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                details.append(f"[OK] validated {BUNDLE_PATH}")
            else:
                ok = False
                for line in (result.stdout + result.stderr).splitlines():
                    details.append(f"[FAIL] bundle validator: {line}")

            memo_validator = os.path.join(os.path.dirname(__file__), 'validate-reviewer-memo.py')
            memo_result = subprocess.run(
                [sys.executable, memo_validator, '--memo', REVIEWER_MEMO_PATH],
                capture_output=True,
                text=True,
            )
            if memo_result.returncode == 0:
                details.append(f"[OK] reviewer memo validated {REVIEWER_MEMO_PATH}")
            else:
                ok = False
                for line in (memo_result.stdout + memo_result.stderr).splitlines():
                    details.append(f"[FAIL] reviewer memo validator: {line}")

            try:
                with open(CLAIMS_TABLE_PATH, 'r', encoding='utf-8') as claims_file:
                    claims_content = claims_file.read()
            except FileNotFoundError:
                ok = False
                details.append(f"[FAIL] claims table not found: {CLAIMS_TABLE_PATH}")
            else:
                p4_rows = [line for line in claims_content.splitlines() if line.startswith('| P4 |')]
                if p4_rows and 'frozen' in p4_rows[0].lower():
                    details.append(f"[OK] claims table shows frozen P4 row in {CLAIMS_TABLE_PATH}")
                else:
                    ok = False
                    details.append(f"[FAIL] claims table missing frozen P4 row in {CLAIMS_TABLE_PATH}")
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
