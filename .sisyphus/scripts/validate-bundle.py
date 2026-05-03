#!/usr/bin/env python3
# pyright: reportUnusedCallResult=false, reportAny=false, reportDeprecated=false
"""Validate downstream contract bundles."""
import argparse
import sys
from collections.abc import Sequence

P4_TO_P1_REQUIRED_FIELDS = [
    "## Assumptions",
    "## Public Key Format",
    "## Share Format",
    "## Parameter Schema",
    "## Transcript Schema",
    "## Encoding Commitments",
    "## Unresolved Risks",
]
DEFAULT_REQUIRED_FIELDS = P4_TO_P1_REQUIRED_FIELDS


def check_bundle(bundle_path: str, required_fields: Sequence[str]) -> list[str]:
    errors: list[str] = []
    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        errors.append(f"bundle file not found: {bundle_path}")
        return errors

    for field in required_fields:
        if field not in content:
            errors.append(f"Missing required section: {field!r}")

    return errors


def check_charter_invariants(charter_path: str) -> list[str]:
    errors: list[str] = []
    required = ["## Review Cadence", "## Reviewer Model", "## Theorem-Proof Obligation"]
    try:
        with open(charter_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        errors.append(f"charter not found: {charter_path}")
        return errors

    for section in required:
        if section not in content:
            errors.append(f"Charter missing section: {section!r}")
    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate downstream contract bundles")
    parser.add_argument("path", nargs="?", default=None)
    parser.add_argument("--bundle", default=None)
    parser.add_argument("--required-fields", nargs="*", default=DEFAULT_REQUIRED_FIELDS)
    parser.add_argument("--check", nargs="*", default=[])
    parser.add_argument("--charters", nargs="*", default=["docs/governance/program-charter.md"])
    parser.add_argument("--research-dirs", nargs="*", default=[])
    parser.add_argument("--target", default=None)
    args = parser.parse_args()

    errors: list[str] = []
    bundle_path = args.bundle or args.path

    if bundle_path:
        errors.extend(check_bundle(bundle_path, args.required_fields))

    if "charter-invariants" in (args.check or []):
        for charter in args.charters:
            errors.extend(check_charter_invariants(charter))

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    print("PASS: bundle validation")
    sys.exit(0)


if __name__ == "__main__":
    main()
