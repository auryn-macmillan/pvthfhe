#!/usr/bin/env python3
"""Verify docs/security-proofs/** files contain required fields."""
import argparse
import os
import sys
from collections.abc import Sequence
from typing import cast

DEFAULT_DIR = "docs/security-proofs"
DEFAULT_REQUIRED_FIELDS = ["## Theorem", "## Proof", "Status"]
THEOREM_HEADER = "## Theorem"


def check_file(path: str, required_fields: Sequence[str]) -> tuple[list[str], int]:
    errors: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        errors.append(f"Cannot read {path}: {e}")
        return errors, 0

    for field in required_fields:
        if field not in content:
            errors.append(f"{path}: missing required field/section '{field}'")

    return errors, content.count(THEOREM_HEADER)


def main():
    parser = argparse.ArgumentParser(description="Validate proof skeleton files")
    _ = parser.add_argument("dir", nargs="?", default=None)
    _ = parser.add_argument("--dir", dest="dir_flag", default=None)
    _ = parser.add_argument("--min-thms", type=int, default=1)
    _ = parser.add_argument("--require-fields", nargs="*", default=DEFAULT_REQUIRED_FIELDS)
    args = parser.parse_args()

    dir_arg = cast(str | None, args.dir)
    dir_flag = cast(str | None, args.dir_flag)
    min_thms = cast(int, args.min_thms)
    require_fields = cast(list[str], args.require_fields)
    target_dir = dir_flag or dir_arg or DEFAULT_DIR

    if not os.path.isdir(target_dir):
        print(f"FAIL: directory not found: {target_dir}")
        sys.exit(1)

    md_files: list[str] = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if fname.endswith(".md"):
                md_files.append(os.path.join(root, fname))

    if not md_files:
        print(f"WARN: no .md files found in {target_dir}")
        sys.exit(0)

    all_errors: list[str] = []
    theorem_count = 0
    for path in md_files:
        errs, file_theorem_count = check_file(path, require_fields)
        all_errors.extend(errs)
        theorem_count += file_theorem_count

    if theorem_count < min_thms:
        all_errors.append(
            f"found {theorem_count} theorem section(s), requires at least {min_thms}"
        )

    if all_errors:
        for e in all_errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    print(
        f"PASS: proof skeletons ({len(md_files)} files checked, {theorem_count} theorem sections)"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
