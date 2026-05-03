#!/usr/bin/env python3
"""Verify reviewer memo files."""
import argparse
import os
import re
import sys

VERDICT_PATTERN = re.compile(r"VERDICT:\s*(APPROVE|REJECT|REQUEST_CHANGES)")
DEFAULT_REQUIRED_FIELDS = ["## Findings", "## Verdict", "VERDICT:"]


def check_memo(path, required_fields):
    errors = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        errors.append(f"memo not found: {path}")
        return errors

    for field in required_fields:
        if field not in content:
            errors.append(f"{path}: missing required field/section: {field!r}")

    if not VERDICT_PATTERN.search(content):
        errors.append(f"{path}: no valid VERDICT line (APPROVE|REJECT|REQUEST_CHANGES)")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate reviewer memo files")
    parser.add_argument("--memo", default=None)
    parser.add_argument("--memos-dir", default=None)
    parser.add_argument("--min-count", type=int, default=0)
    parser.add_argument("--required-fields", nargs="*", default=DEFAULT_REQUIRED_FIELDS)
    args = parser.parse_args()

    errors = []

    if args.memo:
        errors.extend(check_memo(args.memo, args.required_fields))

    if args.memos_dir:
        if not os.path.isdir(args.memos_dir):
            errors.append(f"memos-dir not found: {args.memos_dir}")
        else:
            memo_files = [
                os.path.join(args.memos_dir, f)
                for f in os.listdir(args.memos_dir)
                if f.endswith(".md")
            ]
            if args.min_count and len(memo_files) < args.min_count:
                errors.append(
                    f"Not enough memos in {args.memos_dir}: found {len(memo_files)}, need {args.min_count}"
                )
            for path in memo_files:
                errors.extend(check_memo(path, args.required_fields))

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    print("PASS: reviewer memo validation")
    sys.exit(0)


if __name__ == "__main__":
    main()
