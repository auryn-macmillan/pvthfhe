#!/usr/bin/env python3
"""Create WAITING_FOR_HUMAN_REVIEW marker and check memo verdict."""
import argparse
import os
import re
import sys

VERDICT_APPROVE = re.compile(r"VERDICT:\s*APPROVE")
MARKER_FILE = "WAITING_FOR_HUMAN_REVIEW"


def main():
    parser = argparse.ArgumentParser(description="Human review wait helper")
    parser.add_argument("--memo", default=None, help="Memo file to check for VERDICT: APPROVE")
    parser.add_argument("--create-marker", action="store_true", help="Create WAITING_FOR_HUMAN_REVIEW marker")
    parser.add_argument("--clear-marker", action="store_true", help="Remove WAITING_FOR_HUMAN_REVIEW marker")
    args = parser.parse_args()

    if args.create_marker:
        with open(MARKER_FILE, "w", encoding="utf-8") as f:
            f.write("Waiting for human review.\n")
        print(f"Created marker: {MARKER_FILE}")

    if args.clear_marker:
        if os.path.exists(MARKER_FILE):
            os.remove(MARKER_FILE)
            print(f"Removed marker: {MARKER_FILE}")

    if args.memo:
        try:
            with open(args.memo, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"FAIL: memo not found: {args.memo}")
            sys.exit(1)

        if VERDICT_APPROVE.search(content):
            print(f"PASS: VERDICT: APPROVE found in {args.memo}")
            sys.exit(0)
        else:
            print(f"FAIL: no 'VERDICT: APPROVE' in {args.memo}")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
