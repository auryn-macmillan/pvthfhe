#!/usr/bin/env python3
"""Parse plan task list and flag unaccounted git diff files."""
import argparse
import os
import re
import subprocess
import sys


def parse_plan_files(plan_path):
    """Extract file paths mentioned in the plan's 'What to do' sections."""
    if not os.path.exists(plan_path):
        return []
    with open(plan_path, "r", encoding="utf-8") as f:
        content = f.read()
    # Extract paths that look like file references
    paths = re.findall(r"`([^`]+\.[a-zA-Z]+)`", content)
    paths += re.findall(r"(?:^|\s)((?:crates|circuits|contracts|docs|\.sisyphus|paper|bench)/\S+)", content)
    return list(set(paths))


def get_diff_files(base_ref, head_ref):
    """Get files changed between two git refs."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref, head_ref],
            capture_output=True, text=True, check=True
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError as e:
        print(f"[WARN] git diff failed: {e}")
        return []


def check_fidelity(plan_path, base_ref, head_ref):
    plan_files = set(parse_plan_files(plan_path))
    diff_files = get_diff_files(base_ref, head_ref)

    unaccounted = []
    for f in diff_files:
        if not any(plan_f in f or f in plan_f for plan_f in plan_files):
            unaccounted.append(f)

    return diff_files, plan_files, unaccounted


def main():
    parser = argparse.ArgumentParser(description="Check scope fidelity between plan and git diff")
    parser.add_argument("--plan", required=True, help="Path to plan markdown file")
    parser.add_argument("--base-ref", default="HEAD~1", help="Base git ref")
    parser.add_argument("--head-ref", default="HEAD", help="Head git ref")
    parser.add_argument("--output", default=None, help="Output JSON file")
    args = parser.parse_args()

    diff_files, plan_files, unaccounted = check_fidelity(args.plan, args.base_ref, args.head_ref)

    print(f"Plan file references: {len(plan_files)}")
    print(f"Diff files: {len(diff_files)}")
    print(f"Unaccounted files: {len(unaccounted)}")

    if unaccounted:
        print("\n[WARN] Files in diff not clearly accounted for in plan:")
        for f in unaccounted:
            print(f"  {f}")

    if args.output:
        import json
        import datetime
        record = {
            "plan": args.plan,
            "base_ref": args.base_ref,
            "head_ref": args.head_ref,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "diff_files": diff_files,
            "plan_files": list(plan_files),
            "unaccounted": unaccounted,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        print(f"Output written to {args.output}")

    # Non-zero if there are unaccounted files
    sys.exit(1 if unaccounted else 0)


if __name__ == "__main__":
    main()
