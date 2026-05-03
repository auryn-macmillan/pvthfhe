#!/usr/bin/env python3
"""Lint crates/contracts/circuits for AI-slop patterns."""
import argparse
import os
import re
import sys

# Patterns that indicate AI slop
EXCESSIVE_COMMENT_THRESHOLD = 5  # consecutive comment lines
GENERIC_IDENTIFIERS = re.compile(r"\b(data|result|item|temp|tmp|foo|bar|baz|helper|util|thing)\b")
AS_ANY = re.compile(r"as\s+any\b")
UNWRAP_OUTSIDE_TEST = re.compile(r"\.unwrap\(\)")
PANIC_OUTSIDE_TEST = re.compile(r"panic!\(")
COMMENTED_CODE_RS = re.compile(r"^\s*//\s*(let |fn |pub |use |impl |struct |enum )", re.MULTILINE)
COMMENTED_CODE_NR = re.compile(r"^\s*//\s*(let |fn |pub |use |struct )", re.MULTILINE)

SCAN_EXTENSIONS = {".rs", ".nr", ".sol", ".ts", ".js"}
SKIP_DIRS = {"target", "node_modules", ".git", "artifacts", "out"}


def is_test_context(content, match_pos):
    """Rough heuristic: is the match inside a #[cfg(test)] or #[test] block?"""
    before = content[:match_pos]
    return "#[cfg(test)]" in before[-500:] or "#[test]" in before[-200:]


def scan_file(path):
    issues = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        return [f"{path}: cannot read: {e}"]

    ext = os.path.splitext(path)[1]

    # Check for excessive consecutive comment lines
    consecutive = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            consecutive += 1
            if consecutive >= EXCESSIVE_COMMENT_THRESHOLD:
                issues.append(f"{path}:{i}: excessive consecutive comments ({consecutive}+)")
                consecutive = 0  # reset to avoid repeated reports
        else:
            consecutive = 0

    # Generic identifiers (variable names) - just flag files that have many
    generic_count = len(GENERIC_IDENTIFIERS.findall(content))
    if generic_count > 10:
        issues.append(f"{path}: {generic_count} generic identifier occurrences")

    # as any (TypeScript)
    if ext in {".ts", ".tsx", ".js"}:
        for m in AS_ANY.finditer(content):
            ln = content[:m.start()].count("\n") + 1
            issues.append(f"{path}:{ln}: 'as any' usage")

    # unwrap/panic outside tests (Rust)
    if ext == ".rs":
        for m in UNWRAP_OUTSIDE_TEST.finditer(content):
            if not is_test_context(content, m.start()):
                ln = content[:m.start()].count("\n") + 1
                issues.append(f"{path}:{ln}: .unwrap() outside test context")

        for m in PANIC_OUTSIDE_TEST.finditer(content):
            if not is_test_context(content, m.start()):
                ln = content[:m.start()].count("\n") + 1
                issues.append(f"{path}:{ln}: panic!() outside test context")

        # Commented-out code
        for m in COMMENTED_CODE_RS.finditer(content):
            ln = content[:m.start()].count("\n") + 1
            issues.append(f"{path}:{ln}: commented-out code")

    return issues


def scan_dir(root):
    all_issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1]
            if ext in SCAN_EXTENSIONS:
                path = os.path.join(dirpath, fname)
                all_issues.extend(scan_file(path))
    return all_issues


def main():
    parser = argparse.ArgumentParser(description="Scan for AI-slop patterns")
    parser.add_argument("--dirs", nargs="*", default=["crates", "contracts", "circuits"])
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()

    all_issues = []
    for d in args.dirs:
        if os.path.isdir(d):
            issues = scan_dir(d)
            all_issues.extend(issues)
        else:
            print(f"[SKIP] directory not found: {d}")

    if all_issues:
        for issue in all_issues:
            print(f"[SLOP] {issue}")
        print(f"\nTotal: {len(all_issues)} potential AI-slop issue(s)")
        if args.fail_on_issues:
            sys.exit(1)
    else:
        print("PASS: no AI-slop patterns detected")

    sys.exit(0)


if __name__ == "__main__":
    main()
