#!/usr/bin/env python3
"""Audit paper claims fidelity.

PASS criteria: zero overstated or contradicted claims in paper-claims-v2.md
               (falls back to paper-claims.md if v2 not present).
Reads the Fidelity Summary section for 'overstated: N' / 'contradicted: N',
and also scans table rows for '| overstated |' / '| contradicted |' patterns.
"""
import os
import re
import sys


def find_claims_file(repo_root):
    v2 = os.path.join(repo_root, '.sisyphus', 'evidence', 'paper-claims-v2.md')
    v1 = os.path.join(repo_root, '.sisyphus', 'evidence', 'paper-claims.md')
    if os.path.exists(v2):
        return v2
    if os.path.exists(v1):
        return v1
    return None


def count_bad_claims(path):
    """Return (overstated_count, contradicted_count) from summary section or table rows."""
    overstated = 0
    contradicted = 0

    # Patterns for summary section lines like "- overstated: 5"
    summary_over = re.compile(r'^\s*[-*]\s*overstated\s*:\s*(\d+)', re.IGNORECASE)
    summary_contra = re.compile(r'^\s*[-*]\s*contradicted\s*:\s*(\d+)', re.IGNORECASE)

    # Patterns for markdown table column values
    table_over = re.compile(r'\|\s*overstated\s*\|', re.IGNORECASE)
    table_contra = re.compile(r'\|\s*contradicted\s*\|', re.IGNORECASE)

    in_summary = False
    summary_found = False

    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        if re.search(r'fidelity\s+summary', line, re.IGNORECASE):
            in_summary = True
        if in_summary:
            m = summary_over.match(line)
            if m:
                overstated = int(m.group(1))
                summary_found = True
            m = summary_contra.match(line)
            if m:
                contradicted = int(m.group(1))
                summary_found = True

    if summary_found:
        return overstated, contradicted

    for line in lines:
        if table_over.search(line):
            overstated += 1
        elif table_contra.search(line):
            contradicted += 1

    return overstated, contradicted


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(script_dir, '..', '..'))

    claims_file = find_claims_file(repo_root)
    if claims_file is None:
        print("FAIL: audit-paper-claims — no paper-claims*.md found in .sisyphus/evidence/")
        sys.exit(1)

    overstated, contradicted = count_bad_claims(claims_file)
    total_bad = overstated + contradicted

    if total_bad > 0:
        print(
            f"FAIL: audit-paper-claims — {total_bad} overstated/contradicted claims found "
            f"(overstated={overstated}, contradicted={contradicted}) in {claims_file}"
        )
        sys.exit(1)
    else:
        print(
            f"PASS: audit-paper-claims — all claims supported or untestable "
            f"(source: {os.path.basename(claims_file)})"
        )
        sys.exit(0)


if __name__ == '__main__':
    main()
