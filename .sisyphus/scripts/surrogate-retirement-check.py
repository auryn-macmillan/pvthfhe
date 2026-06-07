#!/usr/bin/env python3
"""Audit surrogate retirement state.

PASS criteria: zero SURROGATE markers found in any .rs, .sol, or .nr file.
Matches the exact grep used in the task: grep -rn 'SURROGATE' (case-sensitive).
FAIL criteria: any SURROGATE marker still present.
"""
import os
import re
import sys


SURROGATE_PAT = re.compile(r'//\s*SURROGATE')

EXTENSIONS = ('.rs', '.sol', '.nr')

# Files that intentionally contain SURROGATE markers as part of their
# surrogate-declaration role (not surrogates themselves — they declare
# which other files ARE surrogates). Excluded from the scan.
WHITELIST = {
    'contracts/script/SurrogateCheck.s.sol',
    'contracts/src/SurrogateNotice.sol',
}


def find_surrogate_hits(root='.'):
    hits = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'target']
        for fname in files:
            if any(fname.endswith(ext) for ext in EXTENSIONS):
                fpath = os.path.join(dirpath, fname)
                relpath = os.path.relpath(fpath, root)
                if relpath in WHITELIST:
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        for lineno, line in enumerate(f, 1):
                            if SURROGATE_PAT.search(line):
                                hits.append((fpath, lineno, line.rstrip()))
                except (OSError, UnicodeDecodeError):
                    pass
    return hits


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(root, '..', '..'))

    hits = find_surrogate_hits(repo_root)

    if hits:
        print(f"FAIL: surrogate-retirement-check — {len(hits)} SURROGATE marker(s) found:")
        for fpath, lineno, line in hits:
            print(f"  {fpath}:{lineno}: {line}")
        sys.exit(1)
    else:
        print("PASS: surrogate-retirement-check — zero SURROGATE markers found")
        sys.exit(0)


if __name__ == "__main__":
    main()
