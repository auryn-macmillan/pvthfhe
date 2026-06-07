#!/usr/bin/env python3
"""Check PvtFheVerifier.sol for vacuous accept paths (return true without prior checks)."""
import re, sys

with open('contracts/src/PvtFheVerifier.sol', 'r') as f:
    src = f.read()

functions = re.split(r'function\s+', src)
CHECK_KWS = [
    'require', 'revert', '_honkVerifier', 'registry.mark',
    '_consumeIvcProof', 'verifyStoredPublicAnchors', 'recordSmudgeSlotUse'
]

vacuous = False
for f in functions[1:]:
    parts = f.split('return true')
    if len(parts) > 1:
        before = parts[0]
        has_check = any(kw in before for kw in CHECK_KWS)
        if not has_check:
            name = f.split('(')[0].strip()
            print(f'VACUOUS ACCEPT: function {name} returns true without verification checks')
            vacuous = True

if vacuous:
    sys.exit(1)
