#!/usr/bin/env python3
import sys
import re

if len(sys.argv) != 2:
    print("Usage: check-oracle-dispositions.py <path-to-review>")
    sys.exit(1)

path = sys.argv[1]
with open(path, 'r') as f:
    content = f.read()

# Split into finding blocks by ### F-NNN headings
blocks = re.split(r'(?=^### F-\d{3})', content, flags=re.MULTILINE)

open_findings = []
for block in blocks:
    m = re.match(r'### (F-\d{3})', block)
    if not m:
        continue
    fid = m.group(1)
    # Check the **Status**: line — only flag if status is explicitly OPEN
    status_match = re.search(r'^\*\*Status\*\*:\s*(\S+)', block, re.MULTILINE)
    if status_match:
        status = status_match.group(1).upper()
        if status == 'OPEN':
            open_findings.append(fid)
    else:
        # No status line found — treat as open
        open_findings.append(fid)

if open_findings:
    print("OPEN findings:", open_findings)
    sys.exit(1)

print("All findings ADDRESSED")
sys.exit(0)
