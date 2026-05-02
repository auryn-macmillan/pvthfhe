#!/usr/bin/env python3
import sys
import re

GAS_LIMIT = 5_000_000

def main():
    text = sys.stdin.read()
    print(text)

    pattern = re.compile(r'verify\s*\|\s*[\d,]+\s*\|\s*[\d,]+\s*\|\s*([\d,]+)')
    matches = pattern.findall(text)

    if not matches:
        print("check-gas: no 'verify' gas entries found in report", file=sys.stderr)
        sys.exit(1)

    max_gas = 0
    for m in matches:
        gas = int(m.replace(',', ''))
        max_gas = max(max_gas, gas)

    print(f"check-gas: max verify gas = {max_gas:,} (limit {GAS_LIMIT:,})")

    if max_gas > GAS_LIMIT:
        print(f"check-gas: FAIL — {max_gas:,} > {GAS_LIMIT:,}", file=sys.stderr)
        sys.exit(1)

    print("check-gas: PASS")

if __name__ == "__main__":
    main()
