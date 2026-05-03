#!/usr/bin/env python3
"""
check-boundary-coverage.py <proof-boundary.md>

Verifies that all 12 PB-01..PB-12 entries in the proof-boundary table
are present and have a non-empty, non-TBD Primary assignment.
Exits 0 on success, 1 on failure.
"""
import re
import sys


REQUIRED_IDS = {f"PB-{i:02d}" for i in range(1, 13)}
VALID_PRIMARIES = {"A", "B", "C", "D"}


def parse_boundary_table(path: str) -> dict[str, str]:
    """Return {pb_id: primary_layer} from the enforcement table in proof-boundary.md."""
    entries: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped.startswith("|"):
                continue
            parts = [p.strip() for p in stripped.split("|")]
            parts = [p for p in parts if p]
            if len(parts) < 3:
                continue
            pb_id = parts[0]
            if not re.match(r"^PB-\d{2}$", pb_id):
                continue
            primary = parts[2] if len(parts) >= 3 else ""
            entries[pb_id] = primary
    return entries


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <proof-boundary.md>")
        return 1

    entries = parse_boundary_table(sys.argv[1])

    missing = REQUIRED_IDS - entries.keys()
    invalid: list[str] = []
    for pb_id in sorted(entries):
        primary = entries[pb_id]
        if primary not in VALID_PRIMARIES:
            invalid.append(f"  {pb_id}: primary='{primary}' (expected one of {sorted(VALID_PRIMARIES)})")

    failures: list[str] = []
    if missing:
        failures.append(f"Missing entries: {sorted(missing)}")
    if invalid:
        failures.append("Invalid primary assignments:\n" + "\n".join(invalid))

    if failures:
        print("FAIL: proof-boundary coverage incomplete:")
        for msg in failures:
            print(msg)
        return 1

    print(f"Success: All {len(REQUIRED_IDS)} boundary entries present with valid primary assignments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
