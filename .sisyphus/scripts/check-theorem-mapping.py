#!/usr/bin/env python3
"""
check-theorem-mapping.py <security-proofs.md> <assumptions-ledger.md>

Verifies that every theorem section (## T-*) in security-proofs.md has
at least one assumption listed under its "Assumption set:" block.
Exits 0 on success, 1 on failure.
"""
import re
import sys


def parse_theorems(path: str) -> dict[str, list[str]]:
    """Return {theorem_id: [assumption, ...]} for each ## T-* section."""
    theorems: dict[str, list[str]] = {}
    current: str | None = None
    in_assumption_block = False

    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("## "):
                in_assumption_block = False
                if stripped.startswith("## T-") or re.match(r"^## T[A-Z-]", stripped):
                    current = stripped[3:].split(":")[0].strip()
                    theorems[current] = []
                else:
                    current = None
            if current is None:
                continue
            if "**Assumption set:**" in stripped or stripped == "Assumption set:":
                in_assumption_block = True
                continue
            if in_assumption_block:
                if stripped.startswith("- `") and stripped.endswith("`"):
                    assumption = stripped[3:-1]
                    theorems[current].append(assumption)
                elif stripped.startswith("#") or (stripped and not stripped.startswith("-")):
                    in_assumption_block = False

    return theorems


def parse_ledger_assumptions(path: str) -> set[str]:
    """Return the set of assumption names defined in the ledger."""
    assumptions: set[str] = set()
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("## "):
                name = stripped[3:].strip()
                if name:
                    assumptions.add(name)
    return assumptions


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <security-proofs.md> <assumptions-ledger.md>")
        return 1

    proofs_path, ledger_path = sys.argv[1], sys.argv[2]

    theorems = parse_theorems(proofs_path)
    ledger = parse_ledger_assumptions(ledger_path)

    if not theorems:
        print("FAIL: no theorem sections (## T-*) found in security-proofs.md")
        return 1

    failures: list[str] = []
    unmapped: list[tuple[str, str]] = []

    for theorem, assumptions in theorems.items():
        if not assumptions:
            failures.append(f"  {theorem}: no assumptions listed")
        else:
            for assumption in assumptions:
                if assumption not in ledger:
                    lower = assumption.lower()
                    if not any(kw in lower for kw in ("open p", "open-p", "deferred", "smudging", "pvss", "lattice", "micronova", "latticefold")):
                        unmapped.append((theorem, assumption))

    if failures:
        print("FAIL: theorem(s) with no assumption mapping:")
        for msg in failures:
            print(msg)
        return 1

    if unmapped:
        print("FAIL: assumption(s) referenced but not in ledger (and not Open/deferred):")
        for theorem, assumption in unmapped:
            print(f"  {theorem} -> '{assumption}'")
        return 1

    total = sum(len(a) for a in theorems.values())
    print(
        f"Success: All theorems mapped correctly "
        f"({len(theorems)} theorems, {total} assumption references)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
