#!/usr/bin/env python3
"""Validate docs/security-proofs/obligations.md rows."""
from __future__ import annotations

import argparse
import re
import sys

DEFAULT_PATH = "docs/security-proofs/obligations.md"
REQUIRED_COLUMNS = [
    "Problem",
    "Theorem-ID",
    "Informal Statement",
    "Status",
    "Proof File Path",
    "Paper Section",
]


def parse_table(content: str) -> tuple[list[str], list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    in_table = False
    headers: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("|") and not in_table:
            cells = [c.strip() for c in line.strip("|").split("|")]
            headers = cells
            in_table = True
            continue
        if in_table and re.match(r"^\|[-| ]+\|$", line):
            continue
        if in_table and line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) == len(headers):
                rows.append(dict(zip(headers, cells)))
    return headers, rows


def validate(
    path: str,
    require_bijection: bool = False,
    _claims: bool | None = None,
    _theorems: bool | None = None,
    _inventory: bool | None = None,
    _gates: bool | None = None,
    _novelty_memos: bool | None = None,
    problem: str | None = None,
    status: str | None = None,
) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"FAIL: file not found: {path}")
        return False

    headers, rows = parse_table(content)
    errors: list[str] = []

    for col in REQUIRED_COLUMNS:
        if col not in headers:
            errors.append(f"Missing column: {col}")

    if not errors:
        for i, row in enumerate(rows):
            for col in ["Problem", "Theorem-ID", "Status"]:
                if not row.get(col, "").strip():
                    errors.append(f"Row {i+1}: empty required field '{col}'")

    if require_bijection and rows:
        theorem_ids = [r.get("Theorem-ID", "") for r in rows]
        dupes = [t for t in theorem_ids if theorem_ids.count(t) > 1]
        if dupes:
            errors.append(f"Duplicate Theorem-IDs: {set(dupes)}")

    filtered_rows = rows
    if not errors and problem:
        filtered_rows = [row for row in rows if row.get("Problem") == problem]
        if not filtered_rows:
            errors.append(f"No rows found for problem: {problem}")

    if not errors and status:
        mismatches = [
            row.get("Theorem-ID", "<unknown>")
            for row in filtered_rows
            if row.get("Status") != status
        ]
        if mismatches:
            errors.append(
                f"Rows do not match required status '{status}': {', '.join(mismatches)}"
            )

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return False

    scope_bits: list[str] = []
    if problem:
        scope_bits.append(f"problem={problem}")
    if status:
        scope_bits.append(f"status={status}")
    scope_suffix = f" [{', '.join(scope_bits)}]" if scope_bits else ""
    print(f"PASS: obligations schema ({len(filtered_rows)} rows){scope_suffix}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Validate obligations.md schema")
    _ = parser.add_argument("positional_path", nargs="?", default=None)
    _ = parser.add_argument("--path", default=None)
    _ = parser.add_argument("--claims", action="store_true")
    _ = parser.add_argument("--theorems", action="store_true")
    _ = parser.add_argument("--inventory", action="store_true")
    _ = parser.add_argument("--gates", action="store_true")
    _ = parser.add_argument("--novelty-memos", action="store_true")
    _ = parser.add_argument("--require-bijection", action="store_true")
    _ = parser.add_argument("--problem")
    _ = parser.add_argument("--status")
    args: argparse.Namespace = parser.parse_args()

    selected_path = (
        getattr(args, "path", None)
        or getattr(args, "positional_path", None)
        or DEFAULT_PATH
    )
    problem = getattr(args, "problem", None)
    status = getattr(args, "status", None)
    require_bijection = bool(getattr(args, "require_bijection", False))

    ok = validate(
        selected_path,
        require_bijection=require_bijection,
        problem=problem,
        status=status,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
