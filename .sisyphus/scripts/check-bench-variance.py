#!/usr/bin/env python3
# pyright: reportAny=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnannotatedClassAttribute=false
"""
Check that bench variance between two runs is within tolerance.
Usage: python3 check-bench-variance.py run1.log run2.log --tolerance 0.15

Each log file contains JSON-line records: {"case": str, "median_ns": float, ...}
Exits 0 if all cases have abs(m1-m2)/max(m1,m2) <= tolerance.
Exits 1 if any case exceeds tolerance (lists offending cases).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TypedDict


class Args(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.run1 = ""
        self.run2 = ""
        self.tolerance = 0.15


class BenchRecord(TypedDict):
    case: str
    median_ns: float


def load_records(path: str) -> dict[str, float]:
    records: dict[str, float] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                raw_record = json.loads(line)
                if not isinstance(raw_record, dict):
                    continue
                parsed_record = {str(key): value for key, value in raw_record.items()}
                case = parsed_record.get("case")
                median_ns = parsed_record.get("median_ns")
                if not isinstance(case, str):
                    continue
                if not isinstance(median_ns, (int, float)):
                    continue
                record: BenchRecord = {
                    "case": case,
                    "median_ns": float(median_ns),
                }
                records[record["case"]] = record["median_ns"]
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("run1")
    _ = parser.add_argument("run2")
    _ = parser.add_argument("--tolerance", type=float, default=0.15)
    args = parser.parse_args(namespace=Args())
    run1_path = args.run1
    run2_path = args.run2
    tolerance = args.tolerance

    run1 = load_records(run1_path)
    run2 = load_records(run2_path)

    failures: list[str] = []
    for case, median1 in run1.items():
        if case not in run2:
            continue
        median2 = run2[case]
        upper = max(median1, median2)
        if upper <= 0:
            continue
        ratio = abs(median1 - median2) / upper
        if ratio > tolerance:
            failures.append(f"{case}: ratio={ratio:.3f} > {tolerance}")

    if failures:
        print("VARIANCE TOO HIGH:")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print(f"OK: all cases within {tolerance * 100:.0f}% tolerance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
