#!/usr/bin/env python3
"""Validate research prior-art matrices and paper/bib.bib."""
import argparse
import re
import sys
from datetime import datetime, timezone

DEFAULT_BIB = "paper/bib.bib"


def parse_bib_entries(content):
    entries = re.findall(r"@\w+\{([^,]+),", content)
    return entries


def check_bib(bib_path, max_age_days=None, eprint_check=False):
    errors = []
    try:
        with open(bib_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        errors.append(f"bib file not found: {bib_path}")
        return errors

    entries = parse_bib_entries(content)
    if not entries:
        errors.append("No bib entries found")
        return errors

    print(f"  Found {len(entries)} bib entries")

    if eprint_check:
        eprint_refs = re.findall(r"eprint\s*=\s*\{([^}]+)\}", content)
        for ref in eprint_refs:
            if not re.match(r"\d{4}\.\d+", ref):
                errors.append(f"Malformed eprint reference: {ref}")

    if max_age_days is not None:
        year_matches = re.findall(r"year\s*=\s*\{?(\d{4})\}?", content)
        current_year = datetime.now(timezone.utc).year
        for y in year_matches:
            age_days = (current_year - int(y)) * 365
            if age_days > max_age_days:
                errors.append(f"Entry with year {y} exceeds max age ({max_age_days} days)")
                break

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate prior-art and bib")
    parser.add_argument("--bib", default=DEFAULT_BIB)
    parser.add_argument("--max-age-days", type=int, default=None)
    parser.add_argument("--eprint-check", action="store_true")
    args = parser.parse_args()

    errors = check_bib(args.bib, args.max_age_days, args.eprint_check)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    print("PASS: prior-art validation")
    sys.exit(0)


if __name__ == "__main__":
    main()
