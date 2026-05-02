#!/usr/bin/env python3
"""Verify pinned references inside TeX or Markdown sources."""
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence

DEFAULT_PAPER = "paper/main.tex"
DEFAULT_REQUIRED_PINS = ["\\cite{", "\\ref{"]
MARKDOWN_PIN_RE = re.compile(r'^[\-*+]\s+`[A-Za-z0-9_\-]+\s*=\s*"[0-9]+(?:\.[0-9A-Za-z\-]+)*"`\s*$', re.MULTILINE)


def check_pins(paper_path: str, required_pins: Sequence[str]) -> list[str]:
    errors: list[str] = []
    try:
        with open(paper_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        errors.append(f"paper file not found: {paper_path}")
        return errors

    if paper_path.endswith(".md"):
        count = len(MARKDOWN_PIN_RE.findall(content))
        print(f'  markdown crate pins: {count} occurrences')
        if count < 4:
            errors.append('Expected at least 4 TOML-style crate pins in Markdown')
        return errors

    for pin in required_pins:
        count = content.count(pin)
        print(f"  {pin!r}: {count} occurrences")
        if count == 0:
            errors.append(f"No occurrences of required pin pattern: {pin!r}")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate pins in TeX sources")
    _ = parser.add_argument("path", nargs="?", default=None)
    _ = parser.add_argument("--paper", default=DEFAULT_PAPER)
    _ = parser.add_argument("--required-pins", nargs="*", default=DEFAULT_REQUIRED_PINS)
    args = parser.parse_args()

    target_path = args.path or args.paper
    errors = check_pins(target_path, args.required_pins)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    print("PASS: pins validation")
    sys.exit(0)


if __name__ == "__main__":
    main()
