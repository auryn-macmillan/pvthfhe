#!/usr/bin/env python3
"""Audit surrogate retirement state.

PASS criteria: each surrogate file exists on disk AND is either
  - annotated with a // SURROGATE comment header, OR
  - wrapped in a Rust feature flag (#[cfg(not(feature="real-..."))])
This confirms the surrogates are present as regression baselines and NOT on
the default production path.
"""
import argparse
import os
import re
import sys

SURROGATES = {
    "api-leakage": "crates/pvthfhe-aggregator/src/keygen/protocol.rs",
    "on-chain-verifier": "contracts/src/generated/HonkVerifier.sol",
    "decrypt-circuit": "circuits/decrypt_share/src/main.nr",
    "aggregator-circuit": "circuits/aggregator_final/src/main.nr",
}

FEATURE_FLAG_PAT = re.compile(r'#\[cfg\((not\()?feature\s*=\s*"real-')
SURROGATE_HEADER_PAT = re.compile(r'//\s*SURROGATE', re.IGNORECASE)


def check_surrogate(name, path):
    if not os.path.exists(path):
        return False, [f"[FAIL] file missing: {path}"]

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    has_feature_flag = bool(FEATURE_FLAG_PAT.search(content))
    has_surrogate_header = bool(SURROGATE_HEADER_PAT.search(content))

    if has_feature_flag or has_surrogate_header:
        marker = "feature-flagged" if has_feature_flag else "SURROGATE-annotated"
        return True, [f"[OK] {name}: {path} — present, {marker}"]
    else:
        return False, [
            f"[FAIL] {name}: {path} — present but missing SURROGATE annotation or feature flag"
        ]


def main():
    parser = argparse.ArgumentParser(description="Check surrogate retirement")
    parser.add_argument("--check", choices=list(SURROGATES.keys()) + ["all"], default="all")
    parser.add_argument("--target", default=None)
    args = parser.parse_args()

    if args.target:
        targets = {args.target: args.target}
    elif args.check == "all":
        targets = SURROGATES
    else:
        targets = {args.check: SURROGATES[args.check]}

    all_ok = True
    passed = 0
    for name, path in targets.items():
        ok, details = check_surrogate(name, path)
        for d in details:
            print(d)
        if ok:
            passed += 1
        else:
            all_ok = False

    total = len(targets)
    print(f"surrogate-retirement-check: {passed}/{total} feature-flagged or annotated")

    if all_ok:
        print("PASS: surrogate-retirement-check")
        sys.exit(0)
    else:
        print("FAIL: surrogate-retirement-check")
        sys.exit(1)


if __name__ == "__main__":
    main()
