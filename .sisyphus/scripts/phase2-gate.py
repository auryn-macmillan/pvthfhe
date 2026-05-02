#!/usr/bin/env python3
import datetime
import json
import os
import subprocess
import sys

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


REQUIRED_ARTIFACTS = [
    ".sisyphus/design/selection-memo.md",
    ".sisyphus/design/spec-keygen.md",
    ".sisyphus/design/spec-decrypt.md",
    ".sisyphus/design/parameters.toml",
    ".sisyphus/design/parameters.md",
    ".sisyphus/design/noise-budget.md",
    ".sisyphus/design/api-spec.md",
    "crates/pvthfhe-api/src/lib.rs",
    ".sisyphus/design/worked-example.md",
    ".sisyphus/design/security-proofs.md",
    ".sisyphus/design/proof-boundary.md",
    ".sisyphus/design/oracle-review.md",
    ".sisyphus/design/lit-refresh-2.md",
]

PARAMETERS_TOML_REQUIRED_KEYS = [
    ("n", ["rlwe"]),
    ("log2_q", ["rlwe"]),
    ("plaintext_modulus", ["rlwe"]),
    ("classical_bits", ["security"]),
]


def run_check_artifacts():
    missing = [p for p in REQUIRED_ARTIFACTS if not os.path.exists(p)]
    if missing:
        return "FAIL", f"Missing {len(missing)} artifact(s): {', '.join(missing)}"
    return "PASS", f"All {len(REQUIRED_ARTIFACTS)} T17-T27 artifacts present"


def run_check_parameters_toml():
    path = ".sisyphus/design/parameters.toml"
    if not os.path.exists(path):
        return "FAIL", f"{path} not found"
    raw = open(path, "rb").read()
    if tomllib is None:
        import re
        text = raw.decode()
        missing = []
        for key, _ in PARAMETERS_TOML_REQUIRED_KEYS:
            if not re.search(rf"^\s*{re.escape(key)}\s*=", text, re.MULTILINE):
                missing.append(key)
        if missing:
            return "FAIL", f"Missing keys: {missing}"
        return "PASS", "parameters.toml parses and contains required keys (regex fallback)"
    try:
        data = tomllib.loads(raw.decode())
    except Exception as exc:
        return "FAIL", f"TOML parse error: {exc}"
    missing = []
    for key, sections in PARAMETERS_TOML_REQUIRED_KEYS:
        found = False
        node = data
        for sec in sections:
            node = node.get(sec, {})
        if key in node:
            found = True
        if not found:
            missing.append(key)
    if missing:
        return "FAIL", f"Missing keys in parameters.toml: {missing}"
    return "PASS", "parameters.toml valid with required keys"


def run_check_noise_budget_test():
    result = subprocess.run(
        ["cargo", "test", "-p", "pvthfhe-core", "--test", "noise_budget"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return "PASS", "cargo test noise_budget passed"
    return "FAIL", f"cargo test noise_budget failed: {result.stderr.strip()[-300:]}"


def run_check_theorem_mapping():
    result = subprocess.run(
        [
            "python3", ".sisyphus/scripts/check-theorem-mapping.py",
            ".sisyphus/design/security-proofs.md",
            ".sisyphus/research/assumptions-ledger.md",
        ],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return "PASS", result.stdout.strip()
    return "FAIL", (result.stdout + result.stderr).strip()[-300:]


def run_check_boundary_coverage():
    result = subprocess.run(
        [
            "python3", ".sisyphus/scripts/check-boundary-coverage.py",
            ".sisyphus/design/proof-boundary.md",
        ],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return "PASS", result.stdout.strip()
    return "FAIL", (result.stdout + result.stderr).strip()[-300:]


def run_check_oracle_dispositions():
    result = subprocess.run(
        [
            "python3", ".sisyphus/scripts/check-oracle-dispositions.py",
            ".sisyphus/design/oracle-review.md",
        ],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return "PASS", result.stdout.strip()
    return "FAIL", (result.stdout + result.stderr).strip()[-300:]


def run_check_lit_refresh_no_blocking():
    path = ".sisyphus/design/lit-refresh-2.md"
    if not os.path.exists(path):
        return "FAIL", f"{path} not found"
    with open(path) as f:
        lines = f.readlines()
    blocking_lines = [
        ln.strip() for ln in lines
        if "blocking" in ln.lower() and "undecided" in ln.lower()
    ]
    if blocking_lines:
        return "FAIL", f"Found BLOCKING+undecided lines: {blocking_lines[:3]}"
    return "PASS", "No BLOCKING+undecided lines in lit-refresh-2.md"


def run_check_cargo_check():
    result = subprocess.run(
        ["cargo", "check", "--workspace"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return "PASS", "cargo check --workspace passed"
    return "FAIL", f"cargo check failed: {result.stderr.strip()[-300:]}"


CHECKS = [
    ("artifacts", run_check_artifacts),
    ("parameters_toml", run_check_parameters_toml),
    ("noise_budget_test", run_check_noise_budget_test),
    ("theorem_mapping", run_check_theorem_mapping),
    ("boundary_coverage", run_check_boundary_coverage),
    ("oracle_dispositions", run_check_oracle_dispositions),
    ("lit_refresh_no_blocking", run_check_lit_refresh_no_blocking),
    ("cargo_check", run_check_cargo_check),
]


def main():
    print("=== Phase 2 Gate ===\n")
    results = []
    all_pass = True

    for check_id, fn in CHECKS:
        print(f"[{check_id}] running...")
        status, detail = fn()
        print(f"[{check_id}] {status}: {detail}\n")
        results.append({"id": check_id, "status": status, "detail": detail})
        if status != "PASS":
            all_pass = False

    gate_status = "PASS" if all_pass else "FAIL"
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    gate_json = {
        "schema_version": "1",
        "gate": "phase2",
        "timestamp": timestamp,
        "status": gate_status,
        "checks": results,
    }

    os.makedirs(".sisyphus/design", exist_ok=True)
    with open(".sisyphus/design/phase2-gate.json", "w") as f:
        json.dump(gate_json, f, indent=2)
    print("Wrote .sisyphus/design/phase2-gate.json")

    rows = "\n".join(
        f"| {r['id']} | {r['status']} | {r['detail']} |"
        for r in results
    )
    md = f"""# Phase 2 Gate Report

**Status**: {gate_status}
**Date**: {timestamp}

## Checks

| Check | Status | Detail |
|-------|--------|--------|
{rows}

## Summary

{"Phase 2 design complete. All checks pass. Proceeding to Phase 3." if all_pass else "Phase 2 gate FAILED. See failing checks above."}
"""
    with open(".sisyphus/design/phase2-gate.md", "w") as f:
        f.write(md)
    print("Wrote .sisyphus/design/phase2-gate.md")

    print(f"\nPHASE 2 GATE: {gate_status}")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
