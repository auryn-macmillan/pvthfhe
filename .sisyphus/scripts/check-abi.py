#!/usr/bin/env python3
"""check-abi.py — Validate PvtFheVerifier ABI against T22 api-spec.md.

Usage:
    python3 check-abi.py <abi.json> [api-spec.md]

Exits 0 if the ABI contains a `verify` function with the exact parameter types
specified in T22 api-spec.md. Exits 1 with an error message otherwise.

Expected `verify` signature (T22 api-spec.md, Interface 4):
    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view returns (bool valid)
"""

import json
import sys
import re

# ---------------------------------------------------------------------------
# Expected ABI (hardcoded from T22 api-spec.md, Interface 4)
# ---------------------------------------------------------------------------

EXPECTED_VERIFY_INPUTS = [
    {"name": "ciphertextHash",     "type": "bytes32"},
    {"name": "plaintextHash",      "type": "bytes32"},
    {"name": "aggregatePkHash",    "type": "bytes32"},
    {"name": "dkgRoot",            "type": "bytes32"},
    {"name": "epoch",              "type": "uint64"},
    {"name": "participantSetHash", "type": "bytes32"},
    {"name": "dCommitment",        "type": "bytes32"},
    {"name": "proof",              "type": "bytes"},
]

EXPECTED_VERIFY_OUTPUTS = [
    {"name": "valid", "type": "bool"},
]

EXPECTED_THRESHOLD_OUTPUTS = [{"type": "uint32"}]
EXPECTED_RLWE_DEGREE_OUTPUTS = [{"type": "uint32"}]


def load_abi(path: str) -> list:
    with open(path) as f:
        data = json.load(f)
    # forge inspect produces either a bare array or {"abi": [...]}
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "abi" in data:
        return data["abi"]
    raise ValueError(f"Unrecognised ABI format in {path!r}")


def find_function(abi: list, name: str) -> dict | None:
    for entry in abi:
        if entry.get("type") == "function" and entry.get("name") == name:
            return entry
    return None


def check_params(actual: list, expected: list, label: str) -> list[str]:
    errors = []
    if len(actual) != len(expected):
        errors.append(
            f"{label}: expected {len(expected)} params, got {len(actual)}"
        )
        return errors
    for i, (a, e) in enumerate(zip(actual, expected)):
        if a.get("type") != e["type"]:
            errors.append(
                f"{label} param[{i}] ({a.get('name', '?')}): "
                f"expected type {e['type']!r}, got {a.get('type')!r}"
            )
        if "name" in e and a.get("name") != e["name"]:
            errors.append(
                f"{label} param[{i}]: expected name {e['name']!r}, got {a.get('name')!r}"
            )
    return errors


def validate_abi(abi: list) -> list[str]:
    errors = []

    # --- verify() ---
    fn = find_function(abi, "verify")
    if fn is None:
        errors.append("Missing function: verify")
    else:
        errors.extend(check_params(fn.get("inputs", []), EXPECTED_VERIFY_INPUTS, "verify inputs"))
        outputs = fn.get("outputs", [])
        if len(outputs) != 1 or outputs[0].get("type") != "bool":
            errors.append(
                f"verify outputs: expected [(bool valid)], got {outputs}"
            )
        if fn.get("stateMutability") not in ("view", "pure"):
            errors.append(
                f"verify stateMutability: expected 'view', got {fn.get('stateMutability')!r}"
            )

    # --- threshold() ---
    fn_t = find_function(abi, "threshold")
    if fn_t is None:
        errors.append("Missing function: threshold")
    else:
        outputs = fn_t.get("outputs", [])
        if len(outputs) != 1 or outputs[0].get("type") != "uint32":
            errors.append(f"threshold outputs: expected [(uint32)], got {outputs}")

    # --- rlweDegree() ---
    fn_r = find_function(abi, "rlweDegree")
    if fn_r is None:
        errors.append("Missing function: rlweDegree")
    else:
        outputs = fn_r.get("outputs", [])
        if len(outputs) != 1 or outputs[0].get("type") != "uint32":
            errors.append(f"rlweDegree outputs: expected [(uint32)], got {outputs}")

    return errors


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-abi.py <abi.json> [api-spec.md]", file=sys.stderr)
        return 1

    abi_path = sys.argv[1]

    try:
        abi = load_abi(abi_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: failed to load ABI from {abi_path!r}: {exc}", file=sys.stderr)
        return 1

    errors = validate_abi(abi)

    if errors:
        print("ABI validation FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("ABI validation PASSED: verify(), threshold(), rlweDegree() match T22 spec.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
