#!/usr/bin/env python3
"""Shared gate utilities for PVTHFHE gate scripts."""
import json
import os
import sys
from datetime import datetime, timezone


def emit_evidence(gate_name, subcheck, status, details, evidence_dir=".sisyphus/evidence"):
    os.makedirs(evidence_dir, exist_ok=True)
    record = {
        "gate": gate_name,
        "subcheck": subcheck,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    path = os.path.join(evidence_dir, f"{gate_name}-{subcheck}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return record


def run_gate(gate_name, subchecks_map, args):
    """
    gate_name: str
    subchecks_map: dict[str, callable() -> (bool, list[str])]
    args: parsed argparse namespace (needs .check, .stub)
    """
    if args.stub:
        print(f"PASS: {gate_name} (--stub mode)")
        sys.exit(0)

    if args.check:
        name = args.check
        if name not in subchecks_map:
            print(f"FAIL: unknown subcheck '{name}'")
            sys.exit(1)
        ok, details = subchecks_map[name]()
        status = "PASS" if ok else "FAIL"
        emit_evidence(gate_name, name, status, details)
        for d in details:
            print(d)
        print(f"{status}: {gate_name}/{name}")
        sys.exit(0 if ok else 1)
    else:
        all_ok = True
        for name, fn in subchecks_map.items():
            ok, details = fn()
            status = "PASS" if ok else "FAIL"
            emit_evidence(gate_name, name, status, details)
            for d in details:
                print(d)
            print(f"  {status}: {name}")
            if not ok:
                all_ok = False
        overall = "PASS" if all_ok else "FAIL"
        print(f"\n{overall}: {gate_name}")
        sys.exit(0 if all_ok else 1)
