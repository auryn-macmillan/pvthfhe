#!/usr/bin/env python3
"""Phase 7 forged-proof harness orchestrator.

Runs existing adversarial Rust and Foundry tests and records fresh evidence that
the current research prototype does not accept the selected forged/tampered proof
paths. This script is an orchestrator only: it does not implement cryptography.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast


REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = REPO_ROOT / ".sisyphus" / "evidence" / "phase7-forged-proof-harness.json"

DISCLAIMER = " ".join(
    [
        "RESEARCH PROTOTYPE — DO NOT DEPLOY.",
        "Cases forged_ivc_decider and cyclo_accumulator_fail_closed demonstrate",
        "FAIL-CLOSED NON-ACCEPTANCE for OPEN problems P4/A1, not cryptographic soundness.",
        "P4/C7/C5/A1 remain BLOCKED-OPEN.",
    ]
)

REJECTION_CLASSES = {
    "cryptographic_reject",
    "input_validation_reject",
    "fail_closed_blocked_open",
}


@dataclass(frozen=True)
class Case:
    name: str
    command: tuple[str, ...]
    rejection_class: str
    note: str


CASES = (
    Case(
        name="folding_witness_tamper",
        command=(
            "cargo",
            "test",
            "-p",
            "pvthfhe-aggregator",
            "--test",
            "folding_tamper",
            "real_folding_gaps::test_fold_tampered_witness_rejected",
            "--",
            "--exact",
            "--nocapture",
        ),
        rejection_class="input_validation_reject",
        note="Fold witness with a 0xff-tampered proof byte rejected by validate_witness NORM-BOUND check (folding/mod.rs) BEFORE NIZK verification. This is input validation, NOT cryptographic proof rejection.",
    ),
    Case(
        name="forged_ivc_decider",
        command=(
            "forge",
            "test",
            "--root",
            "contracts",
            "--match-path",
            "test/IvcFailClosed.t.sol",
            "--match-test",
            "testRejectsForgedIvcVerifyResult",
            "-vv",
        ),
        rejection_class="fail_closed_blocked_open",
        note="Forged IVC verify result rejected because on-chain IVC decider is fail-closed/not configured (P4 OPEN). NON-ACCEPTANCE, not cryptographic soundness.",
    ),
    Case(
        name="tampered_c5_pk",
        command=(
            "cargo",
            "test",
            "-p",
            "pvthfhe-compressor",
            "--test",
            "bfv_encryption_adversarial",
            "tampered_pk0_rejected",
            "--",
            "--exact",
            "--nocapture",
        ),
        rejection_class="input_validation_reject",
        note="Tampered aggregate/encryption public-key input is not accepted; C5 aggregate-pk proof remains OPEN.",
    ),
    Case(
        name="committed_smudge_requires_esm",
        command=(
            "cargo",
            "test",
            "-p",
            "pvthfhe-pvss",
            "--features",
            "mock",
            "--test",
            "nizk_decrypt_committed_smudge",
            "committed_smudge_requires_explicit_esm_witness",
            "--",
            "--exact",
            "--nocapture",
        ),
        rejection_class="cryptographic_reject",
        note="Committed-smudge proof construction fails without the explicit ESM witness required by the remediated C6 binding path.",
    ),
    Case(
        name="legacy_smudge_fallback_rejected",
        command=(
            "cargo",
            "test",
            "-p",
            "pvthfhe-pvss",
            "--features",
            "mock",
            "--test",
            "nizk_decrypt_committed_smudge",
            "committed_smudge_rejects_local_smudge_proof",
            "--",
            "--exact",
            "--nocapture",
        ),
        rejection_class="cryptographic_reject",
        note="Committed-smudge verifier rejects a legacy/local-smudge proof under a committed-smudge statement.",
    ),
    Case(
        name="cyclo_accumulator_fail_closed",
        command=(
            "cargo",
            "test",
            "-p",
            "pvthfhe-nizk",
            "--test",
            "accumulator_fail_closed",
            "accumulator_nonzero_transcript_bytes_fail_closed",
            "--",
            "--exact",
            "--nocapture",
        ),
        rejection_class="fail_closed_blocked_open",
        note="Bogus Cyclo accumulator transcript bytes fail closed because A1 accumulator verification remains OPEN.",
    ),
)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Phase 7 forged-proof non-acceptance harness and emit evidence JSON.",
    )
    _ = parser.add_argument(
        "--evidence-path",
        default=str(EVIDENCE_PATH),
        help=f"where to write evidence JSON (default: {EVIDENCE_PATH})",
    )
    _ = parser.add_argument(
        "--list-cases",
        action="store_true",
        help="list case names and commands without running them",
    )
    return parser.parse_args(list(argv))


def validate_cases() -> None:
    names = [case.name for case in CASES]
    if len(CASES) != 6:
        raise RuntimeError(f"expected exactly 6 cases, found {len(CASES)}")
    if len(set(names)) != len(names):
        raise RuntimeError(f"case names must be unique, found {names}")
    for case in CASES:
        if case.rejection_class not in REJECTION_CLASSES:
            raise RuntimeError(f"invalid rejection_class for {case.name}: {case.rejection_class}")


def subprocess_env(command: tuple[str, ...]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CI": "true",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    if command[0] == "cargo":
        env["PVTHFHE_ALLOW_RESEARCH_BUILD"] = "1"
        env["RUSTFLAGS"] = "-Awarnings"
    return env


def parse_observed_test_count(output: str) -> int:
    counts: list[int] = []

    for match in re.finditer(r"(?m)^\s*running\s+(\d+)\s+tests?\b", output):
        counts.append(int(match.group(1)))

    for match in re.finditer(r"(?m)^\s*test result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored", output):
        counts.append(sum(int(group) for group in match.groups()))

    for match in re.finditer(r"(?m)^\s*Ran\s+(\d+)\s+tests?\s+for\s+", output):
        counts.append(int(match.group(1)))

    for match in re.finditer(r"(?m)^\s*Suite result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+skipped", output):
        counts.append(sum(int(group) for group in match.groups()))

    return max(counts) if counts else 0


def run_case(case: Case) -> dict[str, object]:
    print(f"\n=== {case.name} ===")
    print("$ " + " ".join(case.command))
    completed = subprocess.run(
        case.command,
        cwd=REPO_ROOT,
        env=subprocess_env(case.command),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = completed.stdout or ""
    if output:
        print(output, end="" if output.endswith("\n") else "\n")

    observed_test_count = parse_observed_test_count(output)
    passed = completed.returncode == 0 and observed_test_count > 0
    if observed_test_count == 0:
        failure_reason = "filtered command ran ZERO observed tests"
    elif completed.returncode != 0:
        failure_reason = f"underlying command exited {completed.returncode}"
    else:
        failure_reason = ""

    status = "PASS" if passed else "FAIL"
    summary = (
        f"[{status}] {case.name}: exit_status={completed.returncode}, "
        f"observed_test_count={observed_test_count}, rejection_class={case.rejection_class}"
    )
    print(summary)
    if failure_reason:
        print(f"       reason: {failure_reason}")
    print(f"       note: {case.note}")

    return {
        "case_name": case.name,
        "command": list(case.command),
        "exit_status": completed.returncode,
        "observed_test_count": observed_test_count,
        "rejection_class": case.rejection_class,
        "note": case.note,
        "passed": passed,
        "failure_reason": failure_reason,
    }


def write_evidence(path: Path, case_results: list[dict[str, object]]) -> dict[str, object]:
    overall_pass = all(bool(result["passed"]) for result in case_results)
    evidence_cases = [
        {
            "case_name": result["case_name"],
            "command": result["command"],
            "exit_status": result["exit_status"],
            "observed_test_count": result["observed_test_count"],
            "rejection_class": result["rejection_class"],
            "note": result["note"],
        }
        for result in case_results
    ]
    evidence: dict[str, object] = {
        "generated_at": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        "disclaimer": DISCLAIMER,
        "overall_pass": overall_pass,
        "cases": evidence_cases,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main(argv: Iterable[str] = sys.argv[1:]) -> int:
    args = parse_args(argv)
    validate_cases()

    list_cases = cast(bool, args.list_cases)
    evidence_path = Path(cast(str, args.evidence_path))

    if list_cases:
        for case in CASES:
            print(f"{case.name}: {' '.join(case.command)}")
        return 0

    print("=" * 80)
    print(DISCLAIMER)
    print("=" * 80)

    case_results = [run_case(case) for case in CASES]
    evidence = write_evidence(evidence_path, case_results)

    print("\n" + "=" * 80)
    print(f"Evidence JSON: {evidence_path}")
    print(f"overall_pass={str(evidence['overall_pass']).lower()}")
    print("=" * 80)

    return 0 if bool(evidence["overall_pass"]) else 1


if __name__ == "__main__":
    sys.exit(main())
