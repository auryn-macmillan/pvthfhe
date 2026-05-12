#!/usr/bin/env python3
"""I.1 benchmark/dryrun: one-track vs two-track committed-smudge.

This script intentionally emits an honest benchmark envelope even when the full
apples-to-apples benchmark is blocked.  Current branch state keeps the D.1
share-encryption verifier fail-closed, so the non-bypassed e2e PVSS path is
first probed and recorded.  Feasible fallback probes then measure the current
one-track proof-producing path with the existing demo dry-run verification
bypass, and focused two-track/committed-smudge code paths with their existing
tests.  Any non-comparable metric is explicitly marked unavailable rather than
estimated as a production measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results"
JSON_OUT = RESULTS / "i1-one-vs-two-track.json"
MD_OUT = RESULTS / "i1-one-vs-two-track.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=5, help="representative party count")
    parser.add_argument("--t", type=int, default=2, help="representative threshold")
    parser.add_argument("--seed", type=int, default=1, help="deterministic seed label")
    parser.add_argument("--timeout", type=int, default=180, help="per-command timeout seconds")
    return parser.parse_args()


def cargo_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PVTHFHE_ALLOW_RESEARCH_BUILD"] = "1"
    return env


def run_command(argv: list[str], timeout: int) -> dict[str, Any]:
    command = argv[:]
    timed_argv = command
    if shutil.which("/usr/bin/time"):
        timed_argv = ["/usr/bin/time", "-v", *command]

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            timed_argv,
            cwd=ROOT,
            env=cargo_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        timed_out = False
        returncode: int | None = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = stringify_process_output(exc.stdout)
        stderr = stringify_process_output(exc.stderr)

    wall_ms = (time.perf_counter() - started) * 1000.0
    combined = f"{stdout}\n{stderr}"
    max_rss_kb = parse_time_max_rss(combined)
    return {
        "argv": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "wall_ms": wall_ms,
        "max_rss_kb": max_rss_kb,
        "stdout_tail": tail(stdout),
        "stderr_tail": tail(stderr),
    }


def parse_time_max_rss(output: str) -> int | None:
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", output)
    return int(match.group(1)) if match else None


def stringify_process_output(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def tail(text: str, max_chars: int = 6000) -> str:
    return text[-max_chars:]


def share_encryption_ms(command: dict[str, Any]) -> float | None:
    text = f"{command.get('stdout_tail', '')}\n{command.get('stderr_tail', '')}"
    match = re.search(r"share_encryption_proof_ms=(\d+(?:\.\d+)?)", text)
    return float(match.group(1)) if match else None


def git_sha() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True)
        return out.strip() or "unknown"
    except Exception:
        return "unknown"


def hardware() -> dict[str, Any]:
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem_total_kb = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
                break
    except OSError:
        pass
    kernel = "unknown"
    try:
        kernel = " ".join(Path("/proc/version").read_text(encoding="utf-8").split()[:3])
    except OSError:
        pass
    return {"cpu": cpu, "cpu_cores": os.cpu_count(), "mem_total_kb": mem_total_kb, "kernel": kernel}


def unavailable(reason: str) -> dict[str, Any]:
    return {"value": None, "status": "unavailable", "reason": reason}


def measured(value: float | int | None, unit: str, note: str | None = None) -> dict[str, Any]:
    if value is None:
        return unavailable("measurement did not appear in command output")
    out: dict[str, Any] = {"value": value, "unit": unit, "status": "measured"}
    if note:
        out["note"] = note
    return out


def main() -> int:
    args = parse_args()
    RESULTS.mkdir(parents=True, exist_ok=True)

    full_probe = run_command(
        [
            "cargo",
            "run",
            "-p",
            "pvthfhe-cli",
            "--bin",
            "pvthfhe-e2e",
            "--",
            "--n",
            str(args.n),
            "--t",
            str(args.t),
            "--seed",
            str(args.seed),
            "--dry-run",
        ],
        args.timeout,
    )

    one_track_fallback = run_command(
        [
            "cargo",
            "run",
            "-p",
            "pvthfhe-cli",
            "--features",
            "demo-seeded-rng",
            "--bin",
            "pvthfhe-e2e",
            "--",
            "--n",
            str(args.n),
            "--t",
            str(args.t),
            "--seed",
            str(args.seed),
            "--dry-run",
        ],
        args.timeout,
    )

    two_track_batched = run_command(
        [
            "cargo",
            "test",
            "-p",
            "pvthfhe-pvss",
            "--test",
            "nizk_share_batched_tracks",
            "--",
            "batched_valid_tracks_fail_closed_until_d1_bfv_relation_exists",
            "--exact",
            "--nocapture",
        ],
        args.timeout,
    )

    committed_smudge = run_command(
        [
            "cargo",
            "test",
            "-p",
            "pvthfhe-fhe",
            "--test",
            "committed_smudge_requires_esm",
            "--",
            "committed_smudge_with_valid_esm_succeeds",
            "--exact",
            "--nocapture",
        ],
        args.timeout,
    )

    dkg_ms = share_encryption_ms(one_track_fallback)
    per_party_dkg_ms = dkg_ms / args.n if dkg_ms is not None and args.n else None
    per_wire_share_ms = dkg_ms / (args.n * (args.n - 1)) if dkg_ms is not None and args.n > 1 else None

    d1_blocked = full_probe["returncode"] != 0 and "v3 proof lacks verifier-checkable BFV encryption relation" in (
        full_probe.get("stderr_tail", "") + full_probe.get("stdout_tail", "")
    )
    comparable_two_track = False
    overhead_ratio = None

    envelope: dict[str, Any] = {
        "schema_version": "i1.one_vs_two_track.v1",
        "produced_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_sha": git_sha(),
        "benchmark_mode": "fallback-dryrun",
        "representative_parameters": {"n": args.n, "t": args.t, "seed": args.seed},
        "hardware": hardware(),
        "commands": {
            "full_current_one_track_probe": full_probe,
            "one_track_proof_producer_demo_seeded_fallback": one_track_fallback,
            "two_track_batched_share_proof_focused_probe": two_track_batched,
            "committed_smudge_decrypt_focused_probe": committed_smudge,
        },
        "metrics": {
            "one_track_current": {
                "status": "blocked" if d1_blocked else "measured",
                "blocker": "D.1 fail-closed v3 BFV share-encryption verifier" if d1_blocked else None,
                "dkg_prover_time_per_party_ms": measured(
                    per_party_dkg_ms,
                    "ms/party",
                    "Fallback dry-run with demo-seeded-rng skips fail-closed verify_shares; total divided by n.",
                ),
                "dkg_prover_time_per_wire_share_ms": measured(
                    per_wire_share_ms,
                    "ms/share",
                    "Fallback dry-run total divided by n*(n-1) PVSS recipient-share instances.",
                ),
                "decryption_proof_time_per_party_ms": unavailable(
                    "non-dry-run e2e path is blocked before decrypt proof metrics; dry-run does not emit pvss_decrypt_prove JSON"
                ),
                "fold_compression_time_ms": unavailable("dry-run returns before cyclo_fold/compressor phases"),
                "verifier_time_ms": unavailable("full verifier path fails closed at D.1 before stable comparison timing"),
                "proof_wire_size_bytes": unavailable("PVSS adapter does not expose aggregate proof/wire size in dry-run output"),
                "peak_memory_kb": measured(one_track_fallback.get("max_rss_kb"), "kB"),
            },
            "two_track_committed_smudge_current": {
                "status": "focused-probes-only",
                "dkg_prover_time_per_party_ms": unavailable(
                    "two-track sk+e_sm DKG proof-producing path is not wired into pvthfhe-e2e/bench runner; focused batched proof test uses MockBackend and is not comparable to real one-track BFV PVSS"
                ),
                "decryption_proof_time_per_party_ms": measured(
                    committed_smudge.get("wall_ms"),
                    "ms/test-command",
                    "Focused real FhersBackend committed-smudge API test wall time; includes setup/keygen/encrypt and is not a per-party proof-only timing.",
                ),
                "fold_compression_time_ms": unavailable("two-track committed-smudge fold/compression is not exposed by a benchmark runner"),
                "verifier_time_ms": unavailable(
                    "batched two-track verification intentionally delegates to D.1 v3 verifier and fails closed"
                ),
                "proof_wire_size_bytes": unavailable("focused tests do not emit proof/wire byte counts"),
                "peak_memory_kb": measured(
                    max(v for v in [two_track_batched.get("max_rss_kb"), committed_smudge.get("max_rss_kb")] if v is not None)
                    if any(v is not None for v in [two_track_batched.get("max_rss_kb"), committed_smudge.get("max_rss_kb")])
                    else None,
                    "kB",
                ),
            },
        },
        "overhead_ratios": {
            "dkg_proof_producing_path_two_track_over_one_track": {
                "value": overhead_ratio,
                "status": "unavailable" if not comparable_two_track else "measured",
                "target": "<= 1.5x",
                "reason": "No fair apples-to-apples two-track committed-smudge DKG benchmark runner exists on this branch, and full one-track verification remains D.1 fail-closed.",
            }
        },
        "gate": {
            "target": "Two-track overhead <= 1.5x one-track PVTHFHE for DKG proof-producing path",
            "status": "not_fairly_measurable_current_branch",
            "explanation": "The current branch can produce one-track dry-run timing only with demo-seeded-rng verification bypass; the normal path fails closed at D.1. Two-track sk/e_sm proof surfaces and committed-smudge decrypt APIs have focused tests, but no integrated real-BFV e2e benchmark runner emits comparable DKG proof-producing timings or wire sizes. The target is therefore neither met nor failed by this fallback artifact.",
        },
        "performance_advantage": {
            "status": "not_fairly_measurable_current_branch",
            "statement": "The intended PVTHFHE performance advantage is not demonstrated by this artifact. Current data quantify only fallback/dry-run one-track costs and focused non-comparable two-track probes; fair real-BFV two-track DKG overhead remains blocked by D.1 and missing integrated benchmark output.",
        },
    }

    JSON_OUT.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    MD_OUT.write_text(render_markdown(envelope), encoding="utf-8")
    print(f"wrote {JSON_OUT}")
    print(f"wrote {MD_OUT}")
    return 0


def metric_line(metrics: dict[str, Any], key: str) -> str:
    value = metrics[key]
    if value.get("status") == "measured":
        return f"{value['value']:.3f} {value['unit']}"
    return f"unavailable — {value.get('reason', 'not measured')}"


def render_markdown(envelope: dict[str, Any]) -> str:
    one = envelope["metrics"]["one_track_current"]
    two = envelope["metrics"]["two_track_committed_smudge_current"]
    ratio = envelope["overhead_ratios"]["dkg_proof_producing_path_two_track_over_one_track"]
    return f"""# I.1 — One-track vs two-track PVTHFHE benchmark/dryrun

- Produced: `{envelope['produced_at']}`
- Git SHA: `{envelope['git_sha']}`
- Parameters: `n={envelope['representative_parameters']['n']}`, `t={envelope['representative_parameters']['t']}`, `seed={envelope['representative_parameters']['seed']}`
- Mode: `{envelope['benchmark_mode']}`

## Gate status

**{envelope['gate']['status']}** — {envelope['gate']['explanation']}

DKG overhead target `{ratio['target']}`: **{ratio['status']}** ({ratio['reason']})

Performance-advantage status: **{envelope['performance_advantage']['status']}** — {envelope['performance_advantage']['statement']}

## Metrics

| Metric | One-track current | Two-track committed-smudge current |
|---|---:|---:|
| DKG prover time per party | {metric_line(one, 'dkg_prover_time_per_party_ms')} | {metric_line(two, 'dkg_prover_time_per_party_ms')} |
| DKG prover time per wire share | {metric_line(one, 'dkg_prover_time_per_wire_share_ms')} | n/a |
| Decryption proof time per party | {metric_line(one, 'decryption_proof_time_per_party_ms')} | {metric_line(two, 'decryption_proof_time_per_party_ms')} |
| Fold/compression time | {metric_line(one, 'fold_compression_time_ms')} | {metric_line(two, 'fold_compression_time_ms')} |
| Verifier time | {metric_line(one, 'verifier_time_ms')} | {metric_line(two, 'verifier_time_ms')} |
| Proof/wire size | {metric_line(one, 'proof_wire_size_bytes')} | {metric_line(two, 'proof_wire_size_bytes')} |
| Peak memory | {metric_line(one, 'peak_memory_kb')} | {metric_line(two, 'peak_memory_kb')} |

## Commands

See `{JSON_OUT.name}` for exact argv, return codes, output tails, wall times, and max RSS.  The non-bypassed current one-track probe records the D.1 fail-closed error before fallback probes are used.
"""


if __name__ == "__main__":
    raise SystemExit(main())
