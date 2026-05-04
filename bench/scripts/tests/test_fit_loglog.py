"""Tests for bench/scripts/fit-loglog.py."""

import json
import subprocess
import sys


def test_fit_loglog_defaults_to_scaling_results_and_accepts_scaling_schema(tmp_path):
    results_dir = tmp_path / "bench" / "results"
    results_dir.mkdir(parents=True)

    samples = {
        128: 1.55,
        256: 6.70,
        512: 45.92,
        1024: 182.31,
    }
    for n, aggregator_wall_ms in samples.items():
        path = results_dir / f"scaling-n{n}.json"
        path.write_text(
            json.dumps({"n": n, "aggregator_wall_ms": aggregator_wall_ms}),
            encoding="utf-8",
        )

    script = "/home/dev/pvthfhe/bench/scripts/fit-loglog.py"
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "sub-quadratic growth: CONFIRMED" in result.stdout
