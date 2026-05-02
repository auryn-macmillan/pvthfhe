#!/usr/bin/env python3
"""Assert max(|run_i - median| / median) < 0.15 across repeat runs."""
import json
import os
import sys
import statistics

RESULTS_DIR = "bench/results"
TOLERANCE = 0.15

def check_runs_for_n(n):
    runs = []
    for i in range(1, 10):
        path = os.path.join(RESULTS_DIR, f"scaling-n{n}-run{i}.json")
        if not os.path.exists(path):
            break
        with open(path) as f:
            data = json.load(f)
        runs.append(data["mean"])

    if len(runs) < 2:
        print(f"n={n}: only {len(runs)} run(s) found, skipping tolerance check")
        return True

    med = statistics.median(runs)
    deviations = [abs(r - med) / med for r in runs]
    max_dev = max(deviations)
    ok = max_dev < TOLERANCE
    status = "PASS" if ok else "FAIL"
    print(f"n={n}: runs={len(runs)} median={med:.0f}ns max_deviation={max_dev:.3f} [{status}]")
    return ok

all_ok = True
for n in [128, 256, 512, 1024]:
    if not check_runs_for_n(n):
        all_ok = False

if not all_ok:
    print("TOLERANCE CHECK FAILED")
    sys.exit(1)

print("All tolerance checks passed.")

