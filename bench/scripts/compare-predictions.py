#!/usr/bin/env python3
"""Compare measured bench results vs T15 Architecture B predictions.

Flags deviations >2x as anomalies and exits non-zero if any unannotated.
"""
import json
import os
import sys

RESULTS_DIR = "bench/results"

ARCH_B_PREDICTIONS = {
    "per_party_work": "O(N log N) NTT + O(1) fold contribution",
    "aggregator_work": "O(log N) fold rounds",
    "verifier_gas_range": (200_000, 500_000),
    "proof_size_bytes": 14_336,
    "on_chain_gas_snark": 1278,
}

ANNOTATED_DEVIATIONS = {
    "verifier_gas": "Surrogate verifier uses constant 1278 gas (mock); real UltraHonk ~200k-500k",
    "proof_size": "Simulator proof is hash-chain (32+n*32 bytes); real UltraHonk ~14KB",
}

def load(n):
    path = os.path.join(RESULTS_DIR, f"scaling-n{n}.json")
    with open(path) as f:
        return json.load(f)

ns = [128, 256, 512, 1024]
results = {n: load(n) for n in ns}

print(f"{'n':>6} {'mean_ms':>10} {'median_ms':>10} {'p99_ms':>10} {'snark_B':>10} {'gas':>8}")
print("-" * 60)
for n in ns:
    d = results[n]
    print(f"{n:>6} {d['mean']/1e6:>10.2f} {d['median']/1e6:>10.2f} {d['p99']/1e6:>10.2f} "
          f"{d['final_snark_size_bytes']:>10} {d['verifier_gas']:>8}")

print()
print("=== Deviation Analysis vs T15 Architecture B Predictions ===")

anomalies = []

for n in ns:
    d = results[n]
    gas = d["verifier_gas"]
    pred_gas_lo, pred_gas_hi = ARCH_B_PREDICTIONS["verifier_gas_range"]
    if gas < pred_gas_lo / 2 or gas > pred_gas_hi * 2:
        if "verifier_gas" not in ANNOTATED_DEVIATIONS:
            anomalies.append(f"n={n}: verifier_gas={gas} deviates >2x from predicted {pred_gas_lo}-{pred_gas_hi}")
        else:
            print(f"  [ANNOTATED] n={n} verifier_gas={gas}: {ANNOTATED_DEVIATIONS['verifier_gas']}")

    proof_bytes = d["final_snark_size_bytes"]
    pred_proof = ARCH_B_PREDICTIONS["proof_size_bytes"]
    ratio = proof_bytes / pred_proof if pred_proof > 0 else 1
    if ratio > 2 or ratio < 0.5:
        if "proof_size" not in ANNOTATED_DEVIATIONS:
            anomalies.append(f"n={n}: proof_size={proof_bytes}B deviates >2x from predicted {pred_proof}B")
        else:
            print(f"  [ANNOTATED] n={n} proof_size={proof_bytes}B vs predicted {pred_proof}B: "
                  f"{ANNOTATED_DEVIATIONS['proof_size']}")

if anomalies:
    print()
    print("UNANNOTATED ANOMALIES (>2x deviation):")
    for a in anomalies:
        print(f"  ANOMALY: {a}")
    sys.exit(1)

print()
print("All deviations are annotated. No unannotated anomalies.")

