#!/usr/bin/env python3
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NS = [128, 256, 512, 1024]
RESULTS_DIR = "bench/results"
FIGURES_DIR = "bench/figures"

os.makedirs(FIGURES_DIR, exist_ok=True)

data = {}
for n in NS:
    path = os.path.join(RESULTS_DIR, f"scaling-n{n}.json")
    with open(path) as f:
        data[n] = json.load(f)

ns = NS
mean_ms = [data[n]["mean"] / 1e6 for n in ns]
median_ms = [data[n]["median"] / 1e6 for n in ns]
p99_ms = [data[n]["p99"] / 1e6 for n in ns]
gas = [data[n]["verifier_gas"] for n in ns]
proof_bytes = [data[n]["final_snark_size_bytes"] for n in ns]

fig, ax = plt.subplots()
ax.plot(ns, mean_ms, marker="o", label="mean")
ax.plot(ns, median_ms, marker="s", label="median")
ax.plot(ns, p99_ms, marker="^", label="p99")
ax.set_xlabel("n (parties)")
ax.set_ylabel("wall-clock time (ms)")
ax.set_title("E2E Pipeline Time vs n")
ax.legend()
ax.set_xscale("log", base=2)
fig.tight_layout()
fig.savefig(os.path.join(FIGURES_DIR, "time_vs_n.png"), dpi=150)
plt.close(fig)
print(f"Saved time_vs_n.png")

fig, ax = plt.subplots()
ax.plot(ns, gas, marker="o", color="orange")
ax.set_xlabel("n (parties)")
ax.set_ylabel("verifier gas")
ax.set_title("On-chain Verifier Gas vs n")
ax.set_xscale("log", base=2)
fig.tight_layout()
fig.savefig(os.path.join(FIGURES_DIR, "gas_vs_n.png"), dpi=150)
plt.close(fig)
print(f"Saved gas_vs_n.png")

fig, ax = plt.subplots()
ax.plot(ns, proof_bytes, marker="o", color="green")
ax.set_xlabel("n (parties)")
ax.set_ylabel("proof size (bytes)")
ax.set_title("Final SNARK Proof Size vs n")
ax.set_xscale("log", base=2)
fig.tight_layout()
fig.savefig(os.path.join(FIGURES_DIR, "proof_size_vs_n.png"), dpi=150)
plt.close(fig)
print(f"Saved proof_size_vs_n.png")
