#!/usr/bin/env bash
# bench/p1/run.sh — Build and run the P1 lattice NIZK benchmark matrix.
# Outputs: bench/p1/results-{128,512,1024}.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

echo "[p1-bench] Building bench_nizk (release) ..."
cargo build --release -p pvthfhe-bench --bin bench_nizk

echo "[p1-bench] Running benchmark matrix ..."
cargo run --release -p pvthfhe-bench --bin bench_nizk

echo "[p1-bench] Results:"
for n in 128 512 1024; do
    echo "  bench/p1/results-${n}.json"
    cat "bench/p1/results-${n}.json"
    echo
done

echo "[p1-bench] Done."
