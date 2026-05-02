#!/usr/bin/env bash
set -euo pipefail

N=128
RUNS=3
RESULTS_DIR="bench/results"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --n) N="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        t11-rlwe-relation)
            cat <<'EOF'
source /home/dev/.cargo/env
export PATH="/home/dev/.cargo/bin:/home/dev/.foundry/bin:/home/dev/.nargo/bin:/home/dev/.bb:$PATH"

cd /home/dev/pvthfhe/circuits
nargo compile --package rlwe_relation
nargo execute --package rlwe_relation --prover-name Prover_valid
bb write_vk --scheme ultra_honk -b target/rlwe_relation.json -o target
bb prove --scheme ultra_honk -b target/rlwe_relation.json -w target/rlwe_relation.gz -o target
bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
EOF
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"

echo "=== Hardware Fingerprint ===" | tee "$RESULTS_DIR/hardware-fingerprint.txt"
echo "--- /proc/cpuinfo (model name) ---" | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"
grep "model name" /proc/cpuinfo | head -1 | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"
echo "--- /proc/meminfo (MemTotal) ---" | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"
grep "MemTotal" /proc/meminfo | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"
echo "--- /proc/version ---" | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"
cat /proc/version | tee -a "$RESULTS_DIR/hardware-fingerprint.txt"

source /home/dev/.cargo/env 2>/dev/null || true
export PATH="/home/dev/.cargo/bin:/home/dev/.foundry/bin:/home/dev/.nargo/bin:/home/dev/.bb:$PATH"

cargo build --release -p pvthfhe-bench --bin bench_scaling 2>&1

for i in $(seq 1 "$RUNS"); do
    echo "Run $i/$RUNS for n=$N..."
    cargo run --release -p pvthfhe-bench --bin bench_scaling 2>/dev/null
    if [ -f "$RESULTS_DIR/scaling-n${N}.json" ]; then
        cp "$RESULTS_DIR/scaling-n${N}.json" "$RESULTS_DIR/scaling-n${N}-run${i}.json"
        echo "  saved scaling-n${N}-run${i}.json"
    fi
done

echo "Reproduce complete. Results in $RESULTS_DIR/"

