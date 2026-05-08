#!/usr/bin/env bash
# Detached real bench-comparison runner.
# Runs pvthfhe-e2e three times, then bench_comparison + render_comparison.
# Writes status to .sisyphus/evidence/bench-comparison-real/STATUS
# Captures stdout, stderr, peak RSS via /usr/bin/time -v.

set -uo pipefail

EVIDENCE_DIR="/home/dev/pvthfhe/.sisyphus/evidence/bench-comparison-real"
mkdir -p "$EVIDENCE_DIR"

STATUS="$EVIDENCE_DIR/STATUS"
LOG="$EVIDENCE_DIR/run.log"
MEM_LOG="$EVIDENCE_DIR/mem.log"

cd /home/dev/pvthfhe || exit 99

export RAYON_NUM_THREADS=4
export RUST_LOG=info

echo "STARTED $(date -Iseconds)" > "$STATUS"
echo "PID=$$" >> "$STATUS"

# Background memory sampler — every 10s
(
  while true; do
    ts=$(date -Iseconds)
    free_line=$(free -m | awk '/^Mem:/ {printf "mem_used_mb=%s mem_free_mb=%s", $3, $4}')
    swap_line=$(free -m | awk '/^Swap:/ {printf "swap_used_mb=%s", $3}')
    echo "$ts $free_line $swap_line" >> "$MEM_LOG"
    sleep 10
  done
) &
SAMPLER_PID=$!
echo "SAMPLER_PID=$SAMPLER_PID" >> "$STATUS"

cleanup() {
  kill "$SAMPLER_PID" 2>/dev/null || true
}
trap cleanup EXIT

run_step() {
  local label="$1"
  shift
  echo "=== $label : $(date -Iseconds) ===" | tee -a "$LOG"
  /usr/bin/time -v -o "$EVIDENCE_DIR/$label.time" "$@" >> "$LOG" 2>&1
  local rc=$?
  echo "RC[$label]=$rc" | tee -a "$STATUS"
  if [ $rc -ne 0 ]; then
    echo "FAILED $label rc=$rc $(date -Iseconds)" >> "$STATUS"
    exit $rc
  fi
}

run_step "e2e-run-1" ./target/release/pvthfhe-e2e --n 3 --t 1 --seed 1
run_step "e2e-run-2" ./target/release/pvthfhe-e2e --n 3 --t 1 --seed 1
run_step "e2e-run-3" ./target/release/pvthfhe-e2e --n 3 --t 1 --seed 1
run_step "bench_comparison" ./target/release/bench_comparison --n 3 --t 1 --seed 1
run_step "render_comparison" ./target/release/render_comparison --comparison-json bench/results/comparison.json --output-dir bench/results

echo "DONE $(date -Iseconds)" >> "$STATUS"
