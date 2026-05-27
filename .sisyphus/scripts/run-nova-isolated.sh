#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/dev/pvthfhe"
EVIDENCE_DIR="$ROOT/.sisyphus/evidence/bench-comparison-mem/p0p"
STATUS="$EVIDENCE_DIR/STATUS"
LOG="$EVIDENCE_DIR/run.log"
MEM_LOG="$EVIDENCE_DIR/mem.log"

mkdir -p "$EVIDENCE_DIR"
echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS"
echo "pid=$$" >> "$STATUS"

cleanup() {
  kill "$SAMPLER_PID" 2>/dev/null || true
}

(
  while true; do
    mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_used=$((mem_total - mem_available))
    swap_free=$(grep SwapFree /proc/meminfo | awk '{print $2}')
    swap_total=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
    swap_used=$((swap_total - swap_free))
    printf '%s mem_used_kb=%s swap_used_kb=%s\n' "$(date +%s)" "$mem_used" "$swap_used"
    sleep 10
  done
) >> "$MEM_LOG" &
SAMPLER_PID=$!
trap cleanup EXIT

cd "$ROOT"
set +e
RUST_LOG=pvthfhe_compressor=info /usr/bin/time -v cargo run --release --example nova_isolated -p pvthfhe-compressor > "$LOG" 2>&1
rc=$?
set -e

echo "finished rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS"
exit "$rc"
