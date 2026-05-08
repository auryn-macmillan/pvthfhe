#!/usr/bin/env bash
# Run pvthfhe-e2e probe mode with strict memory + thread caps so it self-terminates
# on overflow instead of taking down the host. Detached usage:
#   setsid nohup .sisyphus/scripts/run-probe-first.sh </dev/null >/tmp/probe-first-nohup.out 2>&1 & disown
set -uo pipefail

ROOT="/home/dev/pvthfhe"
EVIDENCE="$ROOT/.sisyphus/evidence/bench-comparison-mem/probe-first"
STATUS="$EVIDENCE/STATUS"
LOG="$EVIDENCE/run.log"
MEM_LOG="$EVIDENCE/mem.log"
TIME_LOG="$EVIDENCE/time.log"

mkdir -p "$EVIDENCE"
echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ) pid=$$" > "$STATUS"

# Cap virtual memory at 16 GiB so the process gets ENOMEM instead of OOM-killing host.
# 16 GiB = 16 * 1024 * 1024 KiB = 16777216
ulimit -v 16777216 || true
ulimit -d 16777216 || true

# Single-threaded to remove rayon-scratch as a variable.
export RAYON_NUM_THREADS=1
export RUST_LOG=info
export RUST_BACKTRACE=1

# Sampler: log MemAvailable + all pvthfhe-e2e RSS every 5s.
(
  while true; do
    ts=$(date +%s)
    mem_avail=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    rss_sum=$(ps -eo rss,comm | awk '$2 ~ /pvthfhe-e2e/ { s+=$1 } END { print s+0 }')
    printf '%s mem_avail_kb=%s pvthfhe_rss_kb=%s\n' "$ts" "$mem_avail" "$rss_sum"
    sleep 5
  done
) >> "$MEM_LOG" &
SAMPLER_PID=$!

cleanup() {
  kill "$SAMPLER_PID" 2>/dev/null || true
}
trap cleanup EXIT

cd "$ROOT"

/usr/bin/time -v -o "$TIME_LOG" \
  ./target/release/pvthfhe-e2e --n 3 --t 1 --seed 1 --probe-compressor-only \
  > "$LOG" 2>&1
rc=$?

kill "$SAMPLER_PID" 2>/dev/null || true

peak=$(grep -E "Maximum resident set size" "$TIME_LOG" 2>/dev/null | awk '{print $NF}')
echo "finished rc=$rc peak_rss_kb=${peak:-unknown} $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS"
exit "$rc"
