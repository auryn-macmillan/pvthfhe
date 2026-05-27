#!/usr/bin/env bash
# Run the minimal Nova-only probe with a strict virtual-memory cap and
# sample VmRSS from /proc/<pid>/status every 5s.
# Detached usage:
#   setsid nohup .sisyphus/scripts/run-probe-nova-min.sh </dev/null >.../launcher.out 2>&1 & disown
set -uo pipefail

ROOT="/home/dev/pvthfhe"
EVIDENCE="$ROOT/.sisyphus/evidence/bench-comparison-mem/probe-nova-min"
STATUS="$EVIDENCE/STATUS"
LOG="$EVIDENCE/run.log"
MEM_LOG="$EVIDENCE/mem.log"
TIME_LOG="$EVIDENCE/time.log"
PID_FILE="$EVIDENCE/pid"
BIN_PID_FILE="$EVIDENCE/bin.pid"

mkdir -p "$EVIDENCE"
printf 'started %s pid=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" > "$STATUS"
: > "$MEM_LOG"
printf '%s\n' "$$" > "$PID_FILE"
rm -f "$BIN_PID_FILE"

ulimit -v 16777216 || true
ulimit -d 16777216 || true

export RUST_LOG=info
export RUST_BACKTRACE=1
export EVIDENCE

cd "$ROOT"

/usr/bin/time -v -o "$TIME_LOG" bash -lc 'printf "%s\n" "$$" > "$EVIDENCE/bin.pid"; exec ./target/release/nova-min' > "$LOG" 2>&1 &
TIME_PID=$!

while [ ! -s "$BIN_PID_FILE" ]; do
  if ! kill -0 "$TIME_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

BIN_PID=""
if [ -s "$BIN_PID_FILE" ]; then
  BIN_PID=$(tr -d '\n' < "$BIN_PID_FILE")
fi

SAMPLER_PID=""
if [ -n "$BIN_PID" ]; then
  (
    while kill -0 "$BIN_PID" 2>/dev/null; do
      ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
      vmrss=$(grep '^VmRSS:' "/proc/$BIN_PID/status" 2>/dev/null | awk '{print $2}')
      printf '%s vmrss_kb=%s\n' "$ts" "${vmrss:-0}"
      sleep 5
    done
  ) >> "$MEM_LOG" &
  SAMPLER_PID=$!
fi

wait "$TIME_PID"
rc=$?

if [ -n "$SAMPLER_PID" ]; then
  kill "$SAMPLER_PID" 2>/dev/null || true
fi

peak=$(grep -E 'Maximum resident set size' "$TIME_LOG" 2>/dev/null | awk '{print $NF}')
printf 'rc=%s peak_rss_kb=%s %s\n' "$rc" "${peak:-unknown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS"
exit "$rc"
