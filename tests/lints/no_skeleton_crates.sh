#!/usr/bin/env bash
set -euo pipefail

fail=0

while IFS= read -r lib; do
  lines=$(wc -l < "$lib")
  if (( lines < 20 )); then
    if ! grep -Fq '# ⚠️ INTENTIONALLY MINIMAL' "$lib"; then
      printf 'OFFENDING: %s (%s lines, no rationale header)\n' "$lib" "$lines"
      fail=1
    fi
  fi
done < <(find crates -mindepth 3 -maxdepth 3 -type f -name lib.rs -path '*/src/lib.rs' | sort)

exit "$fail"
