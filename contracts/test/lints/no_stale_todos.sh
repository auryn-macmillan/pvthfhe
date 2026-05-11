#!/usr/bin/env bash
# R6.5 RED: no_stale_todos.sh — greps contracts/src/ for TODO, FIXME, XXX, SCAFFOLD.
# Must be empty or whitelisted with file:line + ticket reference.
# Fails on current main because PvtFheVerifier.sol:84 has a SCAFFOLD note (F13).

set -euo pipefail

fail=0
SRC_DIR="$(dirname "$0")/../../src"

# Patterns that are considered stale markers.
# We exclude lines that are part of an approved whitelist (format: file:line ticket-ref).
patterns=(
  "TODO"
  "FIXME"
  "XXX"
  "SCAFFOLD"
)

while IFS= read -r -d '' file; do
  while IFS=: read -r lineno text; do
    [[ -z "$lineno" ]] && continue
    # Skip whitelisted entries: format "file_path:line_number ticket-reference"
    whitelisted=false
    # Allow list: currently none. Add entries here as <<file_path>>:<<line>> <<ticket>>
    # Example: contracts/src/Foo.sol:42 PVTHFHE-9999
    for w in \
      "" \
    ; do
      [[ -z "$w" ]] && continue
      if [[ "$file:$lineno" == "$(echo "$w" | cut -d' ' -f1)" ]]; then
        whitelisted=true
        break
      fi
    done
    if $whitelisted; then
      continue
    fi
    printf 'FAIL: %s:%s ⇒ %s\n' "$file" "$lineno" "$text" >&2
    fail=1
  done < <(grep -nH -E "$(IFS='|'; echo "${patterns[*]}")" "$file" 2>/dev/null || true)
done < <(find "$SRC_DIR" -name '*.sol' -print0 | sort -z)

if [[ $fail -ne 0 ]]; then
  exit 1
fi

printf 'PASS: no stale TODOs/FIXMEs/SCAFFOLDs in contracts/src/\n'
