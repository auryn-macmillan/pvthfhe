#!/usr/bin/env bash
# RED phase for R0.8: this lint must fail on current main.

set -euo pipefail

fail=0

matches=$(grep -rEn --include='*.sol' -e 'valid.*==.*keccak256\(proof\)' -e 'assertEq[[:space:]]*\([[:space:]]*ok[[:space:]]*,[[:space:]]*ciphertextHash' contracts/test/ --exclude-dir=lints 2>/dev/null || true)

if [[ -n "$matches" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    file=${line%%:*}
    rest=${line#*:}
    lineno=${rest%%:*}
    text=${rest#*:}
    printf 'FAIL: %s:%s ⇒ %s\n' "$file" "$lineno" "$text" >&2
    fail=1
  done <<< "$matches"
fi

if [[ $fail -ne 0 ]]; then
  exit 1
fi

printf 'PASS: no keccak tautologies detected\n'
