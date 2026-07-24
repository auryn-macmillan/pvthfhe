#!/usr/bin/env bash
# Canonical-doc consistency lint.
#
# Checks the four root docs (README/ARCHITECTURE/SECURITY/WARNING) for the
# invariants that past doc drift violated: banner presence, no killswitch-era
# claims, no stale-era stack references, and current toolchain naming.
set -euo pipefail

fail=0
docs=(README.md ARCHITECTURE.md SECURITY.md WARNING.md)

for doc in "${docs[@]}"; do
  if [[ ! -f "$doc" ]]; then
    printf 'FAIL: %s is missing\n' "$doc" >&2
    fail=1
    continue
  fi
  if ! head -15 "$doc" | grep -q "DO NOT DEPLOY"; then
    printf 'FAIL: %s is missing the DO NOT DEPLOY banner in its first 15 lines\n' "$doc" >&2
    fail=1
  fi
done

stale_patterns=(
  "tautological surrogates"
  "reverts on all inputs"
  "verifier accepts any proof bytes"
  "Stage 0 killswitch"
  "MicroNova"
  "Sonobe"
  "beta.20"
  "deferred to T4"
  "Seven open problems"
)

for doc in "${docs[@]}"; do
  [[ -f "$doc" ]] || continue
  for pat in "${stale_patterns[@]}"; do
    if grep -qF -- "$pat" "$doc"; then
      printf 'FAIL: %s contains stale-era wording: %q\n' "$doc" "$pat" >&2
      fail=1
    fi
  done
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi

printf 'PASS: no doc contradictions detected\n'
