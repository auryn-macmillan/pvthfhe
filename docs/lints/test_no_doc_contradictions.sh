#!/usr/bin/env bash
# RED phase for R0.1: this test must fail on current main.
# GREEN phase will rename WARNING.txt -> WARNING.md and reconcile the claims.

set -euo pipefail

fail=0

docs=(
  "README.md"
  "ARCHITECTURE.md"
  "SECURITY.md"
  "WARNING.md"
)

terms=(
  "real-cryptography pipeline"
  "production-ready"
  "surrogate"
)

for doc in "${docs[@]}"; do
  if [[ ! -f "$doc" ]]; then
    printf 'FAIL: %s is missing (expected by R0.1 canonical-doc lint)\n' "$doc" >&2
    fail=1
    continue
  fi

  for term in "${terms[@]}"; do
    if matches=$(grep -nH -F -- "$term" "$doc" 2>/dev/null); then
      printf '%s\n' "$matches"
    fi
  done
done

if grep -nH -F -- "real-cryptography pipeline" README.md >/tmp/doclint_readme_pipeline.$$ 2>/dev/null; then
  if grep -nH -F -- "NOT production-ready" README.md >/tmp/doclint_readme_notprod.$$ 2>/dev/null; then
    printf 'FAIL: README.md has conflicting claims for real-cryptography pipeline: %s vs %s\n' \
      "$(tr '\n' ' ' < /tmp/doclint_readme_pipeline.$$ | sed 's/[[:space:]]*$//')" \
      "$(tr '\n' ' ' < /tmp/doclint_readme_notprod.$$ | sed 's/[[:space:]]*$//')" >&2
    fail=1
  fi
fi
rm -f /tmp/doclint_readme_pipeline.$$ /tmp/doclint_readme_notprod.$$ 

if grep -nH -F -- "production-ready" README.md ARCHITECTURE.md SECURITY.md >/tmp/doclint_prod.$$ 2>/dev/null; then
  if ! grep -nH -F -- "NOT production-ready" README.md ARCHITECTURE.md SECURITY.md >/tmp/doclint_notprod.$$ 2>/dev/null; then
    printf 'FAIL: positive production-ready claim found without an explicit NOT production-ready retraction\n' >&2
    cat /tmp/doclint_prod.$$ >&2
    fail=1
  fi
fi
rm -f /tmp/doclint_prod.$$ /tmp/doclint_notprod.$$ 

if grep -nH -F -- "surrogate" README.md ARCHITECTURE.md SECURITY.md >/tmp/doclint_surrogate.$$ 2>/dev/null; then
  if ! grep -nH -F -- "tautological surrogates" ARCHITECTURE.md >/tmp/doclint_taut.$$ 2>/dev/null; then
    printf 'FAIL: surrogate wording is not canonical across docs; expected explicit tautological-surrogate framing\n' >&2
    cat /tmp/doclint_surrogate.$$ >&2
    fail=1
  fi
fi
rm -f /tmp/doclint_surrogate.$$ /tmp/doclint_taut.$$ 

if [[ $fail -ne 0 ]]; then
  exit 1
fi

printf 'PASS: no doc contradictions detected\n'
