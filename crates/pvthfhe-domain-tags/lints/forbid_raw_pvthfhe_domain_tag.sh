#!/usr/bin/env bash
# R0.4 GATE: forbid raw `b"pvthfhe/..."` byte literals outside the canonical Tag enum.
# Replace any flagged literal with `pvthfhe_domain_tags::Tag::<Variant>.as_bytes()`.
# Add a new Tag variant in `crates/pvthfhe-domain-tags/src/lib.rs` if needed.
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "[forbid::raw_pvthfhe_domain_tag] ripgrep ('rg') is required" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

matches="$(rg --no-heading --no-line-number -o 'b"pvthfhe/[^"]*"' \
  --glob '!crates/pvthfhe-domain-tags/**' \
  --glob '!target/**' \
  --glob '!**/forbid_raw_pvthfhe_domain_tag.sh' \
  . || true)"

filtered="$(printf '%s\n' "$matches" | rg -v 'allow-raw-pvthfhe-domain-tag' || true)"

if [[ -n "${filtered// /}" && -n "$filtered" ]]; then
  echo "[forbid::raw_pvthfhe_domain_tag] offending raw byte literals found:" >&2
  printf '%s\n' "$filtered" >&2
  echo >&2
  echo "Replace with \`pvthfhe_domain_tags::Tag::<Variant>.as_bytes()\`. Add the variant to \`crates/pvthfhe-domain-tags/src/lib.rs\` if missing." >&2
  exit 1
fi

echo "[forbid::raw_pvthfhe_domain_tag] OK — no raw 'b\"pvthfhe/...\"' literals outside the canonical enum."
exit 0
