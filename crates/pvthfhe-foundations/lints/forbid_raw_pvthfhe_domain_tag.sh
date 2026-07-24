#!/usr/bin/env bash
# R0.4 GATE: forbid raw pvthfhe byte-string domain literals outside the canonical Tag enum.
# Replace any flagged literal with `pvthfhe_foundations::domain_tags::Tag::<Variant>.as_bytes()`.
# Add a new Tag variant in `crates/pvthfhe-foundations/src/domain_tags.rs` if needed.
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "[forbid::raw_pvthfhe_domain_tag] ripgrep ('rg') is required" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

# The search pattern is assembled by quoting concatenation so this script's own
# text does not contain the literal it greps for (the no_inline_domains test
# scans every file under crates/, including this one).
PAT='b"pvthf''he/[^"]*"'

matches="$(rg --no-heading --no-line-number -o "$PAT" \
  --glob '!crates/pvthfhe-foundations/src/domain_tags.rs' \
  --glob '!crates/pvthfhe-foundations/tests/exhaustive.rs' \
  --glob '!target/**' \
  --glob '!**/forbid_raw_pvthfhe_domain_tag.sh' \
  . || true)"

filtered="$(printf '%s\n' "$matches" | rg -v 'allow-raw-pvthfhe-domain-tag' || true)"

if [[ -n "${filtered// /}" && -n "$filtered" ]]; then
  echo "[forbid::raw_pvthfhe_domain_tag] offending raw byte literals found:" >&2
  printf '%s\n' "$filtered" >&2
  echo >&2
  echo "Replace with \`pvthfhe_foundations::domain_tags::Tag::<Variant>.as_bytes()\`. Add the variant to \`crates/pvthfhe-foundations/src/domain_tags.rs\` if missing." >&2
  exit 1
fi

echo "[forbid::raw_pvthfhe_domain_tag] OK — no raw pvthfhe byte-tag literals outside the canonical enum."
exit 0
