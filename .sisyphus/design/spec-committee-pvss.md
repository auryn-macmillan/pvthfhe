# Committee-Based PVSS Specification

**Status**: draft  
**Paper**: Abraham, Bacho, Stern — ePrint 2026/1159, §4.2 (via ABLS25)  
**Implementation**: `crates/pvthfhe-pvss/src/avid.rs` (`committee_sample`)

## Overview

Committee-based PVSS reduces DKG communication from O(n²) to O(λn) by having each dealer send encrypted shares to only λ = max(128, t) committee members instead of all n parties.

## Protocol

1. **Committee Selection**: `committee_sample(seed, n, size)` → deterministic VRF-based selection using SHA-256.
   - `party_id = SHA256(seed || position) % n + 1` (no duplicates, 1-based).
   - Seed: `SHA256(session_id || epoch)` when on-chain, or session_id for offline testing.
2. **Dealer**: Only encrypts shares for committee members. Feature-gated behind `committee-pvss`.
3. **Aggregation**: Committee members forward transcripts; aggregator collects from committee.

## Security

- Committee size ≥ t ensures at least one honest member (probability).
- Deterministic from seed → publicly verifiable.
- prevrandao() binding for on-chain requests.

## Feature Gate

```toml
committee-pvss = []
```

Public API: `LatticePvssBfvAdapter::deal_committee(secret, recipient_pks, ctx, committee, rng)`.

## See Also

- `crates/pvthfhe-pvss/src/avid.rs` — `committee_sample`, `verify_committee_selection`
- `spec-avid.md` — Provable AVID protocol
