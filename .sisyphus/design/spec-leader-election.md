# Weak Leader Election Specification

**Status**: draft  
**Paper**: Abraham, Bacho, Stern — ePrint 2026/1159, §7  
**Implementation**: `crates/pvthfhe-aggregator/src/leader_election.rs`

## Overview

Weak Leader Election selects one honest aggregator with constant probability (α ≥ 1/3). The protocol is adapted for pvthfhe's synchronous setting using deterministic hash-based ranks.

## Protocol

1. **Seed**: `leader_seed = SHA256(prevrandao || epoch || participant_set_hash)` when on-chain, or session_id for offline testing.
2. **Rank Generation**: `rank_i = SHA256("pvthfhe-leader-election/v1:rank:" || seed || party_id)` — non-interactive, publicly verifiable.
3. **Leader**: `selected = argmax_i(rank_i)`.

## Security

- Deterministic given seed — no interaction, no equivocation risk
- prevrandao() binding for on-chain requests
- Retroactively verifiable: anyone can recompute ranks from the seed
- Fallback to permissionless mode if leader fails

## Integration

- Called before decryption aggregation
- Feature-gated behind `--elect-leader` flag in demo-e2e
- Leader identity stored in DkgTranscript

## See Also

- `crates/pvthfhe-aggregator/src/leader_election.rs` — implementation
- `docs/interfold-threat-model.md` — aggregator threat model
