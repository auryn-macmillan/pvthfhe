# G.6-G.8 — Noir Circuit Participant Constraints

**Status**: READY (Path A confirmed, Phase 2 infrastructure built)
**File**: `circuits/aggregator_final/src/main.nr`
**Estimate**: ~1 hour

## Current State

| Item | Status |
|------|--------|
| G.6 — combined_share_hash binding | ✓ Done (line 135: `computed == combined_share_hash`) |
| G.7 — committee_party_ids ↔ participant_set_hash | ✗ Missing |
| G.8 — threshold enforcement | ✗ Missing |

## Tasks

### Task G7: Bind committee_party_ids to participant_set_hash
- [x] After party_id non-zero asserts (line 100), compute Poseidon hash of `committee_party_ids[0..n]`
- [x] Constrain `computed_ps_hash == participant_set_hash`
- [x] Verify: `nargo test --package aggregator_final` — all pass

### Task G8: Enforce threshold
- [x] Count non-zero `participant_shares[i]` for i < n
- [x] Assert `non_zero_count == threshold + 1`
- [x] Verify: `nargo test --package aggregator_final` — all pass
