# Plan: Per-Node Simulation for Scaling Benchmarks

**Plan**: `per-node-scaling-simulation`
**Status**: DRAFT
**Created**: 2026-05-15
**Goal**: Create a simulation that measures wall time for a single party and the aggregator at arbitrary n and t, replacing the O(n²) demo simulation.

---

## Design

### Existing demo (what we have)
- Simulates ALL n parties on one machine
- setup_threshold: O(n²) Shamir shares generated sequentially
- NIZK verify: O(n²) per-pair verifications
- Total wall time: O(n²) — misleading for production scaling

### New per-node simulation
- Simulates ONE party: their keygen, their Shamir splits, their NIZK proofs, their verification
- Simulates the AGGREGATOR: compressor, aggregate_decrypt, C7
- Wall time: O(n) per party + O(t) for aggregator — reflects real deployment

### Architecture
```
just per-node n=1000 t=500

Output:
  per_node:
    keygen:        0.5s    (one key pair)
    shamir_split:  2.1s    (split own key into n-1 shares)  
    encrypt:      15.3s    (BFV encrypt each share under recipient's key)
    nizk_prove:    4.2s    (one Cyclo NIZK per recipient)
    nizk_verify:   1.2s    (verify t-1 proofs addressed to them)
    decrypt_own:   0.3s    (decrypt their own share)
    total:         23.6s    per party wall time

  aggregator:
    compressor:    4.1s    (fold ceil(n/10) accumulators via Nova)
    aggregate:     7.2s    (t-way NTT decryption)
    C7:           16.1s    (t Nova steps)
    total:         27.4s    aggregator wall time
```

### Phase 1: Per-node simulation structure

Extract the per-party work from `full_pipeline.rs` into a standalone measurement that:
1. Initializes a single party's state (not n parties)
2. Generates their key share
3. Splits into n-1 Shamir shares (measures per-share time, extrapolates)
4. Encrypts a sample of shares (measures per-share time, extrapolates)
5. Runs NIZK prove for a sample (measures per-proof time, extrapolates)
6. Runs NIZK verify for t-1 proofs (full, since this is O(t))
7. Decrypts their own share

### Phase 2: Aggregator simulation structure

Extract the aggregator work:
1. Compressor: initialize with ceil(n/batch_size) Nova steps, run folding
2. aggregate_decrypt: run with t shares
3. C7: run with t Nova steps

### Phase 3: Justfile + CLI integration

Add `just per-node` recipe that runs the simulation at given n and t.

---

## Implementation

| ID | Task | Files | Effort |
|----|------|-------|--------|
| P1 | Create `crates/pvthfhe-cli/src/bin/per_node.rs` — per-node simulation binary | `per_node.rs` | 2 days |
| P2 | Create `crates/pvthfhe-cli/src/bin/per_aggregator.rs` — aggregator simulation binary | `per_aggregator.rs` | 2 days |
| P3 | Add `just per-node` + `just aggregator` recipes | `Justfile` | 0.5 day |
| P4 | Run benchmarks: n=100,500,1000 with t=n/2 and report scaling | Manual | 1 day |

## Acceptance Criteria

- [ ] `just per-node n=1000 t=500` reports per-party wall time
- [ ] `just aggregator n=1000 t=500` reports aggregator wall time  
- [ ] Per-party time scales O(n) (linear), not O(n²)
- [ ] Aggregator time scales O(t) (linear in threshold)
- [ ] Total projected time matches (per_node × n + aggregator) ≈ wall time at smaller n

## Estimated Effort

~5-6 days. Extracting per-party simulation from the full pipeline is the main effort.
