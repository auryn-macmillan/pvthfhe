# P1 Stack Decision Memo

## Decision Summary

This memo freezes **SLAP** as the primary P1 implementation stack, with **Greyhound** as the research fallback and **Rust-in-zkVM** as the delivery fallback. The choice follows the weighted scorecard (`SLAP 3.93 > Greyhound 3.81 > Rust-in-zkVM 3.49`) and the frozen `LatticeNizk` interface: the selected stack must prove the exact `(session_id, participant_id, pvss_commitment_hash, q, N, B_e, c, d_i)` relation without leaking backend-specific proof plumbing into callers.

The quantitative bottleneck is not only prover speed; it is whether the verifier object remains recursion-friendly for P2 folding while still preserving a post-quantum soundness story. That weighting is why SLAP beats stronger wrapper-based verifier profiles despite higher implementation novelty, and why Greyhound stays ahead of zkVM delivery stacks as the first promotion candidate if verifier-shape constraints dominate.

## Evaluation Criteria

The stack comparison uses the frozen P1 metrics required by the task and the scorecard:

- **Prover time at n=1024**
- **Proof size (bytes)**
- **Verifier time**
- **Recursion fit for P2 folding**
- **PQ posture**
- **License**
- **Audit surface**

Quantitative estimates are grounded in the P1 prior-art matrix and local repository baselines:

- `bench/results/rlwe-relation-{512,2048,8192}.json` gives a checked-in surrogate relation baseline of ~29.3–30.8 ms prover, ~6.6–6.8 ms verifier, and 14,656-byte proofs for coefficient-wise toy circuits; these numbers are **not** treated as final P1 measurements, but they anchor the lower bound for wrapper systems that reuse a small Rust/constraint checker.
- `bench/results/scaling-{128,512,1024}.json` gives the current recursive aggregation baseline: 1.57 ms / 44.24 ms / 196.02 ms aggregator wall-clock and 2,752 / 10,944 / 21,856 byte final succinct proofs, showing the verifier-object size regime P2/P3 want to consume.
- `bench/results/backend-compare-2026-05-02.json` records one NTT-domain polynomial multiplication at ~15.29 ms for `N=4096`, giving a sanity anchor for native lattice arithmetic costs inside a prover.

## Comparative Score Table

| Stack | n=1024 prover time | Proof size (bytes) | Verifier time | Recursion fit for P2 folding | PQ posture | License | Audit surface |
| --- | ---: | ---: | ---: | --- | --- | --- | --- |
| SLAP | ~2.5-4.0 s | ~120,000-220,000 | ~18-40 ms | Medium-high | Yes | Research code / unclear | Medium: one native lattice prover/verifier + FS transcript |
| Greyhound | ~3.5-6.0 s | ~180,000-420,000 | ~4-12 ms | High | Yes | Research code / unclear | High: transparent IOP, hash layer, low-degree plumbing |
| Rust-in-zkVM | ~300-1200 s | ~10,000-120,000 | ~1-8 ms | High | Partial / mixed | Apache-2.0/MIT style | High: VM, executor, proving system, guest checker |
| Hybrid zkVM | ~30-90 s | ~8,000-40,000 | ~1-5 ms | High | Partial / mixed | Apache-2.0/MIT style | Very high: SHA-256 gadget path + lattice proof bridge + outer proof |

### Metric notes

- **SLAP** inherits the best scorecard balance because it is the closest native fit to ciphertext/share/plaintext consistency while staying fully lattice-native and compatible with the `LatticeNizk` adapter boundary.
- **Greyhound** improves verifier shape enough to stay the first research fallback, but it pays for that with thinner implementation maturity and a broader transparent-proof audit surface.
- **Rust-in-zkVM** is intentionally slower by one to two orders of magnitude on prover time than the native stacks, but its verifier profile is excellent and it remains the explicit "do not get blocked" path.
- **Hybrid zkVM** reflects the novelty memo's aggressive bet: a bridged proof that keeps SHA-256 checking in a zkVM/SNARK-friendly wrapper while preserving a lattice sub-proof for the RLWE relation.

## Bench Projections

The table below projects order-of-magnitude costs at `n in {128, 512, 1024}`. Scaling is derived from the scorecard ranking, the prior-art matrix's qualitative size classes, and the checked-in local baselines above. Wrapper-based systems are anchored against the existing ~196 ms recursive aggregator and ~14.7 KB surrogate relation proof, then inflated to account for real RLWE witness checking and transcript binding. Native lattice systems are anchored against the ~15.29 ms NTT multiply baseline and prior-art claims that proofs stay in the tens-to-hundreds-of-KB regime rather than SNARK-succinct.

| Stack | n=128 prover (ms) | n=128 proof bytes | n=128 verifier (ms) | n=512 prover (ms) | n=512 proof bytes | n=512 verifier (ms) | n=1024 prover (ms) | n=1024 proof bytes | n=1024 verifier (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SLAP | 320 | 48,000 | 9 | 1,400 | 92,000 | 16 | 2,800 | 168,000 | 28 |
| Greyhound | 410 | 72,000 | 3 | 1,850 | 180,000 | 7 | 4,200 | 320,000 | 11 |
| Rust-in-zkVM | 38,000 | 12,000 | 1.5 | 150,000 | 28,000 | 3 | 600,000 | 64,000 | 6 |
| Hybrid zkVM | 4,500 | 8,000 | 1.2 | 16,000 | 16,000 | 2.4 | 42,000 | 28,000 | 4.2 |

### Projection rationale

- **SLAP:** uses the scorecard's best direct-fit profile and the prior-art note that SLAP should land in the low-hundreds-of-KB regime for medium instances. The prover projection assumes roughly dozens to low-hundreds of NTT-class operations plus transcript work, which is consistent with moving from a ~15 ms primitive operation to a multi-second full proof at `n=1024`.
- **Greyhound:** verifier is projected below SLAP because the prior-art matrix marks it as hash-heavy and polylog-ish for verification, but proof size is larger because the same matrix places it in the tens-of-KB to low-MB transparent-argument bucket.
- **Rust-in-zkVM:** the prior-art matrix already gives a realistic band of 5–20 minutes for a Rust RLWE/share verifier; the `n=1024` projection freezes the middle of that band rather than the optimistic edge.
- **Hybrid zkVM:** faster than Rust-in-zkVM because only the SHA-256/transcript bridge and compact verifier object live in the wrapper layer, but still materially slower than native lattice stacks because it composes two proof domains.

## Primary Decision

Freeze **SLAP** as the primary P1 stack. It is the highest-scoring option in the scorecard and the best direct fit to the frozen `LatticeNizk` trait because it can express the exact decrypt-share relation and bounded-error checks without abandoning a lattice-native proof story.

SLAP also keeps the post-quantum security posture clean while preserving a verifier object that is still plausible for P2 folding consumption. Greyhound has a better recursion profile in theory, but SLAP requires less transparent-proof engineering novelty for the same frozen interface and therefore gives the best balance of feasibility versus downstream verifier constraints.

## Fallback Decision

Freeze **Greyhound** as the first fallback and **Rust-in-zkVM** as the delivery fallback. Greyhound is the immediate promotion candidate if SLAP's verifier object or transcript size turns out too awkward for P2 folding, because it gives the best native-lattice recursion profile among the shortlisted candidates.

Freeze **Rust-in-zkVM** as the last-resort fallback because the project explicitly accepts it as the "worst case" path when proving efficiency would otherwise block delivery. It is not the preferred research direction, but it is the cleanest guarantee that the frozen `LatticeNizk` semantics can still be implemented behind one adapter boundary even if native lattice constants disappoint.

## Recursion Compatibility

### SLAP

- Compatible with the frozen `NizkProof` metadata contract because it can publish deterministic proof bytes plus `constraint_estimate` and `proof_size_bytes` without exposing backend internals.
- Recursion fit is **acceptable but not ideal**: the verifier is still algebra-heavy, yet substantially lighter than classic lattice Σ-protocol baselines.

### Greyhound

- Best native candidate for P2 folding because the verifier is hash/IOP-oriented and the prior-art matrix rates it as the strongest transparent/recursion-friendly lattice direction.
- Main risk is engineering maturity rather than interface mismatch: it still satisfies the frozen statement/witness/proof boundary.

### Rust-in-zkVM / Hybrid zkVM

- Both wrapper options produce verifier objects that are naturally recursion-friendly for P2, but only at the cost of giving up a fully lattice-native base proof.
- They remain semantically compatible with `LatticeNizk` as long as the adapter preserves the same public statement encoding and deterministic proof metadata.

## Pivot Triggers

- **SLAP → Greyhound** if SLAP adaptation to the joint SHA-256-plus-RLWE statement pushes `n=1024` verifier time materially above the ~40 ms budget or forces a verifier object that P2 cannot fold cleanly.
- **SLAP / Greyhound → Rust-in-zkVM** if native-lattice implementations cannot meet schedule or confidence requirements, even after relaxing prover-speed expectations.
- **Any native path → Hybrid zkVM** only if the novelty memo's bridge strategy looks sound and produces a clearly better recursion object than plain Rust-in-zkVM without exceeding the zkVM proving budget.

## Risk Register

- **Joint transcript risk:** the hardest unsolved engineering step remains binding the inherited SHA-256 commitment to the lattice relation under one Fiat-Shamir transcript.
- **Recursion-object risk:** P2 cares more about verifier shape than raw proving speed, so a fast but algebra-heavy verifier can still fail the design goal.
- **License / ecosystem risk:** the native lattice candidates remain research-code heavy with unclear packaging and review depth; wrapper stacks win on ecosystem maturity but lose on PQ purity.

## Final Freeze

- **Primary:** SLAP
- **Fallback:** Greyhound
- **Delivery fallback:** Rust-in-zkVM
