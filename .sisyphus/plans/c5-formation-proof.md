# Plan: C5 Aggregate Public-Key Formation Proof

**Status**: PLAN
**Created**: 2026-06-04
**Parent plan**: `meta-plan-all-deferred.md` (Phase H, §H.2)
**Estimate**: ~2 weeks (design + implementation + tests + on-chain integration)

## Goal

Replace the `bytes32(0)` placeholder at `c5_proof_root` with a cryptographic proof that the aggregate public key (`pk_agg`) is correctly formed from the sum of individual participant public keys (`pk_agg = Σ pk_i`), with protection against rogue-key attacks.

## Current State

### The gap

- `crates/pvthfhe-types/src/verification_statement.rs:70` declares `pub c5_proof_root: [u8; 32]` but it is initialized to `bytes(0x80)` in the golden fixture (line 350) and defaulted to `[0u8; 32]` in all production paths.
- `crates/pvthfhe-aggregator/src/keygen/simulator.rs:348` calls `self.backend.aggregate_keygen(&shares)` and stores the result in `aggregate_pk` without producing any cryptographic proof.
- `contracts/src/PvtFheVerifier.sol:565` hardcodes `c5ProofRoot: bytes32(0)` in the on-chain verifier's statement reconstruction.
- `contracts/src/VerificationStatementV1.sol:25` declares the field but it is never populated with real data.

The verifier does not attempt to validate `c5_proof_root`. It is fail-closed: zero bytes are accepted without checking, and no attacker can make it "more" zero.

### What IS covered (NOT C5)

| Concern | What it means | Status | Plan |
|---------|---------------|--------|------|
| **PK BINDING (G4)** | Prove `aggregate_pk` is committed in `dkg_root` via Merkle path in DKG transcript | OPEN | `meta-plan-all-deferred.md` §B.2: ~3-4 days, ~7,200 constraints |
| **DKG polynomial verification** | Prove each dealer's shares are evaluations of a degree-t polynomial | DONE | `dkg-parity-check-proof.md` |
| **Per-party keygen correctness (C0)** | NIZK proving each participant's key is well-formed | DONE | Simulator generates keygen NIZK (line 415-417) |
| **Key commitment binding (H2)** | Commit-reveal binding of `pk_i_hash` to prevent last-minute key selection | DONE | `compute_round1_commitment` (simulator.rs:110-123) |

### What C5 requires (NOT covered)

C5 proves the arithmetic relation `pk_agg == Σ pk_i` over the FHE key space (BFV RLWE keys). This is NOT the same as proving `aggregate_pk` is in the DKG transcript (G4). A transcript can commit to any value; C5 proves that committed value IS the sum.

## Rogue-Key Attack Scenario

A malicious participant `M` observes honest participants publish `pk_1, pk_2, ..., pk_{n-1}`. Before publishing their own key, they compute:

```
X = a key whose secret key M knows
pk_M = X - Σ_{i≠M} pk_i
```

When the aggregator sums all keys: `pk_agg = (Σ_{i≠M} pk_i) + pk_M = X`

The adversary now knows the secret key for the aggregate, breaking the entire threshold scheme. Without C5, there is no cryptographic barrier to this attack.

### Protection mechanisms

Two standard approaches exist:

1. **Proof-of-Possession (PoP)**: Each participant proves knowledge of their secret key via a Schnorr-like sigma protocol over the BFV key space. This binds the public key to a known discrete log, preventing the attacker from computing `pk_M = X - Σ pk_i` without knowing `sk_M`.

2. **Key-registration model**: A trusted registrar validates keys before they enter the participant set. Simpler but introduces a trust assumption inconsistent with the project's malicious-security goals.

**Recommendation**: PoP approach. It preserves the malicious-security model and can be folded into the existing DKG ceremony with minimal disruption.

## Success Criteria

1. A C5 proof artifact is produced during keygen aggregation in `simulator.rs` and stored in the verification statement's `c5_proof_root` field (replacing `bytes32(0)`).
2. The on-chain verifier (`PvtFheVerifier.sol`) validates `c5ProofRoot` against the aggregated key and participant set.
3. The proof covers rogue-key protection: a participant who submits a key chosen to bias the aggregate after seeing other keys is rejected.
4. Positive test: honest n-party keygen produces a valid C5 proof that passes verification.
5. Negative tests: a manipulated aggregate key (one party's key biased, a key omitted, or a key duplicated) causes proof verification to fail.
6. The `c5_proof_root` field is no longer zero-initialized in production paths.

## Task Breakdown

### Task 1: Protocol design (design doc)
- [ ] Determine proof strategy: PoP-based aggregate sum proof vs. in-circuit sum verification
- [ ] Specify the C5 relation: `pk_agg == Σ pk_i` over the BFV RLWE key space
- [ ] Design rogue-key protection: each participant proves knowledge of `sk_i` corresponding to `pk_i`
- [ ] Decide proof format: native Rust proof with Poseidon commitment root or full Noir circuit folded via Nova
- [ ] Document design in `.sisyphus/design/c5-formation-proof.md`
- [ ] Cross-reference with G4 (PK BINDING) to avoid overlap

### Task 2: Native C5 proof generation (Rust)
- [ ] Create `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs`
- [ ] Implement `fn prove_pk_formation(pks: &[PublicKey], aggregate_pk: &PublicKey) -> C5Proof`
- [ ] Implement `fn verify_pk_formation(pks: &[PublicKey], aggregate_pk: &PublicKey, proof: &C5Proof) -> bool`
- [ ] Include PoP verification per participant
- [ ] Compute `c5_proof_root` as Poseidon hash of the proof bundle
- [ ] Wire into `simulator.rs::run()` at line 348, after `aggregate_keygen` call
- [ ] Test: `cargo test -p pvthfhe-aggregator c5_formation_proof`

### Task 3: Verification statement integration
- [ ] In `simulator.rs`, pass `c5_proof_root` into the verification statement construction (currently done in `full_pipeline.rs`)
- [ ] In `crates/pvthfhe-types/src/verification_statement.rs`, remove zero-initialization for `c5_proof_root` in production paths (golden fixture can remain for testing)
- [ ] In `crates/pvthfhe-aggregator/src/keygen/types.rs`, add `c5_proof_root: [u8; 32]` to `DkgTranscript` or `Round3Aggregate`
- [ ] Update `full_pipeline.rs` C5 verification section (lines 1149-1181) to use real proof instead of the current hash-only `PkAggregationStepCircuit`
- [ ] Test: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-types verification_statement`

### Task 4: On-chain verification
- [ ] In `contracts/src/PvtFheVerifier.sol`, replace `c5ProofRoot: bytes32(0)` at line 565 with a real input sourced from the verifier's public inputs
- [ ] Implement `_verifyC5ProofRoot(bytes32 c5ProofRoot, bytes32 aggregatePkHash, bytes32 participantSetHash)` 
- [ ] Wire the C5 proof root into the statement hash computation
- [ ] Test: `forge test --root contracts --match-contract C5FormationProof`

### Task 5: Adversarial tests
- [ ] Test: honest n-party keygen produces valid C5 proof (positive)
- [ ] Test: manipulated aggregate (one pk replaced with attacker-chosen value) fails verification
- [ ] Test: missing participant (one pk omitted from sum) fails verification
- [ ] Test: rogue-key scenario (attacker chooses pk after seeing honest keys) fails PoP check
- [ ] Test: duplicated key (same pk_i submitted twice) fails verification
- [ ] Test: zero-length or empty proof rejects with clear error
- [ ] Test: wrong participant set hash mismatches proof root

### Task 6: Pipeline integration + integration tests
- [ ] Full demo-e2e passes with real C5 proof
- [ ] `just demo-e2e 10 4 1` produces ACCEPT with nonzero `c5_proof_root`
- [ ] Adversarial e2e: injected rogue key causes REJECT
- [ ] Benchmark: measure proof generation time and proof size

## Acceptance Criteria

1. `grep -r "c5_proof_root" crates/pvthfhe-types/src/verification_statement.rs` no longer shows zero-initialization in production code paths (TDD: fail-first, then pass).
2. `cargo test -p pvthfhe-aggregator c5_formation_proof` passes all positive and negative tests.
3. `forge test --root contracts --match-contract C5FormationProof` passes all Solidity tests.
4. `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just demo-e2e 10 4 1` produces ACCEPT with nonzero `c5_proof_root`.
5. Adversarial test: a manipulated aggregate key causes REJECT.
6. The `docs/OPEN-PROBLEM-BLOCKERS.md §C5` entry is updated to reflect the new status.

## Out of Scope

- **PK BINDING (G4)**: Proving that `pk_agg` is committed in `dkg_root` via Merkle-path. This is covered by `meta-plan-all-deferred.md` §B.2. C5 complements G4: G4 binds the key to the transcript, C5 proves the bound key IS the sum. Both are needed.
- **DKG polynomial correctness**: `dkg-parity-check-proof.md` addresses dealer polynomial verification (are shares correct evaluations?). That is orthogonal.
- **Per-party keygen correctness (C0)**: The keygen NIZK proves each `pk_i` is well-formed. C5 proves the aggregate sum across all of them.
- **Noir circuit for C5**: If Task 1 determines a Noir circuit approach, the circuit implementation is in scope. The Nova IVC folding of that circuit uses the existing `NovaCompressor` infrastructure and is in scope for pipeline wiring, but deep Nova changes are out of scope.
- **Cyclo accumulator or C7 decryption correctness**: Separate open problems (A1, C7).

## Affected Source Files

| File | Lines | What changes |
|------|-------|-------------|
| `crates/pvthfhe-aggregator/src/keygen/simulator.rs` | 348 | Call `prove_pk_formation` after `aggregate_keygen` |
| `crates/pvthfhe-aggregator/src/keygen/types.rs` | 26-29, 32-40 | Add `c5_proof_root` to `Round3Aggregate`/`DkgTranscript` |
| `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs` | (new) | Proof generation and verification logic |
| `crates/pvthfhe-types/src/verification_statement.rs` | 70, 350 | Replace zero-init with real proof root |
| `crates/pvthfhe-cli/src/full_pipeline.rs` | 1149-1181 | Use real C5 proof in pipeline verification |
| `contracts/src/PvtFheVerifier.sol` | 553-565 | Replace `c5ProofRoot: bytes32(0)` with real input |
| `contracts/src/VerificationStatementV1.sol` | 25, 60 | Validation of nonzero proof root |
| `contracts/test/C5FormationProof.t.sol` | (new) | Solidity adversarial tests |
| `docs/OPEN-PROBLEM-BLOCKERS.md` | 49-63 | Update status after resolution |

## References

- Canonical problem: `docs/OPEN-PROBLEM-BLOCKERS.md` §C5 (lines 49-63)
- Meta-plan scope: `meta-plan-all-deferred.md` §H.2 (lines 272-277)
- Security analysis: `SECURITY.md` §C5 (lines 74-76)
- G4 PK BINDING (complementary, not conflicting): `meta-plan-all-deferred.md` §B.2 (lines 69-72)
- DKG polynomial verification (orthogonal): `dkg-parity-check-proof.md`
- Architecture overview: `ARCHITECTURE.md` line 108
- WARNING: `WARNING.md` line 5 (C5 as known gap)
- `soundness-budget-reconciliation.md` lines 93, 159 (C5 as unproven gap)
