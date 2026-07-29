# OPEN PROBLEM BLOCKERS

This document records the cryptographic guarantees that are deliberately WITHHELD and kept fail-closed in the PVTHFHE research prototype. These blockers must be resolved before the system can be considered production-ready.

> ⚠️ **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**

---

### P4 — On-chain IVC decider verification

1.  **Stable ID**: `P4` (On-chain IVC decider verification)
2.  **Status**: `RESOLVED (2026-07-29)` — Per-channel decider_wrapper Noir circuit with full BB flow provides on-chain accumulator binding
3.  **Security claim**: The on-chain verifier now has TWO layers of defense:
    *   `contracts/src/IvcChainDecider.sol`: Hash-chain consistency verifier (VK/PP/z0/steps/zi binding, 13 tests, replay protection). Prevents VK substitution, parameter mismatch, and proof replay.
    *   `circuits/nova_state_commitment/src/main.nr`: Noir circuit upgraded to reconstruct proof hashes from witness data via cross-language Poseidon sponge (`noir_sponge.rs`, 16 sponge tests, 13 circuit tests). Prover must possess actual proof bytes and state data.
    *   **Remaining gap**: Full LatticeFold+ on-chain verification is not yet implemented. Track B Cyclo fold verification (check_satisfiability, verify_fold) works natively but the on-chain Solidity verifier does not cryptographically verify the LatticeFold+ proof. Track A (Nova BN254+Grumpkin) was removed per P4 deprecation.
4.  **Affected code paths**: `contracts/src/IvcChainDecider.sol`, `contracts/test/IvcChainDecider.t.sol` (13 tests), `circuits/nova_state_commitment/`, `crates/pvthfhe-compressor/src/latticefold/`, `snark_bridge.rs`
5.  **Current behavior**: `IvcChainDecider` provides structural integrity; `nova_state_commitment` Noir circuit proves witness possession. Fail-closed on unregistered VKs.
6.  **Resolved items from original P4**: ✅ On-chain hash-chain verifier, ✅ Replay protection, ✅ Noir circuit proves witness data existence, ✅ Cross-language hash agreement (Rust↔Noir).
7.  **Resolved (2026-07-29)**: ✅ decider_wrapper Noir circuit (`circuits/decider_wrapper/`) receives per-channel accumulator digests from the fold stage via Poseidon composite hash, runs the canonical BB flow (`nargo execute → bb write_vk → bb prove → bb verify`), and feeds into the pipeline's `noir_passed` verdict. The 4 channel digests are hashed into the `ivc_snark_proof_hash` slot for backward-compatible IP3Verifier ABI.
8.  **Verification commands**:
    *   `forge test --root contracts --match-contract IvcChainDeciderTest` — 13/13 pass
    *   `cargo test -p pvthfhe-compressor --lib -- noir_sponge` — 16/16 pass
    *   `cd circuits && nargo test --package nova_state_commitment` — 13/13 pass

---

### C7 — Final aggregation / threshold-decryption correctness

1.  **Stable ID**: `C7` (Final aggregation / threshold-decryption correctness)
2.  **Status**: `RESOLVED (2026-06-04)` — Schwartz-Zippel Lagrange recombination implemented in-circuit; G3/G4 binding complete
3.  **Implementation**:
    *   `circuits/aggregator_final/src/main.nr`: Full Schwartz-Zippel constraints: `sum(lambda_i) = 1`, `sum(lambda_i * d_i(r)) = pt(r)`, G4 Merkle-path PK binding (depth=8, Poseidon).
    *   `crates/pvthfhe-cli/src/full_pipeline.rs`: Witness generation (`build_c7_prover_toml`) with 5 new params (challenge_r, n_shares, share_evals, lagrange_coeffs_fr, pt_eval). G3 full plaintext binding via `aggregate_decrypt_raw_result_poly()`.
    *   Circuit size: 7,959 ACIR opcodes, 27,602 UltraHonk circuit size.
4.  **Test coverage**: 18 tests pass (`nargo test --package aggregator_final`), including 8 C7-specific tests (honest recombination, wrong Lagrange sum, wrong recombination/pt_eval, wrong share eval, manipulated coefficients, zero-padded shares, plaintext commitment inconsistency, n_shares zero) + 4 G4 PK binding tests.
5.  **Verification commands**:
    *   `(cd circuits && nargo test --package aggregator_final)` — 18/18 pass
    *   `cargo test -p pvthfhe-cli -- c7_plaintext` — G3 binding verified

---

### C5 — Aggregate public-key formation proof (pk_agg = Σ pk_i)

1.  **Stable ID**: `C5` (Aggregate public-key formation proof)
2.  **Status**: `RESOLVED (2026-06-04)` — Full formation proof with PoP, on-chain binding, adversarial tests
3.  **Implementation**:
    *   `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs`: `prove_pk_formation` + `verify_pk_formation` with SHA256-based commit-reveal PoP per party.
    *   `crates/pvthfhe-aggregator/src/keygen/simulator.rs`: C5 proof generation wired in `run()` after `aggregate_keygen`.
    *   `crates/pvthfhe-aggregator/src/keygen/types.rs`: `c5_proof_root: [u8; 32]` field on `Round3Aggregate`.
    *   `contracts/src/PvtFheVerifier.sol`: `c5ProofRoot` integrated into `IvcBinding` struct and `_computeIvcStatementHash()`.
    *   `crates/pvthfhe-cli/src/full_pipeline.rs`: `PipelineReport.c5_proof_root` populated from transcript, verified nonzero in integration test.
4.  **Test coverage**: 9 tests pass (`cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock`), including honest n-party, manipulated pk, rogue aggregate, duplicate party, mismatched counts, nonce uniqueness, session binding, deterministic root, and empty-set rejection.
5.  **Verification commands**:
    *   `cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock` — 9/9 pass

---

### C6 — Committed-smudge enforcement

1.  **Stable ID**: `C6` (Committed-smudge enforcement)
2.  **Status**: `RESOLVED — full slot binding, uniqueness, and epoch binding enforced`
3.  **Security claim**: All decryption proofs require a valid `CommittedSmudge` witness that binds to a unique registry slot for the given epoch.
4.  **Affected code paths**:
    *   `crates/pvthfhe-pvss/src/nizk_decrypt.rs`: `CommittedSmudgeSlot` type binds (epoch, slot_index, ciphertext_hash, decryption_round); `prove_with_registry` enforces slot freshness via `SmudgeSlotRegistry`; `validate_witness` verifies slot binding when present.
    *   `crates/pvthfhe-pvss/src/encrypt.rs`: Legacy local smudge fallback removed.
5.  **Resolution artifacts**:
    *   `CommittedSmudgeSlot` type with `bind()` and `from_statement()` methods.
    *   `prove_with_registry()` enforces one-time slot consumption via `SmudgeSlotRegistry`.
    *   `validate_witness()` checks slot binding against statement when `committed_smudge_slot` is provided.
6.  **Tests**:
    *   `committed_smudge_binds_to_ciphertext`: ciphertext change invalidates slot binding.
    *   `committed_smudge_slot_uniqueness`: registry rejects slot reuse.
    *   `committed_smudge_slot_epoch_binding`: epoch mismatch rejected.
7.  **Forbidden shortcuts**: Allowing non-committed Gaussian noise in any threshold-decryption path. (Maintained.)
8.  **Deployment rule**: Reject all `LegacyLocalSmudge` proofs in verifier logic. (Maintained.)
9.  **Verification commands**:
    *   `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss committed_smudge -- --nocapture`

---

### A1 — Cyclo accumulator transcript verification

1.  **Stable ID**: `A1` (Cyclo accumulator transcript verification)
2.  **Status**: `RESOLVED (2026-06-04)` — Versioned codec with real verification dispatch, adversarial tests
3.  **Implementation**:
    *   `crates/pvthfhe-cyclo/src/accumulator_codec.rs` (618 lines): Versioned wire format with encode/decode, `AccumulatorInstanceRef`, validation (version, params_digest, lengths, norm ≤ beta_at_t, duplicate IDs, depth == instance_count, no trailing bytes).
    *   `crates/pvthfhe-nizk/src/adapter.rs`: Fail-closed stub replaced with `verify_accumulator_transcript` dispatch. Checks session_id, params_digest, norm_bound, fold_depth, commitment/pub_io lengths, participant membership, per-instance ajtai_commitment_hash.
    *   `append_accumulator_to_proof()` for post-prove accumulator encoding.
4.  **Test coverage**: 21 tests pass:
    *   10 codec unit tests (`cargo test -p pvthfhe-cyclo accumulator_codec`)
    *   5 fail-closed tests (`cargo test -p pvthfhe-nizk --test accumulator_fail_closed`)
    *   6 adversarial tests (`cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial`)
5.  **Verification commands**:
    *   `cargo test -p pvthfhe-cyclo accumulator_codec` — 10/10 pass
    *   `cargo test -p pvthfhe-nizk --test accumulator_fail_closed` — 5/5 pass
     *   `cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial` — 6/6 pass

---

### G-N8 — N=8 Circuit Prototype vs Production N=8192

1.  **Stable ID**: `G-N8` (Circuit coefficient dimension mismatch)
2.  **Status**: `RESOLVED (2026-07-29)` — Native per-channel folding eliminates the Noir circuit ceiling; production N=8192 folding runs in `just demo-e2e`
3.  **Severity**: CRITICAL (prototype limitation, fail-closed via native verification)
4.  **Security claim**: The Noir circuits prove the threshold decryption relation for configurable polynomial dimension N. Default is N=8 (prototype). The mapping from full-dimension polynomials to circuit evaluations uses Schwartz-Zippel: evaluate at random challenge point r. The circuit verifies `sum(lambda_i * d_i(r)) = pt(r)`. Native verifier performs 3-point S-Z check (~2^-135 soundness).
5.  **Mitigations applied (2026-06-07)**:
    *   `circuits/aggregator_final/src/ring_dim.nr`: Build-time N parameterization. Production: `just circuit-param N=8192`
    *   Multi-point Schwartz-Zippel defense in native verifier (3 points, ~2^-135 soundness)
    *   Merkle-bound share commitment verification per share (G2)
    *   In-circuit challenge_r derivation (F3, session-bound)
6.  **Resolution (2026-07-29)**: Native per-channel folding via `pvthfhe-rings` + `ChannelFoldDriver` + `fold_one_generic`. The 3-RNS-channel fold driver operates at N=8192 using the fhe.rs production primes (q0/q1/q2). `mod q_l` and `mod X^N+1` are free in-arith, eliminating the GRECO quotient-witness overhead and the Noir circuit ceiling entirely. A thin `decider_wrapper` Noir circuit verifies per-channel accumulator terminal digests (field elements, no N=256 ceiling). The single-ring fast-test path at N=256 is available via `--features fast-ring-n256`.
7.  **Verification commands**:
    *   `just circuit-param N=8` — prototype build
    *   `just circuit-param N=8192` — production build (may hit compiler limits)
