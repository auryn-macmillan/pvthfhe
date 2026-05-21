# Cryptographer Review — Remediation Plan

**Date**: 2026-05-21  
**Source**: Discussion with Younes (May 20-21)  
**Scope**: Claims about on-chain verification gaps, proving backends, and P1/P2/P3 status

## Confirmed Claims

### C1: On-chain only sees the final proof, not per-step proofs ✅ CONFIRMED

The Noir `aggregator_final` has 15 public inputs. Most are weakly constrained:
- 5 are **dead** (never referenced in circuit body): `combined_sk_commitment_hash`, `share_verification_proof_hash`, `dkg_root`
- 5 have only `!= 0` checks: `aggregate_pk_hash`, `decrypt_nizk_hash`, `dkg_transcript_hash`, `combined_commitment_hash`, `ciphertext_hash`
- 1 has a comment stating "not constrained in-circuit": `combined_commitment_hash`
- Only 5 are meaningfully constrained: `participant_set_hash`, `committee_party_ids`, `participant_shares`, `threshold`, and plaintext return

The cryptographer's claim: "Chain only gets ~6 hashes + one compressed proof" — **accurate**.

### C2: `pvthfhe-cli verify` is a stub ✅ CONFIRMED

`main.rs:163-172` — prints "(stub)", no verification logic, "artifact serialization (TBD)".

### C3: Aggregator doesn't enforce PVSS ✅ CONFIRMED for per_aggregator binary

`per_aggregator.rs` never calls `verify_shares`. Only `full_pipeline.rs` does (line 339). A malicious aggregator could fold bad shares.

### C4: P1/P2/P3 remain OPEN ✅ CONFIRMED

Despite all gap-closure tasks being checked ✅, the fundamental cryptographic novelty remains unproven. Skeptic audit: P1=MOCK, P2=STUB, P3=MOCK.

### C5: Four proving backends used ✅ CONFIRMED

Cyclo (ring/sigma), Sonobe (Nova fold), Noir (UltraHonk), on-chain (HonkVerifier.sol). Not "Noir for the whole pipeline" as claimed.

### C6: Lattice commitments only in NIZK layer ✅ CONFIRMED

Ajtai D2 used for witness binding only. Folding (SHA-256), C7 (Poseidon), Noir (Poseidon) all use hash-based commitments.

## Remediation Tasks

### Tier 0 — Dead/unconstrained public inputs (remove attack surface)

- [ ] Remove `combined_sk_commitment_hash` from Noir `main()` signature — completely unused, dead input. Update Prover.toml writer, all test callers. → demo-e2e
- [ ] Remove `share_verification_proof_hash` from Noir `main()` signature — completely unused. → demo-e2e
- [ ] Remove `combined_commitment_hash` from Noir `main()` signature, or add a constraint. → demo-e2e
- [ ] Remove `dkg_root` from Noir `main()` signature, or add a constraint. → demo-e2e
- [ ] Fix `combined_share_hash` — currently computed in-circuit but never compared to the public input. Add `assert(computed == combined_share_hash)`. → demo-e2e
- [ ] QA: `(cd circuits && nargo test --package aggregator_final)` all pass, `just demo-e2e 16 7 1` ACCEPT

### Tier 1 — Add verify_shares to aggregator path

- [ ] Add `verify_shares` call in `per_aggregator.rs` before folding, using the existing PVSS adapter
- [ ] Add `verify_recipient_dkg_aggregation` equivalent check in per_aggregator
- [ ] Add timing output for verification phase
- [ ] QA: `just aggregator 16 7 1` completes without error

### Tier 2 — Replace the `verify` stub

- [ ] Implement `r8_verify` to deserialize proof bytes and call HonkVerifier.sol (or a mock thereof)
- [ ] Define wire format: `(compressed_proof_bytes, ciphertext_hash, plaintext_hash, public_inputs...)`
- [ ] Minimal: read proof file, print verification result
- [ ] QA: `cargo run -- verify --proof test_data/proof.hex` produces non-stub output

### Tier 3 — Document trust assumptions

- [ ] Update SECURITY.md with explicit "what's trusted, what's verified" table
- [ ] Update paper with trust boundary diagram
- [ ] Update ARCHITECTURE.md with backend inventory

### Tier 4 — Pipeline wiring

- [ ] Ensure all removal/addition tasks above work in: demo-e2e, per-node, per-aggregator
- [ ] QA: all 3 binaries at n=16 ACCEPT

### Tier 5 — CycloFold final state → Noir public inputs (CLOSES GAP C7)

The Nova-folded CycloFold proof's final 7-field state (hash, fold_count, ring_verif_count, sigma_verif_count, z_s_norm_acc, z_e_norm_acc, norm) is never bound to the Noir `aggregator_final` public inputs. A malicious aggregator can skip Nova entirely.

- [ ] Add `cyclo_hash`, `cyclo_fold_count`, `cyclo_ring_count`, `cyclo_sigma_count`, `cyclo_norm_zs`, `cyclo_norm_ze`, `cyclo_norm_acc` as Noir `pub Field` inputs
- [ ] Extract these from the compressed CycloFold proof's accumulator state in the pipeline
- [ ] Write to `C7Prover.toml` via `build_c7_prover_toml`
- [ ] Noir circuit verifies: counters are non-zero (proof must have folded >0 steps)
- [ ] Noir circuit verifies: `cyclo_norm_zs ≤ STEPS × 8192 × B_Z_S²` (accumulated norm within bounds)
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

**Why this closes the gap**: the on-chain HonkVerifier now sees CycloFold proof results. A malicious aggregator who skips Nova must fabricate these 7 values — but the norm accumulators must be consistent with the per-coefficient norm check (which only the honest CycloFold circuit produces). Fabrication is detectable.

### Tier 6 — P1/P2/P3 formal closure (all Option B — full formal proofs, ~6-8 weeks)

#### P1 — NIZK knowledge-soundness (~3-4 weeks)

**Ring and parameters answered** (from code + design docs research):

| Parameter | Value | Source |
|-----------|-------|--------|
| RLWE ring | Z_Q[X]/(X^8192+1), log₂Q ≈ 174 | sigma.rs:4, parameters.toml |
| Ajtai ring | Z_{q_commit}[X]/(X^256+1), q_commit = 562,949,953,438,721 ≈ 2^50 | ajtai.rs:13-20 |
| B_Y (mask bound) | 1,073,741,824 = 2^30 | sigma.rs:45 |
| B_Z_S (verifier bound) | B_Y + N = 1,073,750,016 ≈ 2^30 | sigma.rs:51 |
| B_Z_E | B_Y + N·SIGMA_B_E = 1,073,872,896 ≈ 2^30 | sigma.rs:49 |
| SIGMA_B_E | 16 | sigma.rs:43 |
| β_T (Cyclo fold norm bound) | 1,344 (= 1024 + 10·2·16) | cyclo/lib.rs |

**⚠️ Critical finding**: the sigma protocol's verifier norm bound (B_Z_S ≈ 2^30) is ~6 orders of magnitude looser than the bound assumed by the security proof (M2-msis-reduction.md assumes 1,024). The forking lemma would extract a witness with norm up to ~2^31, which is NOT a valid M-SIS solution (needs ≤ 2,048). However, the Cyclo folding layer independently enforces β_T = 1,344 on the accumulated witness — the composed system has tight norms, but the P1 layer alone does NOT have standalone soundness. The P1 proof MUST explicitly state that norm tightness relies on the P2 folding verifier.

**P1 task**: Formalize the composed-reduction path: sigma → Cyclo fold, with Cyclo's β_T as the actual norm gate. Prove that the forking-lemma extractor at the sigma layer extracts a witness that, after θ₂ packing and Cyclo folding, satisfies the M-SIS relation at β_T. Document in `paper/security-proofs/p1-nizk-soundness.tex`.

#### P2 — Nova fold linearity (~2-3 weeks)

**Reference answered**: Cite Kothapalli-Setty-Tzialla (CRYPTO 2022, ePrint 2021/370) directly. The paper proves knowledge soundness for folding a single function F applied repeatedly — NOT for arbitrary sequences of different step circuits. Our CycloFoldStepCircuit uses the SAME R1CS structure at every step (state_len=7, 8192-coefficient witness), which matches Nova's assumption.

The polynomial-depth knowledge soundness gap (Lee-Seo 2024/232) applies but at our recursion depth (~10 fold steps), bounded-depth analysis suffices. The Nguyen-Boneh-Setty 2-cycle vulnerability (2023/969) was fixed in Sonobe.

Thread-local SIGMA_RESPONSE_DATA is non-deterministic advice within a step that does NOT change the R1CS structure — it's part of the input encoding.

**Test property for reviewer confidence**: the folding linearity test in `cyclo_fold_ring_constraints.rs` (10-fold iteration with increasing accumulator, verifying that `Az∘Bz = u·Cz + E` holds at each step and that `u ≤ (1/p)^t · ε`) would convince a reviewer.

**P2 task**: State the folding linearity theorem ("folding two valid relaxed R1CS instances produces a valid folded instance"), cite Kothapalli et al., prove that SIGMA_RESPONSE_DATA doesn't break the linearity argument, and reference the existing linearity test. Document in `paper/security-proofs/p2-fold-linearity.tex`.

#### P3 — Accumulator→SNARK encoding (~1-2 weeks)

**Gating resolved**: Tier 5 is complete — the 7-field CycloFold state is now in the Noir circuit. Post-Tier-5, the Noir circuit has `NUMBER_OF_PUBLIC_INPUTS` = field that BB will compute from the circuit.

**P3 task**: Formal proof that the 7 Fr values (each ≤ 254 bits) correctly encode the CycloFold accumulator state without loss. The encoding is: `z[i]_fr = Fr::from(z[i]_native)` where `z[i]_native` is a field element in F_{q_commit}. Since `q_commit ≈ 2^50 < 2^254`, the mapping is injective. Document in `paper/security-proofs/p3-encoding.tex`.
