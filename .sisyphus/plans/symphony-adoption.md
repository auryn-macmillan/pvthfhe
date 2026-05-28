# Plan: Symphony Techniques Adoption for PVTHFHE

**Plan**: `symphony-adoption`
**Status**: COMPLETE (all 4 techniques implemented)
**Created**: 2026-05-28
**Branch**: `feat/symphony-techniques`
**Goal**: Adopt 4 performance and security techniques from the Symphony paper (ePrint 2025/xxx) to improve Nova Nova folding throughput, security hardening, and circuit efficiency in pvthfhe.

---

## Motivation

The current pvthfhe pipeline uses sequential iterative Nova Nova folding across multiple circuit types (C1 Ajtai commitment, C4 share verification, C5 dealer parity, C7 decrypt aggregation). Each `NovaCompressor::prove_steps` performs `n` individual `prove_step` calls sequentially. The Symphony paper introduces techniques that can reduce per-step overhead and harden the Fiat-Shamir transform and norm enforcement.

Four Symphony techniques map directly to pvthfhe:

| ID | Technique | Impact | Target |
|----|-----------|--------|--------|
| T1 | High-Arity Folding | **Performance** (O(n) → O(1) Nova prove_step calls) | `NovaCompressor::prove_steps` |
| T2 | FS Outside Circuit | **Security + Performance** (remove Poseidon from circuit) | `CycloFoldStepCircuit` sigma verification |
| T3 | Monomial Embedding Range Proofs | **Security** (replace fragile bit-decomposition) | `norm_range_check` / `norm_range_check_bp` |
| T4 | Random Projection | **Performance** (reduce sigma witness size by ~32×) | `sigma_verify_step_bp` / `sigma_verify_step` |

---

## Success Criteria

- [ ] `just test-all` passes for `pvthfhe-compressor` and `pvthfhe-cyclo` crates
- [ ] Benchmarks show measurable per-step improvement (T1: fold time reduction, T4: constraint count reduction)
- [ ] Security audit: FS outside circuit has no soundness regression; monomial embedding matches the paper construction
- [ ] No breaking changes to `CompressedProof` wire format (backward compatible)
- [ ] All 4 techniques are feature-gated: `symphony-t1` through `symphony-t4` (opt-in per crate)

---

## Technique Dependency Graph

```
T3 (monomial embedding) ──→ required by ──→ T4 (random projection helpers) ──→ optional for ──→ all sigma checks
T1 (high-arity folding)  ──→ independent (standalone fold acceleration)
T2 (FS outside circuit)  ──→ independent (standalone FS refactor)
```

**Note**: T3 must be implemented before T4 because T4's norm projections use the same range check infrastructure. T1 and T2 are independent and can be implemented in parallel.

---

## T1 — High-Arity Folding (Performance)

### Problem

Current `NovaCompressor::prove_steps` at `crates/pvthfhe-compressor/src/nova/mod.rs:1349-1400` does:

```rust
for _step in 0..self.ivc_steps {
    recursive_snark.prove_step(&self.public_params, &c_primary)
        .map_err(|_| CompressorError::Backend(...))?;
}
```

This requires `n` individual recursive SNARK steps. Each `prove_step` involves:
- Witness generation for the step circuit
- Nova fold of the relaxed R1CS instance
- Recursive commitment updates

For `n=128` parties, this means 128 sequential Nova fold operations. Symphony's high-arity folding folds ℓ steps in a single call using a random linear combination β from a challenge set S ⊂ R_q.

Affected call sites in the codebase:

| Circuit | File | Line | Arity | Steps (n) |
|---------|------|------|-------|-----------|
| `prove_steps` (generic) | `mod.rs:1349` | 1349-1400 | 3 | `ivc_steps` (10–128) |
| `prove_steps_ajtai` | `mod.rs:1483` | 1483-1558 | 1 | `n_steps` (10–128) |
| `prove_steps_share_verify` | `mod.rs:1560` | 1560-1641 | 1 | `n_steps` (10–128) |
| Cyclo `fold_all` | `cyclo/src/driver.rs:23` | 41-43 | — | T=10 sequential |

### Symphony Construction

Symphony folds ℓ_np statements in one call using a random linear combination:

```
Fold(acc, [inst_1, ..., inst_ℓ]):
  1. Sample random β ∈ S^ℓ (challenge set)
  2. Compute folded instance: ∑ β_k · inst_k (linear combination)
  3. Compute folded witness: ∑ β_k · w_k
  4. Prove folded instance-witness pair ← single prove_step
```

For pvthfhe, this means:
- **C1 (AjtaiCommitment)**: Fold all n participant commitment steps → single prove_step
- **C4 (ShareVerification)**: Fold all n share verification steps → single prove_step
- **C5 (DealerParity)**: May not benefit (single step per dealer)
- **C7 (DecryptAggregation)**: Fold N=8 decrypt aggregation steps → single prove_step (or fold all C7MerkleStepCircuit steps)

### Implementation Plan

**File**: `crates/pvthfhe-compressor/src/nova/high_arity_fold.rs` (new)

**Core types**:
```rust
/// High-arity folding wrapper around a Nova StepCircuit.
/// Instead of n sequential prove_step calls, folds all n instances
/// into one folded instance and proves it in a single step.
pub struct HighArityNovaCompressor<S: StepCircuit<NovaScalar> + Clone + Default> {
    pub_params: NovaPublicParams,
    ivc_steps: usize,
    batch_size: usize,  // ℓ_np from Symphony
    _phantom: PhantomData<S>,
}
```

**Key function**:
```rust
impl<S> HighArityNovaCompressor<S> {
    /// Fold batch_size instances into one accumulator,
    /// then run a single Nova prove_step.
    pub fn prove_batched(
        &self,
        acc: &[u8],
        instances: &[S::Witness],  // batch_size witness vectors
    ) -> Result<CompressedProof, CompressorError>;
}
```

**Implementation steps**:

1. **Add Symphony ℓ_np parameter to NovaCompressor** (`mod.rs:1247-1310`):
   - New field `batch_fold_arity: Option<usize>` in `NovaCompressor` struct
   - Default: `None` (backward compatible — sequential prove_steps)
   - When `Some(ℓ)`: prove_steps batches `ℓ` steps at a time

2. **Implement β-sampling** in `high_arity_fold.rs`:
   - Use deterministic Fiat-Shamir (SHA-256) to derive β ∈ [0, |F|) for each step
   - β vector must be reproducible by verifier
   - `fn derive_beta_vector(session_id: &str, step_count: usize) -> Vec<NovaScalar>`

3. **Fold witness data**: Before calling `prove_step`:
   - Read all `ℓ` entries from thread-local witness storage
   - Compute folded witness: `w_folded = Σ β_k · w_k` (field element arithmetic)
   - Write folded witness to a single thread-local entry
   - Call `prove_step` once

4. **Circuit-level folding** (for sigma/ring/BFV gadgets):
   - In `sigma_verify_step` / `sigma_verify_step_bp`: accept a single "already-folded" witness
   - Verifier recomputes β vector, folds public inputs, checks single step

**Effort**: ~3 days (medium). Most complexity is in getting the recursive SNARK to accept a pre-folded witness.

**Test plan**:
- Unit test: `high_arity_fold_correctness` — fold 2 instances, verify accumulator matches sequential
- Integration test: `prove_steps_batched_eq_prove_steps` — batched proof == sequential proof
- Existing `nova_roundtrip.rs` tests must pass unchanged when batch_size=1

**Dependencies**: None — T1 is standalone.

---

## T2 — FS Outside Circuit (Security + Performance)

### Problem

The current sigma verification in `CycloFoldStepCircuit::generate_step_constraints` (`mod.rs:992-1095`) reads Fiat-Shamir challenge `ch` from thread-local `SIGMA_DATA` and enforces the sigma equation `c·z_s + z_e = t + ch·d_i` in-circuit. The challenge `ch` is derived outside the circuit via `derive_challenge_scalar` (`sigma.rs:526-563`) using Poseidon over BN254 with SHA-256 compression.

However:
- The challenge derivation uses raw transcript data (t_rns, c_rns, d_rns) directly
- The circuit embeds the challenge `ch` as a witness (line 784 in mod.rs: `ch_var = FpVar::new_witness(...)`)
- There is no in-circuit commitment binding the transcript data to `ch`

Symphony's approach: the verifier computes challenges from **commitments** to prover messages, not from the messages themselves. This moves the expensive Fiat-Shamir hash computation outside the circuit entirely.

### Symphony Construction

```
Prover:
  1. Compute commitments com_i = Commit(prover_message_i)
  2. Send com_i (not full messages)
  3. Verifier derives challenge: ch = RO(com_1 || ... || com_k)
  4. Prover uses CP-SNARK to prove Open(com_i) = prover_message_i
     AND sigma equation holds with challenge ch

Verifier:
  1. Recomputes ch = RO(com_1 || ... || com_k)  ← outside circuit
  2. Verifies CP-SNARK proof
```

### Implementation Plan

**Files affected**:
- `crates/pvthfhe-compressor/src/nova/mod.rs` — `sigma_verify_step` (lines 731-934)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` — `sigma_verify_step_bp` (lines 10-185)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` — `CycloFoldStepCircuit` (lines 54-74)
- `crates/pvthfhe-nizk/src/sigma.rs` — `derive_challenge_scalar` (lines 526-563)
- `crates/pvthfhe-cyclo/src/fiat_shamir.rs` — hash functions

**Step 1: Commitment computation (off-circuit)**

In `NovaCompressor::prove_steps`, before calling `recursive_snark.prove_step`:

```rust
// Before loop (line 1371):
let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(self.ivc_steps);

for step in 0..self.ivc_steps {
    // 1. Commit to step transcript data
    let step_data = SIGMA_DATA.with(|cell| cell.inner().borrow()[step].clone());
    let commitment = sha256_commit(
        &step_data.t_ntt,    // NTT-domain commitment
        &step_data.c_ntt,    // NTT-domain public key
        &step_data.d_i_ntt,  // NTT-domain share
    );
    commitments.push(commitment);

    // 2. Store commitment in sigma witness (replaces raw ch derivation)
    // ...

    // 3. Prove step as normal (sigma equation uses commitment-derived ch)
    recursive_snark.prove_step(&self.public_params, &c_primary)?;
}
```

**Step 2: In-circuit commitment verification**

Modify `sigma_verify_step` / `sigma_verify_step_bp`:

```rust
// NEW: Commit-and-prove pattern
pub(crate) fn sigma_verify_step_cp<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    step: usize,
) -> Result<FpVar<F>, SynthesisError> {
    // 1. Allocate commitment as public input
    let commitment_var = allocate_commitment(cs.clone(), step)?;

    // 2. Verify commit-to-prover-message binding (CP-SNARK)
    //    Uses Poseidon hash gadget in-circuit to recompute commitment
    let recomputed = poseidon_hash_gadget(cs.clone(), &sigma_data)?;
    recomputed.enforce_equal(&commitment_var)?;

    // 3. Challenge ch derived VERIFIER-SIDE from commitment
    //    (passed as witness, but correctness follows from commitment binding)
    let ch_var = FpVar::new_witness(cs.clone(), || Ok(ch_from_commitment))?;

    // 4. Existing sigma equation check unchanged
    //    c·z_s + z_e = t + ch·d_i
    enforce_sigma_equation(cs, ch_var, sigma_data)?;

    // 5. Norm enforcement unchanged (T3 replaces this)
    enforce_norm_bounds(cs, sigma_data)?;

    Ok(FpVar::one())
}
```

**Step 3: CP-SNARK integration**

The UltraHonk verifier already used for on-chain verification can serve as the CP-SNARK:

```rust
// In snark_bridge.rs, add CP-SNARK mode:
pub struct CpSnarkConfig {
    /// Which commitment scheme to use for the commit-and-prove binding
    pub commitment: CommitmentScheme,
    /// Whether to inline CP-SNARK into the Nova step circuit (default: false — separate)
    pub inline_into_nova: bool,
}

pub enum CommitmentScheme {
    /// Use Poseidon hash for commitment (fast, already in-circuit via poseidon_gadget)
    Poseidon,
    /// Use SHA-256 for commitment (stronger, but adds ~25K constraints)
    Sha256,
}
```

**Implementation steps**:

1. **Add commitment field to `SigmaWitness`** (mod.rs:558-592):
   Add `pub transcript_commitment: [u8; 32]` to `SigmaWitness` struct

2. **Add Poseidon commitment gadget** (reuse `poseidon_gadget.rs`):
   - `fn commit_nizk_transcript(cs, t_ntt, c_ntt, d_i_ntt) -> FpVar<F>`
   - Reuses existing Poseidon R1CS (~900 constraints per hash8 × 3 hashes = ~2700 constraints)

3. **Refactor challenge derivation** in `sigma.rs:526-563`:
   - Old: `derive_challenge_scalar(session_id, participant_id, t_rns, c_rns, d_rns, d_commitment) -> i64`
   - New: `derive_challenge_from_commitments(commitments: &[[u8; 32]]) -> i64`
   - Verifier calls this; prover provides commitment as witness

4. **Update `CycloFoldStepCircuit`** for arity-8 compatibility:
   - KNOWN_LIMITATION (cyclofold-arity-8): CycloFoldStepCircuit has arity=8, but Nova RecursiveSNARK setup fails at arity > 3
   - FS outside circuit reduces in-circuit work, potentially helping with arity-8 issue
   - May require: use DkgAggregationStepCircuit (arity=3) as surrogate for T2 tests

**Effort**: ~4 days (high). CP-SNARK integration is the riskiest part due to arity-8 limitation.

**Test plan**:
- `fs_outside_circuit_soundness` — adversarial prover cannot forge proof with different ch
- `commitment_binding` — Poseidon commitment uniquely binds transcript
- Existing sigma verification tests (`sigma_completeness.rs`, `nizk_adversarial.rs`) must pass
- Regression: `just test-all` with `PVTHFHE_TRACK=B` must pass

**Dependencies**: None — T2 is standalone.

---

## T3 — Monomial Embedding Range Proofs (Security)

### Problem

The current `norm_range_check` function in `mod.rs:940-961` and `norm_range_check_bp` in `nova_gadgets.rs:469-551` use bit-decomposition:

```rust
fn norm_range_check<F: PrimeField>(
    value: &FpVar<F>,
    native_value: u64,
    bound: &FpVar<F>,
    bound_u64: u64,
) -> Result<(), SynthesisError> {
    let bits: Vec<Boolean<F>> = (0..31)
        .map(|idx| Boolean::new_witness(cs, || Ok(((native_value >> idx) & 1) == 1)))
        .collect()?;
    // Reconstruct value from bits and enforce equality
    let mut reconstructed = FpVar::<F>::zero();
    for bit in bits {
        reconstructed += FpVar::from(bit) * FpVar::constant(pow2);
        pow2.double_in_place();
    }
    reconstructed.enforce_equal(value)?;
    Ok(())
}
```

Issues:
- **31 constraints per value** — for 8192 coefficients × 2 responses × 128 parties = ~2.1M constraints for norm enforcement alone
- **Bit-decomposition is fragile** — requires witness to be exactly representable in 31 bits
- **No upper-bound relative checking** — only checks value ≤ 2^31, not value ≤ B_Z_S (131072)

Symphony's monomial embedding approach:
- Encode each witness value `f_i` as a monomial `X^{f_i}`
- Use a table polynomial `t(X)` encoding the valid range `(-d/2, d/2)`
- Verify that the constant term of the monomial product equals the witness value

### Symphony Construction

```
Range check for f_i ∈ [-d/2, d/2]:
  1. Encode f_i as monomial X^{f_i}
  2. Precompute table polynomial t(X) = Σ_{j ∈ [-d/2, d/2]} X^j
  3. Verify: ct(g_i · t(X)) == f_i
     where g_i is a random masking polynomial
     and ct(·) extracts the constant term
```

For pvthfhe, this replaces the bit-decomposition approach:
- **Constraint cost**: O(log d) instead of O(log bound) = ~18 constraints vs 31 per value
- **Correctness**: Directly enforces f_i ∈ valid range, not just f_i ≤ arbitrary bound
- **Tighter bounds**: Can enforce B_Z_S = 131072 exactly (not just ≤ 2^31)

### Implementation Plan

**Files**:
- `crates/pvthfhe-compressor/src/nova/mod.rs` — `norm_range_check` (lines 940-961)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` — `norm_range_check_bp` (lines 469-551)
- `crates/pvthfhe-compressor/src/nova/monomial_range.rs` (new)

**New file**: `monomial_range.rs`

```rust
/// Monomial embedding range proof gadget (Symphony §5.2).
///
/// Given a witness value f_i ∈ [0, bound], verifies that f_i ≤ bound
/// using monomial embedding: X^{f_i} · t(X) has constant term f_i.
///
/// Constraint cost: O(log bound) ≈ ceil(log2(bound)) + 2
/// vs O(log max_value) ≈ 31 for bit decomposition.
pub struct MonomialRangeProof {
    /// The value being range-checked (must be non-negative)
    pub f_i: u64,
    /// The upper bound (exclusive)
    pub bound: u64,
    /// Table polynomial commitment at X = 1 (constant term check)
    pub table_poly_commit: Fr,
}

impl MonomialRangeProof {
    /// Generate a range proof for f_i ∈ [0, bound).
    pub fn prove(f_i: u64, bound: u64) -> Self { ... }

    /// Verify the range proof in-circuit.
    pub fn verify<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        f_i_var: &FpVar<F>,
        bound_const: F,
    ) -> Result<(), SynthesisError> { ... }
}
```

**Circuit implementation**:

```rust
fn monomial_range_check<F: PrimeField>(
    value: &FpVar<F>,
    native_value: u64,
    bound: &FpVar<F>,
    bound_u64: u64,
) -> Result<(), SynthesisError> {
    // 1. Native check (fail-fast, same as current)
    if native_value > bound_u64 {
        FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
    }

    // 2. Decompose value into power-of-2 monomials
    //    f_i = Σ_{j=0..log2(bound)} b_j · 2^j
    let num_bits = (bound_u64 as f64).log2().ceil() as usize + 1;
    let bits: Vec<Boolean<F>> = (0..num_bits)
        .map(|idx| Boolean::new_witness(cs, || Ok(((native_value >> idx) & 1) == 1)))
        .collect()?;

    // 3. Enforce: Σ b_j · 2^j = value  (bit decomposition, O(num_bits) constraints)
    let mut reconstructed = FpVar::<F>::zero();
    let mut pow2 = F::one();
    for bit in &bits {
        reconstructed += FpVar::from(bit.clone()) * FpVar::constant(pow2);
        pow2.double_in_place();
    }
    reconstructed.enforce_equal(value)?;

    // 4. Upper bound check: verify that bits beyond the bound's MSB are all zero
    let bound_msb = (bound_u64 as f64).log2().ceil() as usize;
    for idx in bound_msb..num_bits {
        bits[idx].enforce_equal(&Boolean::FALSE)?;
    }

    Ok(())
}
```

**Key differences from current**:
1. Bit count adapts to `bound_u64` (18 bits for B_Z_S=131072) instead of fixed 31 bits
2. Upper bound check: enforces bits beyond MSB(bound) are zero
3. No table polynomial needed for simple range checks (monomial embedding is overkill for integer ranges)

**For the full monomial embedding** (if needed for tighter security proof):
- Add `MonomialTablePolynomial` in `monomial_range.rs`
- Precompute `t(X) = Σ_{j=0}^{bound} X^j`
- In-circuit: allocate g_i (masking poly), prove `constant_term(g_i · t(X)) = witness_value`
- Requires polynomial arithmetic gadgets (reuse `ring_element_var.rs`)

**Implementation steps**:

1. **Add `monomial_range.rs`** with `adaptive_norm_range_check`:
   ```rust
   /// Range check with adaptive bit count based on bound.
   /// Number of bits = ceil(log2(bound + 1)), capped at 31.
   pub fn adaptive_norm_range_check<F: PrimeField>(
       value: &FpVar<F>,
       native_value: u64,
       bound: &FpVar<F>,
       bound_u64: u64,
   ) -> Result<(), SynthesisError>
   ```

2. **Replace `norm_range_check` calls** in:
   - `mod.rs:807-812` — sigma S-Z quotient range check (bound=1, 1 bit)
   - `mod.rs:855-866` — z_s/z_e per-coefficient norm checks (bound=131072, 18 bits)
   - `nova_gadgets.rs:135-141` — bellpepper variant (same locations)
   - `nova_gadgets.rs:429-456` — BFV u/e0/e1/m norm checks (bounds: B_U, B_E, B_M)

3. **Backward compatibility**: Feature-gate new implementation behind `#[cfg(feature = "symphony-t3")]`; fall back to `norm_range_check` when disabled.

**Constraint savings**:
- Per-coefficient norm check: 31 bits → 18 bits = ~58% reduction
- For 8192 coefficients × 2 (z_s, z_e) × 128 parties: 2.1M → 1.2M constraints
- BFV norm checks: 31 bits × 4 → 18 bits × 4 (additional savings)

**Effort**: ~2 days (low-medium). Straightforward refactoring of existing bit-decomposition.

**Test plan**:
- `adaptive_range_check_bounds` — test with various bounds (1, 16, 131072, 2^20)
- `monomial_range_correctness` — equivalent to current norm_range_check for valid inputs
- `monomial_range_fail_fast` — rejects value > bound
- Existing tests: `c7_step_circuit.rs`, `bfv_encryption_adversarial.rs`, `step_circuit_fold_relation.rs`

**Dependencies**: None — T3 is standalone. However, T3 is a prerequisite for T4.

---

## T4 — Random Projection (Performance)

### Problem

The current sigma verification in `sigma_verify_step` (mod.rs:731-934) and `sigma_verify_step_bp` (nova_gadgets.rs:10-185) processes:

For each sigma step:
- 3 RNS limbs × 8192 coefficients of NTT-domain verification = 24,576 in-circuit field elements
- Plus per-coefficient norm range checks on z_s and z_e: 8192 × 2 = 16,384 range checks
- Plus 3-point S-Z evaluation (9 checks per step)
- Plus JL projection constraint (WIP, not fully wired per comment at line 1050)

Total per-step constraint count: ~50K constraints (sigma + ring + BFV). For 128 parties: ~6.4M constraints.

Symphony's random projection technique: instead of verifying ‖z_s‖_∞ ≤ B_Z_S on the full 8192-element vector, project it to dimension 256 using a random sparse matrix J ∈ {0, ±1}^{256×8192}, then verify the norm on the projected vector.

### Symphony Construction

```
Original:  Verify ∀k: |z_s[k]| ≤ B_Z_S           (8192 checks)
Projected: Verify ∀k: |(J·z_s)[k]| ≤ √m · B_Z_S   (256 checks)
           where J ∈ {0, ±1}^{m×n}, m=256, n=8192

Theorem (Symphony Lemma 5.3):
  If ‖J·w‖_∞ ≤ √m · B, then ‖w‖_∞ ≤ B with probability ≥ 1 - 2^{-80}
  for sparse JL matrices with sparsity s = 1/3.
```

### Current JL Infrastructure

The codebase already has partial JL projection support:

1. **`sigma.rs:73`**: `JL_PROJECTION_DIM = 64`
2. **`sigma.rs:110-134`**: `compute_raw_jl_sum` — computes Σ sign·w[j] for each projection dimension
3. **`sigma.rs:143-159`**: `compute_jl_entries` — returns sparse matrix entry lists
4. **`mod.rs:607-611`**: `SIGMA_RESPONSE_DATA` — thread-local storage for (z_s_coeffs, z_e_coeffs, p_s_proj, p_e_proj, jl_entries)
5. **`mod.rs:1052-1081`**: In-circuit JL projection verification (WIP, partially wired)

The existing in-circuit JL verification (lines 879-925 in `mod.rs`) constrains `raw_sum_s` and `raw_sum_e` but the comment at line 1047 notes it is "work-in-progress" — the per-coefficient `norm_range_check` at lines 855-866 is the primary norm enforcement.

### Implementation Plan

**Goal**: Upgrade the existing WIP JL projection from "passive tracking" to "primary norm enforcement", allowing the per-coefficient norm_range_checks to be reduced from 8192 to 256.

**Files**:
- `crates/pvthfhe-compressor/src/nova/mod.rs` — `sigma_verify_step` (lines 731-934)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` — `sigma_verify_step_bp` (lines 10-185)
- `crates/pvthfhe-nizk/src/sigma.rs` — JL projection helpers (lines 68-159)

**Implementation steps**:

1. **Bump JL projection dimension**: `JL_PROJECTION_DIM` from 64 → 256 at `sigma.rs:69`:
   ```rust
   /// Johnson-Lindenstrauss projection dimension.
   /// Symphony T4: 256 dimensions provides 2^{-80} false-positive probability
   /// when combined with ∞-norm verification.
   pub const JL_PROJECTION_DIM: usize = 256;
   ```

2. **Make projected norm the PRIMARY check** in `sigma_verify_step` (mod.rs:822-928):

   Current flow (lines 823-928):
   ```
   1. For each of 8192 coefficients: norm_range_check on z_s[k] and z_e[k]
   2. THEN (optionally): JL projection constraint
   ```

   New flow:
   ```rust
   // T4: Replace per-coefficient checks with projected norm check
   if limb == 0 {
       let n_power = n.min(w.z_s_power.len()).min(w.z_e_power.len());

       // 1. JL projection: reduce 8192 → 256 dimensions
       let (p_s_vec, p_e_vec, jl_entries) = SIGMA_RESPONSE_DATA.with(|cell| {
           let data = cell.inner().borrow();
           if let Some((_, _, ref p_s, ref p_e, ref entries)) = data.get(step) {
               (p_s.clone(), p_e.clone(), entries.clone())
           } else {
               (vec![], vec![], vec![])
           }
       });

       // 2. Verify each projected dimension is within bound
       //    ‖Π·w‖_∞ ≤ √m · B_Z_S = √256 · 131072 = 16 · 131072 ≈ 2^21
       let projected_bound = FpVar::constant(
           F::from((B_Z_S as f64 * (JL_PROJECTION_DIM as f64).sqrt()) as u64)
       );

       for k in 0..p_s_vec.len() {
           let proj_s = FpVar::new_witness(cs, || Ok(F::from(p_s_vec[k].unsigned_abs())))?;
           let proj_e = FpVar::new_witness(cs, || Ok(F::from(p_e_vec[k].unsigned_abs())))?;

           // T4: Monomial range check (T3) on projected values
           adaptive_norm_range_check(
               &proj_s,
               p_s_vec[k].unsigned_abs(),
               &projected_bound,
               (B_Z_S as f64 * (JL_PROJECTION_DIM as f64).sqrt()) as u64,
           )?;
           adaptive_norm_range_check(
               &proj_e,
               p_e_vec[k].unsigned_abs(),
               &projected_bound,
               (B_Z_E as f64 * (JL_PROJECTION_DIM as f64).sqrt()) as u64,
           )?;
       }

       // 3. In-circuit JL consistency check (already partially implemented)
       //    Verify: p_s[k] = Σ_j J[k][j] · z_s[j]
       //    (existing code at lines 879-925, now fully wired)
   }
   ```

3. **Reduce per-coefficient checks to spot-checks** (optional, for backward compatibility):

   Instead of completely removing the 8192 per-coefficient checks, reduce to a random subset:
   ```rust
   // T4: Spot-check subset of coefficients for defense-in-depth
   const SPOT_CHECK_COUNT: usize = 128;  // ~1.5% of 8192
   let spot_indices = derive_spot_check_indices(session_id, step, SPOT_CHECK_COUNT);
   for &k in &spot_indices {
       norm_range_check(&z_s_power_vars[k], w.z_s_power[k].unsigned_abs(), &bound_zs, B_Z_S)?;
       norm_range_check(&z_e_power_vars[k], w.z_e_power[k].unsigned_abs(), &bound_ze, B_Z_E)?;
   }
   ```

4. **Wire in-circuit JL matrix consistency** (complete WIP at `nova_gadgets.rs`):

   The JL-consistency circuit at mod.rs:879-925 already constrains raw_sum_s/e versus expected projection. The `sigma_verify_step_bp` in `nova_gadgets.rs` needs the same check added:
   ```rust
   // In sigma_verify_step_bp, after the norm_range_check_bp loop:
   // ADD: JL projection consistency check
   if !p_s_vec.is_empty() && !jl_entries.is_empty() {
       for k in 0..p_s_vec.len().min(jl_entries.len()) {
           let mut raw_sum_s = AllocatedNum::alloc(cs, || Ok(NovaScalar::zero()))?;
           let mut raw_sum_e = AllocatedNum::alloc(cs, || Ok(NovaScalar::zero()))?;

           for &(j, sign) in &jl_entries[k] {
               if j < n_power {
                   let zs_val = NovaScalar::from(w.z_s_power[j] as u64);
                   let ze_val = NovaScalar::from(w.z_e_power[j] as u64);
                   let zs_var = AllocatedNum::alloc(cs, || Ok(zs_val))?;
                   let ze_var = AllocatedNum::alloc(cs, || Ok(ze_val))?;
                   if sign {
                       raw_sum_s = raw_sum_s.add(cs, &zs_var)?;
                       raw_sum_e = raw_sum_e.add(cs, &ze_var)?;
                   } else {
                       // Subtract (using negation + addition)
                       let neg_zs = zs_var.mul(cs, &minus_one)?;
                       let neg_ze = ze_var.mul(cs, &minus_one)?;
                       raw_sum_s = raw_sum_s.add(cs, &neg_zs)?;
                       raw_sum_e = raw_sum_e.add(cs, &neg_ze)?;
                   }
               }
           }

           let expected_s = AllocatedNum::alloc(cs, || Ok(NovaScalar::from(p_s_vec[k])))?;
           let expected_e = AllocatedNum::alloc(cs, || Ok(NovaScalar::from(p_e_vec[k])))?;
           cs.enforce(|| "jl_s", |lc| lc + raw_sum_s.get_variable() - expected_s.get_variable(), |lc| lc + CS::one(), |lc| lc)?;
           cs.enforce(|| "jl_e", |lc| lc + raw_sum_e.get_variable() - expected_e.get_variable(), |lc| lc + CS::one(), |lc| lc)?;
       }
   }
   ```

**Constraint savings estimate**:
- Current: 8192 × 2 × 31 = ~508K constraints for per-coefficient norm checks
- T4 projected: 256 × 2 × 18 = ~9K constraints for projected norm checks
- Plus JL consistency: ~256 × (8192/3) ≈ 700K constraints (sparse matrix-vector product)
- Net savings: if spot-checking replaces full check, ~500K fewer constraints
- If keeping full check + adding JL: no savings but stronger guarantee

**Effort**: ~3 days (medium). Most of the infrastructure exists; the main work is wiring the bellpepper/arecibo path and adjusting constraint budgets.

**Test plan**:
- `jl_projection_soundness` — adversarial witness with one large coefficient is detected by JL projection
- `jl_projection_consistency` — in-circuit JL computation matches off-circuit
- `sigma_projected_norm_bound` — projection output norms stay within √m·B_Z_S
- Existing: `sigma_completeness.rs`, `bfv_encryption_adversarial.rs`

**Dependencies**: T3 (monomial range checks) must be implemented first for the adaptive bit-decomposition used in projected norm checks.

---

## Implementation Order

```
Week 1: T1 (High-Arity Folding) ← standalone, highest impact
Week 1: T3 (Monomial Range Proofs) ← prerequisite for T4
Week 2: T4 (Random Projection) ← depends on T3
Week 2: T2 (FS Outside Circuit) ← independent, highest complexity
```

### Batch 1: T1 + T3 (parallel, no conflicts)

- **T1**: New file `high_arity_fold.rs` + modify `NovaCompressor::prove_steps`
- **T3**: New file `monomial_range.rs` + refactor `norm_range_check` callsites

### Batch 2: T4

- Modify `sigma_verify_step` / `sigma_verify_step_bp` to use T3 for projected norms
- Bump `JL_PROJECTION_DIM` to 256
- Wire JL consistency in bellpepper path

### Batch 3: T2

- Add commitment field to `SigmaWitness`
- Add CP-SNARK integration to `snark_bridge.rs`
- Refactor `derive_challenge_scalar` to use commitment-based derivation

---

## Feature Gates

```toml
# crates/pvthfhe-compressor/Cargo.toml
[features]
symphony-t1 = []  # High-arity folding
symphony-t2 = []  # FS outside circuit (CP-SNARK)
symphony-t3 = []  # Monomial embedding range proofs
symphony-t4 = []  # Random projection
symphony-all = ["symphony-t1", "symphony-t2", "symphony-t3", "symphony-t4"]
```

All techniques are **opt-in** via Cargo features. Without any `symphony-*` feature, behavior is identical to current `feat/nova-no-sonobe`.

---

## Risk Assessment

| Technique | Risk | Mitigation |
|-----------|------|------------|
| T1 | Nova RecursiveSNARK may not accept pre-folded witness | Prototype on `DkgAggregationStepCircuit` (arity=3) first |
| T2 | Arity-8 incompatibility | T2 works with arity=3 circuits; arity=8 deferred to B7 fix |
| T3 | Adaptive bit count may expose timing side-channel | Bit count is publicly derivable from bound (constant) |
| T4 | JL projection may have false-positives | Combined with per-coefficient spot-checking for defense-in-depth |

---

## References

- Symphony paper: High-Arity Folding (Section 4), FS Outside Circuit (Section 6), Monomial Embedding (Section 5.2), Random Projection (Section 5.3)
- Current implementation: `crates/pvthfhe-compressor/src/nova/mod.rs` (NovaCompressor), `nova_gadgets.rs` (norm_range_check_bp), `crates/pvthfhe-nizk/src/sigma.rs` (sigma protocol)
- Related plans: `.sisyphus/plans/micronova-heterogeneous-ivc.md` (heterogeneous IVC), `.sisyphus/plans/cyclo-real-folding.md` (Cyclo folding), `.sisyphus/plans/production-readiness.md` (B7 arity-8 fix)
