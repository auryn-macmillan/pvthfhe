
# Dual-Mode Lagrange Pattern — Reference for Interfold Port

*Recorded: 2026-05-25*

## Pattern Overview

The `aggregator_final` circuit accepts precomputed `lagrange_coeffs` as **public inputs** with a **dual-mode fallback**:
- **Production mode**: `lagrange_coeffs` are computed off-circuit (Rust, O(n²)) → passed as public inputs → circuit uses weighted sum (O(n))
- **Test/fallback mode**: If `lagrange_coeffs[0] == 0`, the circuit computes them in-circuit (O(n²))

This eliminates the old "prover-trusted coefficients" pattern where Lagrange coefficients were witness (not public) and the verifier had no way to check them.

## File Map

### 1. Noir Circuit
- **File**: `/home/dev/pvthfhe/circuits/aggregator_final/src/main.nr`
- **Constants (line 14-15)**:
  ```
  global N: u32 = 8;
  global MAX_PARTICIPANTS: u32 = 128;
  ```
- **Function signature (lines 77-92)**: `lagrange_coeffs` is `pub [Field; MAX_PARTICIPANTS]` — a public input array of size 128
- **Dual-mode logic (lines 136-151)**:
  ```noir
  if lagrange_coeffs[0] != 0 {
      // Use precomputed off-circuit coeffs (O(n) total)
      for i in 0..MAX_PARTICIPANTS {
          coeffs[i] = lagrange_coeffs[i];
      }
  } else {
      // Fall back to in-circuit computation (O(n²))
      for i in 0..MAX_PARTICIPANTS {
          if (i as u32) < n {
              coeffs[i] = lagrange_coeff_at(i, committee_party_ids, n);
          }
      }
  }
  ```
- **Σ=1 integrity check (lines 153-160)**:
  ```noir
  let mut lagrange_sum = 0;
  for i in 0..MAX_PARTICIPANTS {
      if (i as u32) < n {
          lagrange_sum = lagrange_sum + coeffs[i];
      }
  }
  assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");
  ```
- **Weighted sum reconstruction (lines 191-200)**: O(n) per coefficient:
  ```noir
  for j in 0..N {
      let mut coeff = 0;
      for i in 0..MAX_PARTICIPANTS {
          if (i as u32) < n {
              coeff = coeff + coeffs[i] * participant_shares[i][j];
          }
      }
      computed_plaintext[j] = coeff;
  }
  ```
- **In-circuit Lagrange formula (lines 55-73)**:
  ```noir
  fn lagrange_coeff_at(i: u32, party_ids: [Field; MAX_PARTICIPANTS], n: u32) -> Field {
      let mut num = 1;
      let mut den = 1;
      for j in 0..MAX_PARTICIPANTS {
          if (j as u32) < n {
              if (j as u32) != i {
                  num = num * party_ids[j];
                  den = den * (party_ids[i] - party_ids[j]);
              }
          }
      }
      let lambda = num / den;
      // Sign correction: l_i(0) = (-1)^{n-1} * prod x_j / prod (x_i - x_j)
      if (n % 2 == 0) { -lambda } else { lambda }
  }
  ```

### 2. Rust-side Coefficient Computation
- **File**: `/home/dev/pvthfhe/crates/pvthfhe-cli/src/full_pipeline.rs`
- **Function (lines 2559-2579)**: `compute_lagrange_coeffs_bn254`
  ```rust
  fn compute_lagrange_coeffs_bn254(xs: &[Fr], eval_point: Fr) -> Vec<Fr> {
      let n = xs.len();
      let mut coeffs = Vec::with_capacity(n);
      for i in 0..n {
          let mut num = Fr::one();
          let mut den = Fr::one();
          for j in 0..n {
              if i != j {
                  num *= eval_point - xs[j];
                  den *= xs[i] - xs[j];
              }
          }
          coeffs.push(num * den.inverse().unwrap_or(Fr::zero()));
      }
      coeffs
  }
  ```
- **Called at line 1456**: `let lagrange_coeffs_fr = compute_lagrange_coeffs_bn254(&party_ids_fr, Fr::from(0u64));`
- **Called at line 2932** (Prover.toml generation): same signature, same eval point (0)

### 3. Prover.toml Generation
- **File**: `/home/dev/pvthfhe/crates/pvthfhe-cli/src/full_pipeline.rs`
- **Function** (line 2889): `pub fn build_c7_prover_toml(...)`
- **Lagrange coeffs format (lines 3034-3045)**:
  ```rust
  toml.push_str("lagrange_coeffs = [");
  for i in 0..NOIR_MAX_PARTICIPANTS {
      if i < lagrange_coeffs_fr.len() {
          toml.push_str(&format!("\"0x{}\"", field_hex_be(lagrange_coeffs_fr[i])));
      } else {
          toml.push_str("\"0x00000...000\"");
      }
  }
  toml.push_str("]\n");
  ```
- **Party IDs format (lines 3053-3067)**: 128 entries, active ones first, rest zero-padded
- **Prover.toml example**: `/home/dev/pvthfhe/circuits/aggregator_final/C7Prover.toml` (line 10 — shows 128 lagrange_coeffs entries, only first 4 non-zero for n=4)

### 4. Nova C7 Circuit (Rust-side IVC folding)
- **File**: `/home/dev/pvthfhe/crates/pvthfhe-compressor/src/nova/c7_circuit.rs`
- **Accumulator state** (lines 252-261): `[acc_eval, lagrange_sum, step_count]`
  - `z'[0] = z[0] + λ_i * eval` (accumulated weighted evaluation)
  - `z'[1] = z[1] + λ_i` (accumulated Lagrange sum)
  - `z'[2] = z[2] + 1` (step counter)
- **Final verification**: verifier checks `z[1] == 1` after all steps

### 5. Witness Struct
- **File**: `/home/dev/pvthfhe/crates/pvthfhe-compressor/src/witness.rs`
- **C7Witness** (lines 118-134): carries `share_eval`, `lagrange_coeff`, `coeffs`, `coeff_commitment`
- **C7WitnessSet::new** (lines 166-197): asserts `shares.len() == lagrange_coeffs.len()`

### 6. Shamir Module (scalar-field version)
- **File**: `/home/dev/pvthfhe/crates/pvthfhe-pvss/src/shamir.rs`
- **`lagrange_coefficient_at_zero`** (lines 198-221): standalone BN254 scalar version, same formula but for scalar field shares
- NOT used for Prover.toml generation; used for PVSS threshold recovery

## Before/After Pattern

### Before (old, insecure)
- Lagrange coefficients were untrusted **witness** inputs
- No in-circuit Σ=1 check
- Prover could supply arbitrary coefficients

### After (current, secure)
- `lagrange_coeffs` are **public inputs** → verifier sees them
- Circuit verifies Σ λ_i == 1 (catches zero/duplicate IDs)
- Dual-mode: precomputed (fast) or in-circuit (test-friendly)
- Weighted sum replaces O(n²) reconstruction with O(n) when precomputed

## Key Design Decisions
1. `MAX_PARTICIPANTS = 128` — fixed array size for Noir compatibility
2. Sentinel `lagrange_coeffs[0] != 0` activates precomputed mode
3. Zero-padding fills unused array slots
4. `committee_party_ids` must be non-zero and pairwise distinct (enforced by Σ=1 check catching degeneracy)
5. Evaluation point is always 0 (Lagrange interpolation to recover secret/plaintext at x=0)


# T2 Implementation: Precomputed Lagrange Coefficients in Interfold C7

*Recorded: 2026-05-25*

## Files Modified

### 1. main.nr (`~/enclave/circuits/bin/threshold/decrypted_shares_aggregation/src/main.nr`)
- Added `lagrange_coeffs: pub [[Field; T + 1]; L]` as the last parameter in `main()`
- Passed through to `DecryptedSharesAggregation::new()` as the last argument

### 2. decrypted_shares_aggregation.nr (`~/enclave/circuits/lib/src/core/threshold/decrypted_shares_aggregation.nr`)
Three changes:

#### a. Struct field (line 61-63)
Added `lagrange_coeffs: [[Field; T + 1]; L]` field with doc comment.

#### b. Constructor `new()` (line 75)
Added `lagrange_coeffs: [[Field; T + 1]; L]` as the last parameter, stored in struct.

#### c. `execute()` (lines 98-108)
Replaced the O(n^2) in-circuit computation:
```noir
let lagrange_coeffs = compute_all_lagrange_coeffs::<T, L>(self.configs.qis, self.party_ids);
```
With:
1. **Sigma=1 integrity check** (lines 98-105): For each CRT basis l, sums all lagrange_coeffs[l][i] for i=0..T and asserts sum == 1. Uses plain Field arithmetic (no ModU128 wrapper).
2. **Precomputed usage** (lines 107-108): `let lagrange_coeffs = self.lagrange_coeffs;` moves the precomputed coefficients for use by `compute_crt_components`.

Step numbering updated: Step 3→compute CRT components, Step 4→CRT reconstruction, Step 5→decoding.

### 3. Preserved `compute_all_lagrange_coeffs` (line 185-248)
Function kept as dead code for reference/diagnostic. Only occurrence in the entire circuits directory.

## CRT-Aware Design Notes

Unlike pvthfhe's single-basis Lagrange (one `[Field; MAX_PARTICIPANTS]` array), Interfold needs CRT-aware coefficients: `[[Field; T+1]; L]`. Each CRT modulus q_l has its own set of T+1 Lagrange coefficients because L_i(0) mod q_l differs per modulus.

The Sigma=1 check verifies: for each basis l, sum_{i=0..T} lagrange_coeffs[l][i] == 1. Since Lagrange basis polynomials form a partition of unity, this holds mathematically. The check catches invalid/tampered coefficients.

## Build Verification
- `nargo check`: 142 errors total, all from pre-existing dependency issues (Vec deprecation, poseidon2_permutation API change, bignum comptime global). ZERO errors from the two modified files.
- `compute_all_lagrange_coeffs` confirmed unused (single definition, zero call sites).
- No Rust files touched (left for T3).

## Key Decisions
1. **No dual-mode fallback**: Unlike pvthfhe's circuit that falls back to in-circuit computation when `lagrange_coeffs[0] == 0`, Interfold directly uses precomputed coefficients. No sentinel-based fallback.
2. **Plain Field sum for Sigma=1**: Followed task spec to use plain Field addition (not ModU128) since the sum of properly-computed Lagrange coefficients is exactly 1 as a Field value.
3. **party_ids preserved**: Still needed for d-commitment verification. Not removed.
4. **compute_all_lagrange_coeffs kept**: Preserved as reference — useful for diagnostics and understanding the original algorithm.


# T3 Implementation: Rust-side Lagrange Coefficient Computation + Prover.toml

*Recorded: 2026-05-25*

## Files Modified

### 1. utils.rs (`~/enclave/crates/zk-helpers/src/circuits/threshold/decrypted_shares_aggregation/utils.rs`)

Added `lagrange_coeffs_at_zero(party_ids: &[usize], modulus: u64) -> Result<Vec<BigInt>, CircuitsErrors>` (lines 73-103).

- Standalone implementation (does NOT call `lagrange_recover_at_zero`). Extracted the inner Lagrange lambda_i loop from the existing function.
- For each party i: computes L_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j) mod modulus using `crate::math::mod_inverse_bigint`.
- Returns `Vec<BigInt>` where `coeffs[i] = L_i(0)`.
- Empty `party_ids` returns an error.
- `lagrange_recover_at_zero` left untouched (used by existing u_per_modulus computation).

### 2. computation.rs (`~/enclave/crates/zk-helpers/src/circuits/threshold/decrypted_shares_aggregation/computation.rs`)

Three changes:

#### a. Inputs struct field (line 111-112)
Added `pub lagrange_coeffs: Vec<Vec<BigInt>>` — shape `[L][T+1]`, outer Vec indexed by CRT basis, inner Vec indexed by party.

#### b. Inputs::compute() — population (lines 277-282)
After `u_per_modulus` loop, added a second per-modulus loop:
```rust
let mut lagrange_coeffs_per_modulus = Vec::new();
for (_m, &modulus) in moduli.iter().enumerate().take(num_moduli) {
    let coeffs = utils::lagrange_coeffs_at_zero(reconstructing_parties, modulus)?;
    lagrange_coeffs_per_modulus.push(coeffs);
}
```
Stored via `Ok(Inputs { ..., lagrange_coeffs: lagrange_coeffs_per_modulus, ... })`.

#### c. Inputs::to_json() — serialization (lines 377-382, 393)
Added `lagrange_coeffs_json` using the 2D mapping pattern from `decryption_shares`:
```rust
let lagrange_coeffs_json: Vec<Vec<serde_json::Value>> = self
    .lagrange_coeffs
    .iter()
    .map(|row| bigint_1d_to_json_values(row))
    .collect();
```
Included as `"lagrange_coeffs": lagrange_coeffs_json` in the `serde_json::json!` macro.

## Tests Added

### test_lagrange_coeffs_at_zero_two_points
Verifies standalone Lagrange coefficient computation with 2 parties mod 7:
- L_1(0) = 2, L_2(0) = 6, Σ ≡ 1 mod 7.

### test_lagrange_coeffs_populated_in_compute
End-to-end test: runs `Inputs::compute()` with sample data and verifies:
- `lagrange_coeffs.len() == num_moduli` (one row per CRT modulus)
- Each row has `T+1` coefficients
- Σ L_i(0) ≡ 1 mod q_m for each modulus (partition of unity)

## Build Results
- `cargo test -p e3-zk-helpers`: **99 passed, 0 failed, 0 warnings** (only pre-existing `workspace.msrv` notice)
- Both new tests pass.

## Notes
- Package name is `e3-zk-helpers`, not `zk-helpers` as stated in the plan.
- The `m` loop variable in the lagrange computation was unused; prefixed with underscore to suppress warning.
- `codegen.rs` not touched — it calls `inputs.to_json()` which automatically picks up the new field.
- Noir files not touched (already done in T2).
