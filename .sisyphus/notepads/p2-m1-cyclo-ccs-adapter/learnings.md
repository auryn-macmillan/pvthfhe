## P2-M1.1 — CCS Encoding Design Doc — 2026-05-14

### Key Decisions

1. **Coefficient-wise encoding**: The 256 ring coefficients are encoded as separate
   Fr field elements in the CCS variable vector (1025 entries), NOT as polynomial
   ring elements. This avoids polynomial multiplication entirely for the base P1
   verifier equation.

2. **Constant-1 trick**: Linear constraints (no cross-terms) are encoded using the
   standard CCS technique: M₂ selects the constant 1, reducing the Hadamard product
   to the identity, so (M₁·z) ⊙ 1 = M₃·z enforces M₁·z = M₃·z.

3. **Matrix topology**: M₁ has exactly 2 non-zero entries per row (selecting z_s
   and z_e per coefficient), M₂ has 1 (constant 1), M₃ has 1 (public constant t +
   c·d_i). Matrix is block-diagonal with no cross-coefficient dependencies.

4. **Challenge as matrix constant**: The challenge c ∈ {-1,0,1} is embedded as a
   scalar constant in the M₁ matrix entries, not as a CCS variable. This means a
   new matrix is required for each proof session (since c varies via FS).

5. **s and e included but unconstrained**: The secret key and error coefficients
   are in the variable vector (indices 0–511) with zero matrix coefficients.
   They're present as placeholders for composition with RLWE relation and Ajtai
   commitment constraints in later phases (M1.3, M4).

### File Created

- `.sisyphus/research/p2/ccs-encoding.md` (431 lines, 7 sections)

### References Consulted

- `sigma.rs:verify()` — source of P1 verifier equation
- `ccs_rlwe.rs:encode_rlwe_share_relation()` — existing CCS 3-matrix encoding pattern
- `ccs_encode.rs:check_satisfiability_rq()`, `check_three_matrix_rq()` — CCS satisfiability implementation
- `spec-real-p2p3.md` §4.1 — locked Cyclo parameters
- `fold-construction.md` §2.3 — CCS encoder context
- `ccs-full-matrix/learnings.md` — prior implementation learnings for 3-matrix format
- `cyclo-digest.md` §2, §3 — formal CCS relation definition

---

## P2-M1.2 & P2-M1.3 — RingElement and CycloVerifierCCS — 2026-05-14

### Files Created

- `crates/pvthfhe-aggregator/src/folding/ring_element.rs` — RingElement<F: PrimeField> with O(N²) polynomial arithmetic modulo X^N+1
- `crates/pvthfhe-aggregator/src/folding/ccs_adapter.rs` — CycloVerifierCCS<F: PrimeField> encoding P1 verifier equation
- Updated `crates/pvthfhe-aggregator/src/folding/mod.rs` — added `pub mod ring_element; pub mod ccs_adapter;`

### Dependencies Added

- `ark-ff = "0.5"` (direct) — was already a workspace transitive dep through pvthfhe-cyclo
- `ark-bn254 = "0.5"` (dev) — needed for test type aliases, already used in 7 other workspace crates

### Test Results

- 10/10 tests passed (5 ring_element, 5 ccs_adapter)
- 0 compilation errors, 0 LSP diagnostics

### Design Decisions

1. **Generic over PrimeField**: Both RingElement and CycloVerifierCCS are generic over `F: PrimeField`, not hardcoded to a specific field. This enables reuse with different fields.

2. **O(N²) convolution for mul**: The multiplication uses a direct nested loop (N² = 65,536 ops for N=256). Accepted as M1 proof-of-concept — NTT deferred to later phases.

3. **X^N+1 ring modulus**: The convolution correctly handles the sign flip: when i+j ≥ N, subtract a[i]*b[j] (since X^N ≡ -1). Verified by the ring_mul_mod_xn_plus_one test.

4. **RingElement not modulo q_commit**: All arithmetic is over the field F, not reduced modulo q_commit. The callers are responsible for modular reduction. This is documented in the struct docstring.

5. **verify_equation formula correction**: Initial test code had `t = z_s + z_e - c·d` but the correct formula per the P1 equation `c·z_s + z_e - t - c·d = 0` is `t = c·z_s + z_e - c·d`. The missing `c·` on `z_s` only matters when challenge ≠ 1 (e.g., c=-1).

6. **ark-ff 0.5 trait imports**: `Zero::zero()` and `One::one()` require explicit trait imports (`use ark_ff::Zero;`, `use ark_ff::One;`). These are not inherent methods on Fp types in ark-ff 0.5.

### Not Implemented (Deferred to P2-M1.4)

- R1CS constraint encoding (to_ccs_matrix)
- Wire into CycloFoldStepCircuit
- CCS matrix (A, B, C) construction

---

## P2-M1.4 — Wire CycloVerifierCCS into CycloFoldStepCircuit — 2026-05-14

### Files Created

- `crates/pvthfhe-compressor/src/nova/cyclo_verifier.rs` — `verify_ring_equation()` free function wrapping `CycloVerifierCCS::verify_native()`

### Files Modified

- `crates/pvthfhe-compressor/Cargo.toml` — added `pvthfhe-aggregator` dependency
- `crates/pvthfhe-compressor/src/nova/mod.rs` — updated `CycloFoldStepCircuit`:
  - `state_len()` 3 → 4 (added `ring_verification_count`)
  - `descriptor().width` 3 → 4
  - `generate_step_constraints` now returns 4 elements with M1 placeholder comment
  - Added `pub mod cyclo_verifier;` and `use ark_r1cs_std::fields::FieldVar;`

### Key Decisions

1. **State layout**: [commitment_hash, norm, fold_count, ring_verification_count]
2. **M1 placeholder**: The 4th state element increments by 1 each fold step, tracking that a step occurred. The actual R1CS ring-equation verification is deferred to M2.
3. **Native pre-verification**: `cyclo_verifier::verify_ring_equation()` provides a native (non-R1CS) check that can be called before folding enters the circuit.
4. **Track A/B coexistence**: The hash-then-fold path (Track A, 3-element state originally) is preserved. The 4th element is the Track B placeholder.
5. **`FpVar::one()`**: Used `FpVar::<F>::one()` (from `FieldVar` trait) to increment the verification counter in R1CS. The initial attempt to use `FpVar::constant()` failed because that method doesn't exist on `FpVar`.

## P2-M1.5 — 7 RED Tests — 2026-05-14

### File Created

- `crates/pvthfhe-aggregator/tests/cyclo_ccs_adapter.rs` — 7 integration tests

### Test Results

- 7/7 passed (0 compilation errors, 0 LSP diagnostics)

### Test Fixes

- **`verifier_rejects_wrong_challenge`**: Original test data (all ones) was too symmetric — the equation `c·1 + 1 - 1 - c·1 = 0` holds for any c. Fixed by using distinct values (s=2, d=3, e=5, t=4) where t is valid only for c=1.
- **Unused variable `c`** in `verifier_accepts_honest_witness`: removed redundant `let c = challenge;` binding.

## P2-M1.6 — Documentation — 2026-05-14

### Updated

- `crates/pvthfhe-compressor/src/nova/mod.rs`: CycloFoldStepCircuit docstring now documents the 4-element state layout, M1 ring verification placeholder, and Track A/B coexistence.
- `crates/pvthfhe-compressor/src/nova/cyclo_verifier.rs`: full module and function docstrings explaining the M1 ring-equation verification and M2 deferral.
- `crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs`: fixed pre-existing missing `use ark_bn254::Fr;` in test module.
- `crates/pvthfhe-compressor/tests/multi_input_step_circuit.rs`: updated to 4-element state with ring_verification_count assertions.

### Verification

- `cargo build --workspace`: passes
- `cargo test -p pvthfhe-aggregator --test cyclo_ccs_adapter`: 7/7 passed
- `cargo test -p pvthfhe-compressor`: passes (pre-existing RED `nova_isolated_mem` test excepted)
- `cargo test -p pvthfhe-aggregator --test folding_relation --test cyclo_wire`: passes
- `just demo-e2e`: ACCEPT
- LSP diagnostics: 0 errors across all changed files

### Deferred to M2

- R1CS constraint encoding of RingElement operations (`add`, `sub`, `scale` as FpVar operations)
- CCS matrix construction (`to_ccs_matrix`)
- Actual ring-equation enforcement in R1CS constraints (currently just increments counter)
