# Plan: P2 M1 — Cyclo CCS Adapter for LatticeFold+

**Plan**: `p2-m1-cyclo-ccs-adapter`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-14
**Goal**: Implement the Cyclo CCS constraint system adapter that encodes the frozen P1 verifier equation under ternary challenge space {-1,0,1}, enabling real LatticeFold+ folding (replacing the current hash-then-fold approach in CycloFoldStepCircuit).

---

## Context

### Current state: CycloFoldStepCircuit (hash-then-fold)

The `CycloFoldStepCircuit` in `compressor_glue.rs:41` does NOT perform full Ajtai commitment folding. It hashes the Cyclo accumulator state down to 3 Fr elements (commitment_hash, norm, fold_count) and folds those hashes through Nova. The comment at `compressor_glue.rs:56-60` states:

> "The design intentionally hashes the accumulator down to 3 field elements before entering the IVC because lattice-native folding is infeasible inside a Sonobe Nova step circuit."

This is the Track A surrogate. M1 replaces it with the real Track B folding.

### Target state

A `CycloCCSAdapter` that encodes the P1 verifier equation as a CCS constraint system over the Cyclo commitment ring ($R_{q\_commit}$), enabling native LatticeFold+ folding. The CCS matrix encodes:

$$\text{Verify}(w, x): c \cdot z_s + z_e - t - c \cdot d_i \equiv 0 \pmod{q\_commit}$$

Where $w = (s, e, \rho)$ is the witness, $x = (t, d_i, c)$ is the public statement, and all operations are in the polynomial ring $R = \mathbb{Z}_{q\_commit}[X]/(X^{256}+1)$.

The challenge space is $\{-1, 0, 1\}$ (ternary). Lemma 9 is accepted as a documented assumption for challenge difference invertibility.

### Why the current hash-then-fold works

The hash-and-fold approach is sound because:
1. The hash is deterministic and collision-resistant (SHA-256)
2. The hash is computed BEFORE folding, so the folded commitment matches the pre-image
3. The Nova IVC guarantees the relationship between consecutive hashes

But it incurs a cost: the folding loses the algebraic structure of the Cyclo commitment. The full Ajtai folding (P2) would preserve this structure, enabling tighter proofs and better asymptotic performance.

---

## Implementation

### P2-M1.1 — Understand the CCS encoding target

**File**: New design doc in `.sisyphus/research/p2/ccs-encoding.md`

Document the exact CCS constraint matrix M and vector z encoding the P1 verifier equation:

- **Variables**: the witness vector `z` includes coefficients of `s` (N_commit elements), `e` (N_commit elements), and response terms `z_s`, `z_e` (2N_commit elements), plus auxiliary variables
- **Matrix**: M = [A | B | C] where A multiples with z, B with z°, C with z°° (CCS triple product)
- **Ring**: $R = \mathbb{Z}_{q\_commit}[X]/(X^{256}+1)$ with $N_{commit}=256$
- **Modulus**: $q_{commit} \approx 2^{50}$

### P2-M1.2 — Implement ring arithmetic in CCS

**File**: `crates/pvthfhe-aggregator/src/folding/ccs_adapter.rs` (new)

Build a ring element wrapper over Bn254::Fr that emulates polynomial arithmetic modulo $X^{256}+1$:

```rust
pub struct RingElement<F: PrimeField> {
    pub coeffs: Vec<F>,  // 256 coefficients in Bn254::Fr
}

impl<F: PrimeField> RingElement<F> {
    pub fn add(&self, other: &Self) -> Self;
    pub fn mul(&self, other: &Self, q: F) -> Self; // polynomial multiplication mod X^256+1, scaled by q
    pub fn scale(&self, c: F) -> Self;
    pub fn norm_inf(&self) -> F; // ||coeffs||_∞
}
```

For the ring multiplication $a \cdot b \mod X^{256}+1$, implement a direct O(N²) convolution (N=256, 65,536 multiplications — acceptable for M1) or use NTT if available in the Bn254 field.

### P2-M1.3 — Encode the verifier equation as CCS constraints

**File**: `crates/pvthfhe-aggregator/src/folding/ccs_adapter.rs`

Create `CycloVerifierCCS` that encodes the P1 equation:

```rust
pub struct CycloVerifierCCS {
    pub n_commit: usize,        // 256
    pub q_commit: Fr,           // ≈ 2^50, stored as Fr element
    pub challenge: Fr,          // ternary: -1, 0, or 1
}

impl CycloVerifierCCS {
    /// Verify the equation: c·z_s + z_e - t - c·d == 0 (mod q_commit)
    pub fn verify_equation(&self, witness: &CCSWitness, statement: &CCSStatement) -> bool;
    
    /// Encode as CCS matrix (A, B, C)
    pub fn to_ccs_matrix(&self) -> CCSMatrix;
}
```

### P2-M1.4 — Wire into CycloFoldStepCircuit

**File**: `crates/pvthfhe-compressor/src/sonobe/mod.rs` (CycloFoldStepCircuit)

Replace the hash-and-fold logic with CCS constraint verification:

```rust
impl<F: PrimeField> FCircuit<F> for CycloFoldStepCircuit<F> {
    fn generate_step_constraints(...) -> Vec<FpVar<F>> {
        // 1. Decode external inputs into ring elements
        // 2. Verify the CCS equation: c·z_s + z_e - t - c·d == 0 mod q_commit
        // 3. Update accumulator state: [commitment_hash, norm, fold_count]
        // 4. Return new state
    }
}
```

The constraints now verify the RING equation in R1CS, not just a hash of the state. The ring operations (addition, subtraction, scalar multiplication, polynomial multiply) are expressed as R1CS constraints.

### P2-M1.5 — Tests

**File**: `crates/pvthfhe-aggregator/tests/cyclo_ccs_adapter.rs` (new)

| Test | Description |
|------|-------------|
| `ring_add_identity` | a + 0 == a |
| `ring_mul_commutative` | a * b == b * a (mod X^256+1) |
| `ring_mul_by_challenge_scalar` | c * (a + b) == c*a + c*b for ternary c |
| `verifier_accepts_honest_witness` | Honest (s, e) passes CCS equation |
| `verifier_rejects_wrong_witness` | Tampered s → equation fails |
| `verifier_rejects_wrong_challenge` | Wrong challenge → equation fails |
| `fold_step_roundtrip` | CycleFoldStepCircuit with CCS accepts one step |

### P2-M1.6 — Documentation

- Update `docs/security-proofs/p2/T1.md` — note M1 CCS adapter implementation
- Update `p2-latticefold-target.md` — mark M1 complete
- Update `compressor_glue.rs` comment: note that hash-then-fold is the Track A surrogate; Track B uses CycloCCSAdapter

---

## Acceptance Criteria

- [ ] RingElement<Fr> with add, mul, scale operations
- [ ] CycloVerifierCCS encodes P1 equation as CCS matrix
- [ ] CycloFoldStepCircuit verifies ring equation in R1CS constraints
- [ ] 7 RED tests pass (including fold step roundtrip)
- [ ] Demo ACCEPT (Track A path unchanged)
- [ ] Existing Sonobe tests pass
- [ ] Lemma 9 referenced as accepted assumption

## Non-Goals

- Production NTT (O(N²) convolution is fine for M1 with N=256)
- Full Ajtai commitment folding (requires Com_A, deferred to M4)
- Replacing hash-then-fold (complementary, not replacement)

## Estimated Effort

~1-2 weeks. The ring arithmetic and CCS encoding are the core deliverables. The O(N²) convolution at N=256 (~65K ops) is feasible for M1 proof-of-concept.
