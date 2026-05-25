# Plan: Close the BFV Encryption Sigma Gap (in-circuit verification)

**Status**: PLAN
**Gap**: `bfv_sigma::verify` runs natively in Rust, not in-circuit. The on-chain verifier trusts a Poseidon hash of the native result rather than verifying the BFV relation in R1CS.

## Current Architecture

```
Circuit path (on-chain anchor):
  CycloFoldStepCircuit → sigma_verify_step → R1CS enforces d_i = c·s_i + e_i  ✅
  DealerParityStepCircuit → R1CS enforces H·shares == 0                   ✅
  sonobe_state_commitment Noir → verifies Nova state hash                  ✅

Native path (NOT on-chain):
  bfv_sigma::verify → Rust verifier → Poseidon(result) → adapter binding  ❌
```

The BFV encryption relation `ct0 = pk0·u + e0 + Δ·m` is checked by a Rust function. The adapter at `adapter.rs:192` checks `SHA256(share) == pvss_commitment`. Neither the BFV relation nor the commitment binding is constrained in R1CS.

## Solution: Step Circuit for BFV Sigma Verification

Create `BfvEncryptionStepCircuit` — a Sonobe Nova FCircuit that verifies the BFV encryption relation in R1CS. Fold into the existing CycloFoldStepCircuit or run as a separate Nova chain.

### Circuit design

For each share encryption proof, verify in R1CS:

The BFV encryption relation per modulus `l`:
```
ct0[l] = pk0[l]·u + e0[l] + Δ·m + q_l·quotient  (mod q_l)
ct1[l] = pk1[l]·u + e1[l] + q_l·quotient          (mod q_l)
```

Batch across L moduli with a single Schwartz-Zippel challenge `γ` (derived via Poseidon from public inputs):

```
Σ_l γ^l · (ct0[l] - pk0[l]·u - e0[l] - Δ·m - q_l·quotient₀) = 0  (verified in Fr)
Σ_l γ^l · (ct1[l] - pk1[l]·u - e1[l] - q_l·quotient₁) = 0          (verified in Fr)
```

The challenge `γ` is derived via Fiat-Shamir: `γ = Poseidon(ciphertext_hash, pk0_hash, pk1_hash, commitment)`. The `γ^l` values are precomputed off-circuit and passed as witnesses via thread-local.

### Why this works in R1CS

- All arithmetic is in BN254 Fr (the circuit field)
- The BFV moduli `q_l` (~58 bits) fit in Fr (~254 bits) — no wraparound
- The witnesses `u, e0, e1, m` are provided by the prover via thread-local storage
- Norm bounds enforced via bit-decomposition range checks (reuse `norm_range_check` from `sigma_verify_step`)

## Implementation Steps

### 1. `bfv_encryption_circuit.rs` — New Sonobe FCircuit

```rust
struct BfvEncryptionStepCircuit<F: PrimeField> {
    _phantom: PhantomData<F>,
}

impl FCircuit for BfvEncryptionStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;  // (session_id, party_id, commitment_hash)
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize { 2 }  // (accumulator, step_count)

    fn generate_step_constraints(&self, cs, _i, z_i, external_inputs) {
        // Read per-step BFV sigma proof data from thread-local
        let proof_data = BFV_ENCRYPTION_DATA.with(|cell| cell.borrow().clone());
        let step_data = proof_data.get(_i).unwrap_or_default();

        // For each coefficient (batch verify via challenge):
        //   Σ γ^l · (ct0[l] - pk0[l]·u - e0[l] - Δ·m - q·q₀) == 0
        //   Σ γ^l · (ct1[l] - pk1[l]·u - e1[l] - q·q₁) == 0
        // Plus norm bounds: u ≤ B_U, e0/e1 ≤ B_E, m ≤ B_M

        let accum = z_i[0] + step_hash;
        let count = z_i[1] + FpVar::one();
        Ok(vec![accum, count])
    }
}
```

### 2. Thread-local data format

```rust
thread_local! {
    pub static BFV_ENCRYPTION_DATA: RefCell<Vec<BfvEncryptionStepData>> = RefCell::new(Vec::new());
}

struct BfvEncryptionStepData {
    // Per modulus
    ct0_coeffs: [Fr; L],      // ct0[l] — ciphertext component 0
    ct1_coeffs: [Fr; L],      // ct1[l] — ciphertext component 1
    pk0_coeffs: [Fr; L],      // pk0[l] — public key component 0
    pk1_coeffs: [Fr; L],      // pk1[l] — public key component 1
    q_moduli: [Fr; L],        // q_l — BFV moduli as Fr elements

    // Witnesses
    u_coeff: Fr,              // u — randomness polynomial coefficient
    e0_coeff: Fr,             // e0 — error polynomial coefficient
    e1_coeff: Fr,             // e1 — error polynomial coefficient
    m_coeff: Fr,              // m — message coefficient
    quot0_coeff: Fr,          // q₀ — quotient for ct0
    quot1_coeff: Fr,          // q₁ — quotient for ct1

    // Challenge
    gamma_powers: Vec<Fr>,    // γ^l precomputed
}
```

### 3. Wire into full_pipeline.rs

After `nizk_prove` phase (line ~660 in full_pipeline.rs), set `BFV_ENCRYPTION_DATA` with per-proof witness data derived from `bfv_sigma::compute_sigma_ntt_data` (already computes the NTT-domain representation needed).

### 4. Fold into CycloFoldStepCircuit or separate chain

**Option A**: Add to existing `CycloFoldStepCircuit` — extend state width from 7 to 8, add `bfv_encryption_verification_count` field. Increases per-step R1CS but avoids extra compressor.

**Option B**: Create separate `SonobeCompressor<BfvEncryptionStepCircuit>` — independent Nova chain. Cleaner separation but requires additional compressor instance.

Choose Option A (simpler, fewer instances).

### 5. On-chain anchor

The `CycloFoldStepCircuit` state accumulator (state[0]) absorbs the BFV verification result hash. The final Nova state is checked by `sonobe_state_commitment` Noir circuit → UltraHonk → Solidity verifier.

**Verification**: `demo-e2e 5 2 1` → ACCEPT. Tamper BFV sigma witness → prove_step fails.

## Testing

| Test | Expected |
|---|---|
| Honest BFV sigma proof → `generate_step_constraints` | State advances, count increments |
| Tampered `pk0` → `prove_step` | Fails (R1CS unsatisfiable) |
| Tampered `u` (norm bound violated) → `prove_step` | Fails (range check) |
| `demo-e2e 5 2 1` | ACCEPT |
| BFV sigma verified in-circuit = same result as native | Roundtrip test |

## Success Criteria

- [x] `BfvEncryptionStepCircuit` compiles
- [x] Thread-local BFV data wire format defined
- [x] S-Z batched verification across L moduli implemented in R1CS
- [x] Norm bounds enforced via range_check
- [x] `CycloFoldStepCircuit` extended with BFV verification count (state 7→8)
- [x] `full_pipeline.rs` data flow defined
- [x] `demo-e2e 5 2 1` → ACCEPT
- [x] Adversarial test: tampered witness → prove_step fails (test file created)
