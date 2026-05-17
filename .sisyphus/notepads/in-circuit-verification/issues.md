# Issues: G2 Implementation

## Resolved

### 1. Type conversion: ark_bn254::Fr → F: PrimeField
- **Symptom**: Cannot use `F::from(v.into_bigint())` because generic `F` doesn't guarantee `From<ark_bn254::Fr::BigInt>`
- **Fix**: Serialize to bytes via `CanonicalSerialize`, deserialize via `F::from_le_bytes_mod_order`

### 2. collect() type inference failure
- **Symptom**: `Iterator<Item=Vec<u8>>` cannot be collected into `Vec<u8>`
- **Fix**: Use `flat_map` to flatten nested byte vectors before collecting

### 3. Missing trait imports
- **Symptom**: `FpVar::new_witness`, `enforce_equal` not found
- **Fix**: Added `use ark_r1cs_std::alloc::AllocVar` and `use ark_r1cs_std::eq::EqGadget`

### 4. FpVar::constant causes incompatible constraint matrices
- **Symptom**: Proving succeeds, Nova verification fails with `Ok(false)`
- **Root cause**: Different constant values in R1CS B-matrix between preprocessing (zero) and proving (real r^j)
- **Fix**: Changed r-powers from constants to witnesses

### 5. Horner evaluation direction mismatch
- **Symptom**: Real-coefficient test fails verification (eval_poly_bn254 ≠ circuit evaluation)
- **Root cause**: Horner computes c₀·r^{N-1}, circuit computed c₀·r⁰ (reversed)
- **Fix**: Use power index `N_COEFFS-1-j` in dot product

## Open

None.
