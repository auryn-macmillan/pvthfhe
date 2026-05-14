# Decisions — P3-M2 MicroNova Compression

## Date: 2026-05-14

### Architecture

1. **Concrete Fr rather than generic**: The task spec uses `ark_bn254::Fr` directly rather than a generic `F: PrimeField` parameter. This matches the Sonobe backend's tight coupling to BN254/Grumpkin cycle and avoids unnecessary generics complexity for M2.

2. **ivc_steps = 1**: Each node fold uses exactly one IVC step, which matches the `prove_steps` API where each pair gets a single `ExternalInputs3`. Alternative (passing all pairs as multiple steps) would require a different compressor with `ivc_steps = total_pairs` but would lose per-pair verification granularity.

3. **XOR identity as parent hash**: The task uses XOR of left and right leaf bytes as the parent hash (identity function for toy implementation). This is a placeholder; a real implementation would use a cryptographic hash (Keccak256 or Poseidon).

4. **Root proof is a separate prove call**: After all pairs are folded, one final `prove_steps` call with zero-valued inputs produces the root `CompressedProof`. This is a toy placeholder; real root would be the last pair-fold proof.

### No changes to existing APIs

- SonobeCompressor API unchanged
- fold_verifier_circuit.rs unchanged
- All existing tests pass
