# P1 Trait Sketch — `LatticeNizk`

This is a design excerpt only. It freezes the Rust-facing trait shape without adding source code to the workspace.

```rust
use rand_core::RngCore;

pub trait LatticeNizk {
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError>;

    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}
```

## Notes

- `NizkStatement` binds `c`, `d_i`, the inherited 32-byte PVSS commitment hash, FHE params `(q, N, B_e)`, `session_id`, and `participant_id`.
- `NizkWitness` binds `s_i`, `e_i`, and prover randomness `r_i`.
- `NizkProof` is an opaque deterministic-bytes proof object with recursion-oriented metadata.
- No Noir-specific types, backend verifier contracts, circuit wires, or proof-system-internal labels appear in this trait.
