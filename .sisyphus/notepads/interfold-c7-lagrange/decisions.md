
# Porting Decisions for Interfold

*Recorded: 2026-05-25*

## Pattern to Replicate
The dual-mode Lagrange pattern from `aggregator_final` should be replicated in the Interfold circuit:

1. Accept `lagrange_coeffs: pub [Field; MAX_PARTICIPANTS]` as a public input
2. Dual-mode: use precomputed when `lagrange_coeffs[0] != 0`, compute in-circuit otherwise
3. Assert Σ λ_i == 1
4. Reconstruct plaintext/shares via weighted sum: `Σ λ_i · share_i`
5. Pad unused slots in the MAX_PARTICIPANTS array with zeros

## Key Constants to Replicate
- `MAX_PARTICIPANTS`: match the Interfold circuit's expected maximum
- `N` (ring dimension): 8 for prototype, 8192 for production
- `DOMAIN_VECTOR_MERKLE` and other domain tags from `protocol_constants`

## Rust-side Pattern
- `compute_lagrange_coeffs_bn254(xs: &[Fr], eval_point: Fr) -> Vec<Fr>` computes off-circuit
- Prover.toml generation must write exactly MAX_PARTICIPANTS entries
- Party IDs must be 1-based distinct non-zero values

