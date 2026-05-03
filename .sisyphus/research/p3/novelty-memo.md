# P3 Novelty Gap Memo

## Gap (a): On-chain accumulator verification within gas budget
Currently, verifying P2's folded accumulator directly on the EVM within the allocated ≤5M gas budget is impossible with native opcodes. The accumulator evaluation entails significant polynomial commitments and large-modulus arithmetic that far exceed the EVM execution limits if performed naively. The existing `HonkVerifier.sol` uses ~3M gas merely for the 32-byte surrogate proof. We need a verifiable folding sequence or a highly optimized accumulation verifier that fits within this gas envelope.

## Gap (b): Lattice-native EVM operations
There is no native support for large-modulus (lattice-native) arithmetic in the EVM. Implementing this in Solidity would result in astronomical gas costs. We require either a SNARK wrapper that translates lattice-based accumulation steps into EVM-friendly pairings (e.g., BN254), or a novel EVM precompile that directly supports these operations.

## Gap (c): Batched session verification
While verifying a single FHE session is challenging, batching verification across multiple FHE sessions introduces further complexity. The gap lies in aggregating multiple accumulator proofs into a single verifiable instance on-chain without linear growth in verification cost or proof size. The protocol must maintain the ≤14KB proof size constraint even when batching.

## Gap (d): Trust assumptions
Avoiding a trusted setup per protocol is critical. The current EVM verification landscape relies heavily on pairing-friendly curves with trusted setups (like KZG). We need transparent, post-quantum or non-trusted-setup mechanisms that can still be efficiently verified on-chain, or bridge via recursion to a generic universal setup.

## Aggressive Bets
- **STIR/WHIR Final-Step Recursion**: Leveraging recent advances like STIR or WHIR to recurse the lattice-based folded accumulator into a pairing curve (like BN254) in the final step. This allows for transparent, high-efficiency accumulation off-chain, coupled with a standard EVM-friendly groth16/plonk verifier on-chain.
- **Novel Cycle-of-Curves for RLWE**: Exploring a cycle-of-curves uniquely adapted for RLWE arithmetic, bridging the gap between the lattice operations and standard EVM curves without falling back to a heavyweight zkVM.

## Pivot Triggers
If the recursive wrapper using STIR/WHIR exceeds the ≤14KB proof size constraint, or if translating the RLWE accumulator to an EVM-friendly SNARK results in unmanageable prover times (exceeding protocol latency bounds). This would force a fallback to the "Rust-in-zkVM" approach, generating a standard STARK/SNARK of the Rust verification execution.

## VERDICT: APPROVE
