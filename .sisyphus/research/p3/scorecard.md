# P3 Candidate Scorecard

This scorecard ranks the P3 verifier candidates against the frozen constraints for the P2→P3 bundle: gas ≤5,000,000, proof payload well below the 14 KB cap once the fixed 200-byte public-input blob is included, no primary that depends on landing a new EIP without a non-EIP fallback, explicit treatment of trusted-setup posture, preference for post-quantum-friendly internals where practical, and enough maturity to avoid letting verifier engineering dominate the phase.

| stack | gas estimate | calldata bytes | proof size | trusted-setup posture | PQ-safe | audit maturity | novelty cost | SCORE |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| SP1 + Groth16 wrap | ~270k gas | ~496 bytes | ~260 bytes | Groth16 wrapper adds trusted setup, but deploys on existing BN254 precompiles with no EIP dependency | partial / mixed | strongest published audits/security materials among current candidates | medium | 27 |
| Rust-in-zkVM with EVM final wrap | ~250k-300k gas | ~500-1,104 bytes | ~260-868 bytes | wrapper-dependent trusted setup; still deployable on existing precompiles without new EIPs | partial / mixed | depends on chosen zkVM, but delivery path is explicit and robust | low-medium | 25 |
| RISC0 + Groth16 | ~250k-270k gas | ~480-520 bytes | ~256 bytes | Groth16 shrink-wrap adds trusted setup on existing BN254 precompiles | partial / mixed | mature zkVM ecosystem, but less direct than generic Rust-in-zkVM fallback | medium | 23 |
| Halo2/PSE EVM verifier | ~350k gas | ~1.2-1.6 KB | ~1.0-1.4 KB | setup-based/KZG lineage on existing BN254 precompiles | no | meaningful production lineage, though not a task-specific audited instantiation | medium | 22 |
| Plonky3 + Groth16 wrap | ~250k-270k gas | ~500-540 bytes | ~256-300 bytes | transparent inner stack but Groth16 wrapper still introduces trusted setup; no EIP dependency | partial / mixed | low for the exact composition | high | 21 |
| MicroNova on-chain variant | ~2.2M gas | ~1.2-2.2 KB | ~1-2 KB | compression path carries setup assumptions but does not need a new EIP | no | low-medium | high | 18 |
| Nebra-style accumulation | ~350k aggregated gas | batch-amortized; ~1-2 KB aggregate payload | ~1-2 KB aggregate proof | Halo2-KZG/setup-based service path using existing precompiles | no | production service exists, but single-proof path is less aligned | high | 17 |
| Jolt EVM target | unshipped | unshipped | unshipped | verifier path not shipped; cannot count as a timed delivery commitment | partial / mixed | low | very high | 8 |

## Primary: SP1 + Groth16 wrap

Freeze SP1 + Groth16 wrap as the primary because it sits far below the gas and proof/calldata ceilings, has the cleanest present-day Solidity verifier path, and does not depend on landing any new EIP or lattice-native precompile during the P3 schedule. Its trusted-setup cost is real, but that assumption is already captured by T3 and is a better trade than betting the primary on unshipped infrastructure.

## Fallback: Rust-in-zkVM with EVM final wrap

Freeze Rust-in-zkVM with EVM final wrap as the fallback because it is the explicit worst-case path endorsed by project guidance and the most defensible non-EIP escape hatch if direct circuit work or wrapper novelty stalls. It preserves exact Rust semantics from the frozen upstream verifier surface while keeping the final on-chain object in the same pairing-precompile class as the primary.
