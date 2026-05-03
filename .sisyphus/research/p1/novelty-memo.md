# P1 Novelty Gap Memo

## Required Novelty
In the PVTHFHE setting, standard textbook lattice zero-knowledge (ZK) proofs fall short because they assume lattice-based commitments (like Ajtai or MLWE). Our system utilizes SHA-256 for PVSS (Publicly Verifiable Secret Sharing) commitments. Specifically, we have $t$-of-$n$ Shamir secret sharing over the field $2^{61}-1$, where the commitment is $H(\text{session\_id} || \text{id} || s_i)$ via SHA-256. 
To prove correctness of the decryption share $d_i = c \cdot s_i + e_i \bmod q$ (with bounded noise $e_i$), we need a **joint proof** linking the algebraic RLWE relation to the boolean SHA-256 commitment under a single Fiat-Shamir transcript.
Furthermore, the construction requires **batch amortization** across $t$ shares to achieve $O(n)$ per-party work, meaning the proof must scale efficiently, and it must support downstream folding in P2 (LatticeFold+ compatibility) to maintain $O(\text{polylog } n)$ verifier cost for the on-chain recursive verification path in P3.

## Aggressive Bets
1. **Poseidon-based Hybrid zkVM Precompile**: Utilize a zkVM (like SP1 or RISC0) with a highly optimized custom precompile for SHA-256 verification and an embedded Plonky3 argument for the RLWE relation. This treats the lattice operations inside the VM, while outputting a SNARK that naturally folds in P2.
2. **Custom Lattice IOP (The "Bridged Extractor" Bet)**: Construct a custom Interactive Oracle Proof where the first message commits to both the SHA-256 transcript and the RLWE share via a joint extractor. This bridges the boolean and algebraic domains directly in the IOP, avoiding heavy generic SNARK machinery for the lattice part.

## Risk Register
- **LatticeFold+ Incompatibility**: The chosen proof system (especially if relying heavily on zkVM) might produce proof formats that are too large or structurally misaligned for LatticeFold+ in P2.
- **On-chain Verification Cost**: If the batch amortization fails to compress the proof sufficiently, the final P3 verifier might exceed EVM gas limits for on-chain verification.
- **Soundness of Joint Extractor**: A custom Lattice IOP bridging SHA-256 and RLWE may have subtle soundness flaws, specifically around the Fiat-Shamir transform binding both domains.

## Pivot Triggers
- **Trigger 1**: If the Custom Lattice IOP requires an extractor that reduces soundness below 100 bits, pivot immediately to the Hybrid zkVM approach.
- **Trigger 2**: If the zkVM precompile approach yields a base proof generation time exceeding 10 seconds for $t=128$, pivot to exploring an Ajtai/MLWE commitment upgrade for the PVSS, deprecating SHA-256 commitments entirely.
