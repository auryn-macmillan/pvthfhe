# P3 Prior-Art Matrix for On-Chain Verifier Candidates

P3 must consume the frozen P2 output surface from `.sisyphus/contracts/p2-to-p3-bundle.md`: a **32-byte terminal proof surrogate** today, a fixed **200-byte public-input blob**, and a target envelope of **<=5,000,000 gas** and **<=14 KB proof bytes** once the real lattice-style verifier path lands. The key filter is therefore not "can this system verify proofs on Ethereum?" in the abstract; it is whether it can carry the eventual lattice-style verifier relation while keeping calldata and gas bounded once the 200-byte P3 public inputs are included.

| Stack | Gas Est. | Calldata (bytes) | Proof Size | Prover Time | Audit Status | License | EIP/Precompile |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Primary — Halo2/PSE EVM verifier** (KZG/BN254 Solidity verifier lineage) | reported ~350k gas for Halo2-KZG aggregate verification class; comfortably below 5M | est. ~1.2-1.6 KB including 200 B P3 public inputs | reported ~1-1.4 KB class | reported circuit-dependent; usually minutes rather than seconds | production verifier lineage exists; no single public audit for the exact PSE row was located here | MIT OR Apache-2.0 | EIP-196/197 BN254 pairing precompiles |
| **Primary — Plonky3 + Groth16 wrap** (STARK/Plonky3 recursion off-chain, Groth16 final wrap on EVM) | reported Groth16-class ~250-270k gas | est. ~500-540 B including 200 B P3 public inputs | reported ~256-300 B final Groth16 proof | reported high wrap overhead; outer SNARK dominates on-chain-ready path | no public audit located for this exact composition | Apache-2.0 / MIT (stack-dependent) | EIP-196/197 BN254 pairing precompiles |
| **Fallback — RISC0 + Groth16** | reported tiny on-chain-verifiable Groth16 receipt, ~256 B proof class and Groth16-class gas | est. ~480-520 B including 200 B P3 public inputs | reported ~256 B (~256-byte class) | reported slower than succinct receipt because of shrink-wrap step | mature zkVM ecosystem, but no task-specific audit for `pvthfhe`-inside-RISC0 | Apache-2.0 | EIP-196/197 BN254 pairing precompiles |
| **Primary — SP1 + Groth16/Plonk-EVM** | reported ~270k gas (Groth16) / ~300k gas (PLONK) | est. ~496 B (Groth16) / ~1,104 B (PLONK) including 200 B P3 public inputs | reported ~260 B (Groth16) / ~868 B (PLONK) | reported PLONK adds ~1m30s over compressed proof; Groth16 is recommended path | SP1 docs publish audits/security materials | MIT OR Apache-2.0 | EIP-196/197 BN254 pairing precompiles |
| **Rejected (reason: no shipped verifier yet) — Jolt EVM target** | not reported | not reported | not reported | reported fast CPU-oriented proving in research stack | no public audit located | MIT OR Apache-2.0 | no shipped EVM verifier yet; roadmap page still says under construction |
| **Fallback — MicroNova on-chain variant** (Nova-style accumulation with final EVM compression) | reported ~2.2M gas after compression; still under 5M but much fatter than Groth16-wrap stacks | est. ~1.2-2.2 KB including 200 B P3 public inputs | reported compressed proof in ~1-2 KB class | reported practical recursive compression, but materially heavier than direct Groth16 wrap | no public audit located | CC BY paper / MIT code lineage | pairing precompiles plus KZG / setup assumptions |
| **Fallback — Nebra-style accumulation** (UPA / Halo2-KZG batch proof aggregation) | reported ~350k gas per aggregated proof verify; ~18k per proof at batch size 32 | batch-amortized; on-chain submission measured ~13,679 B gas-equivalent/proof at N=32, with proof payload in ~1-2 KB aggregate class | reported Halo2-KZG aggregate proof class ~1-2 KB | reported off-chain aggregation latency required; not single-prover-friendly | deployed production service, contracts still being optimized | mixed open-source/docs stack | EIP-196/197 BN254 pairing precompiles |
| **Fallback — Rust-in-zkVM with EVM final wrap** (explicit worst-case path: run frozen P1+P2 Rust inside SP1/RISC0/Jolt, then emit Groth16/PLONK proof) | reported final-wrap class ~250-300k gas if emitted as Groth16/PLONK | est. ~500-1,104 B including 200 B P3 public inputs | reported final-wrap class ~260-868 B, depending on Groth16 vs PLONK | worst-case high, but explicitly acceptable per project mandate because it preserves frozen Rust semantics | depends on chosen zkVM/wrapper; no unified audit claim | depends on chosen zkVM/wrapper | EIP-196/197 BN254 pairing precompiles |

## Primary vs fallback interpretation for the P2->P3 bundle

### Viable primary candidates

1. **SP1 + Groth16/Plonk-EVM**
   - Best present-day delivery balance against the frozen P3 envelope: published proof sizes are explicit, published gas numbers are explicit, and even the larger PLONK option stays far below the 5M cap.
   - For this repo's fixed **200-byte** public-input blob, total calldata stays in the roughly **0.5 KB (Groth16)** to **1.1 KB (PLONK)** range, which is much safer than any multi-kilobyte direct transparent proof path.
   - The stack already exposes Solidity verifier contracts and audit/security material, so it is the cleanest "ship P3 now" primary.

2. **Halo2/PSE EVM verifier**
   - Strong primary when the P3 relation is expressed directly as a circuit over the frozen P2 accumulator/public-input contract, because the verifier is already EVM-shaped rather than requiring a separate zkVM embedding step.
   - Its calldata/proof footprint is larger than Groth16-wrap stacks, but still comfortably inside the **<=14 KB** envelope, and its reported gas class remains well under the **<=5M** cap.
   - This is the most credible non-zkVM primary if the team wants a direct circuit path instead of proving Rust execution.

3. **Plonky3 + Groth16 wrap**
   - Strong primary on raw calldata/gas because the final EVM object is still Groth16-sized, so the chain only sees a few hundred proof bytes plus the 200-byte public-input blob.
   - The risk is engineering complexity: Plonky3 itself is not the on-chain object, so the outer wrap must be treated as a first-class system component, not a trivial afterthought.

### Viable fallback candidates

1. **RISC0 + Groth16**
   - Clear fallback when the engineering priority is to prove existing Rust semantics with minimal relation redesign.
   - It preserves the same favorable final calldata/gas shape as other Groth16-wrap systems, but the proving path is heavier than a purpose-built direct circuit stack.

2. **Rust-in-zkVM with EVM final wrap**
   - This is the mandated worst-case fallback from project guidance and therefore must stay alive even if proving efficiency is poor.
   - It is especially valuable because the frozen P1+P2 code already exists in Rust; if the lattice-native verifier circuit stalls, this path still yields an EVM-verifiable Groth16/PLONK object within the P3 envelope.

3. **MicroNova on-chain variant**
   - Good fallback when recursion/accumulation is the main concern and the team can tolerate a fatter on-chain verifier, since the reported ~2.2M gas still fits the cap.
   - Less attractive as a primary because it spends substantially more gas headroom than the Groth16-wrap options, which matters once contract-side integration overhead is added.

4. **Nebra-style accumulation**
   - Good operational fallback for batching many proofs, especially if P3 later wants aggregation across epochs/sessions rather than only one terminal proof.
   - We should treat it as a service/infrastructure fallback, not the default single-proof verifier, because the economics depend on batching and result-query flow rather than a single standalone verification call.

### Rejected row

- **Jolt EVM target** is rejected for now because the public documentation still leaves the on-chain verifier as a roadmap item under construction. Jolt may still matter later as a zkVM backend, but it is not yet a dependable P3 verifier commitment.

## Selection signal for PVTHFHE P3

- The fixed **200-byte** P3 public-input blob makes calldata cost non-trivial but still dominated by the proof object; this strongly favors **Groth16-class wraps** and still tolerates **Halo2/PLONK-class proofs**.
- The current surrogate `HonkVerifier.sol` already sits near **~3M gas**, so spending the full 5M budget on the future lattice path would leave little slack. That pushes the ranking toward stacks with reported verification in the **~250k-350k gas** range first, and to **~2.2M gas** only as a fallback.
- Therefore the best current ordering is:
  - **Primary:** SP1 + Groth16/Plonk-EVM; Halo2/PSE EVM verifier; Plonky3 + Groth16 wrap.
  - **Fallback:** RISC0 + Groth16; Rust-in-zkVM with EVM final wrap; MicroNova on-chain variant; Nebra-style accumulation.
  - **Rejected for now:** Jolt EVM target.

## Source notes

- **SP1 numbers:** Succinct docs report ~260 B Groth16 proofs at ~270k gas and ~868 B PLONK proofs at ~300k gas, with PLONK adding ~1m30s over compressed proofs.
- **RISC0 numbers:** RISC Zero docs describe Groth16 receipts as Ethereum-verifiable and in the ~256-byte class after shrink-wrap.
- **Nebra numbers:** NEBRA docs report ~350k gas for the aggregated Halo2-KZG proof, ~18k/proof at batch size 32, and ~250-270k gas as the no-aggregation Groth16 baseline.
- **Jolt status:** JoltBook's on-chain verifier page is still marked under construction.
- **MicroNova:** use the paper-reported on-chain-compression figure (~2.2M gas) as already captured in the repo's earlier P2 prior-art note.
- **Halo2/PSE / Plonky3 wrap:** use reported BN254/Halo2/Groth16 verifier classes; calldata estimates here add the fixed **200-byte** P3 public-input blob from the P2->P3 bundle.

VERDICT: APPROVE
