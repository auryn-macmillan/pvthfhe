---
verdict: NoGo
---

# Sonobe-in-UltraHonk feasibility spike

## (a) Sonobe final-proof byte size and verifier-circuit estimated gate count

- Measured closest in-tree Sonobe artifact: `pvthfhe_compressor::sonobe::SonobeCompressor` emits a deterministic 4-step toy Nova IVC proof of **7,129,316 bytes** and verifier key bytes of **2,162,768 bytes** for `(seed=7, acc=3, public_input=7)`.
- The current in-tree Sonobe backend stops at serialized `IVCProof<G1, G2>` bytes; it does **not** produce a Noir verifier circuit, a Sonobe decider proof, or a Noir-consumable BN254/Grumpkin verifier gadget.
- The current Noir workspace has no verifier dependency for Sonobe/Nova/BN254/Grumpkin: `circuits/Nargo.toml` contains only the existing workspace packages, and `circuits/micronova_wrap/Nargo.toml` depends only on `poseidon`.
- Upstream Sonobe evidence points away from a Noir verifier path: `examples/noir_full_flow.rs` uses Rust `NoirFCircuit` as the *folded program frontend*, then performs final verification with Rust `DeciderEth<..., Groth16<Bn254>, ...>` and generates a Solidity verifier. That is not a Noir circuit verifying a Sonobe final proof.
- External Noir ecosystem evidence is also unfavorable. The readily discoverable BN254 pairing implementation `onurinanc/noir-bn254` is experimental, requires a forked `noir-bigint`, targets much older Noir (`0.9.x+`), and reports **~0.5 h compilation time for one pairing on 16 GB RAM**.
- Gate-count estimate for a real Sonobe/Nova wrap is therefore only a principled feasibility estimate, not a measured in-repo number: a practical verifier would need at least pairing-scale BN254 arithmetic plus Grumpkin/Nova state checks, i.e. **orders of magnitude larger than the current 1,150-ACIR-op surrogate** (`nargo info --package micronova_wrap`). Given the external pairing benchmark and missing in-tree gadgets, the realistic risk envelope is **multi-million gates and plausibly beyond the plan's ~2^23-gate NoGo threshold**.

## (b) Actual `nargo execute` + `bb write_vk` + `bb prove` wall time and peak RSS for a minimal wrap

Because no actual Noir Sonobe/Nova verifier library was available, the only executable wrap-like Noir package in-tree is the existing `micronova_wrap` surrogate. I measured that package as a **lower-bound floor**, not as a faithful Sonobe verifier:

| Step | Command | Wall time | Peak RSS |
|---|---|---:|---:|
| witness generation | `nargo execute --package micronova_wrap --prover-name Prover` | **0.16 s** | **89,048 KiB** |
| VK generation | `bb write_vk --scheme ultra_honk -b target/micronova_wrap.json -o target` | **0.05 s** | **20,128 KiB** |
| proof generation | `bb prove --scheme ultra_honk -b target/micronova_wrap.json -w target/micronova_wrap.gz -o target` | **0.14 s** | **32,084 KiB** |

Additional floor measurements for the surrogate:

- `nargo info --package micronova_wrap`: **1,150 ACIR opcodes**.
- `target/proof`: **14,656 bytes**.
- `target/vk`: **3,680 bytes**.
- `target/public_inputs`: **256 bytes**.

These numbers are useful only as a sanity-check lower bound: they show the existing Poseidon-based surrogate is tiny, but they do **not** demonstrate feasibility for a real BN254/Grumpkin Sonobe verifier inside Noir.

## (c) Extrapolation to the full-protocol IVC step count (`N = 8192`, expected ~1000 steps)

- The blocker is not the current surrogate's runtime; it is the absence of a practical Noir verifier for the final Sonobe proof.
- For a final IVC wrap, the expensive part is the verifier relation itself (pairings, big-integer field arithmetic, curve checks, transcript/state binding), not merely the folded-step count. Moving from a toy example to ~1000 folded steps does not eliminate that verifier burden.
- Host capacity is also unfavorable for the only concrete pairing-circuit data point found: this machine has **15 GiB RAM total / 12 GiB available**, while the external `noir-bn254` README already reports **~0.5 h compile time for a single pairing on 16 GB RAM**.
- Since Sonobe's documented happy path today is Rust decider proof generation plus Solidity verification—not Noir verification—the missing implementation surface is larger than a local optimization task. Even before proving time is considered, compile/witness-generation feasibility on this host is not credible.

## (d) Binary verdict and justification

**Verdict: NoGo.**

Justification:

1. No practical Noir Sonobe/Nova final-proof verifier library exists in this repo or current Noir workspace.
2. Sonobe's own example path uses Rust decider logic and Solidity verification, not a Noir verifier circuit.
3. The only discoverable Noir BN254 pairing library is experimental, outdated relative to this toolchain, depends on a forked bigint library, and already reports ~0.5 h compile time for one pairing on a 16 GB machine.
4. This host has less RAM than that external single-pairing benchmark, and a real Sonobe/Nova verifier would require substantially more than one pairing-equivalent component.

Conclusion: a Noir/UltraHonk circuit that verifies a Sonobe Nova final IVC proof on this stack is **not** presently credible to compile, witness-generate, and `bb prove` within available host memory and the ≤4 h wall-time budget. The plan should therefore take the **N3'/N4'/N5' off-chain Sonobe + on-chain commitment fallback path**.
