# P2 Prior-Art Matrix for Folding Schemes and RLWE-Friendly Accumulation

This note surveys folding and accumulation schemes relevant to replacing the current Noir hash-chain surrogate in `circuits/aggregator_final/src/main.nr` with a real recursive accumulator for P1 SLAP proofs. The P1→P2 bundle fixes a verifier relation that is mostly arithmetic but still contains SHA-256 transcript recomputation and bounded-norm checks on `z_e`; the best P2 candidates are therefore schemes that either (a) are lattice-native enough to plausibly absorb RLWE / Ajtai-style commitments, or (b) provide a realistic delivery fallback with acceptable on-chain verification.

## P2 target relation

P2 needs to fold repeated checks of the frozen P1 verifier equation over proofs whose binary layout is:

`[2B version][4B t_len][t_bytes][8B z_s][4B z_e_count][z_e i64s][openings]`

The key selection criteria for prior art are therefore:

1. whether the folding scheme is RLWE- or lattice-native enough to avoid an awkward field/commitment mismatch;
2. whether the recursive verifier can plausibly fit an on-chain checkpoint path;
3. whether the scheme has actually been exercised beyond toy recursion depth;
4. whether there is usable code / a permissive license;
5. whether the scheme is audited or still purely research-grade.

## Prior-art matrix

| Scheme | Year | Paper / Source | RLWE-native? | Verifier-cost-on-chain | Recursion-depth-tested | License | Audit-status | Viable |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nova | 2021 | Kothapalli, Setty, Tzialla, “Nova: Recursive Zero-Knowledge Arguments from Folding Schemes” (ePrint 2021/370); Microsoft `Nova` repo | No — elliptic-curve / Pedersen-style commitments, relaxed R1CS, not lattice-native | Moderate only after compression; raw folding verifier is not an RLWE-friendly on-chain object | Extensive implementation use; production-oriented libraries and many-step IVC demos exist, but paper does not frame a hard depth cap | CC BY paper; repo MIT | No public third-party audit located | fallback |
| SuperNova | 2022 | Kothapalli, Setty, “SuperNova: Proving universal machine executions without universal circuits” (ePrint 2022/1758) | No — extends Nova, still non-lattice | Similar to Nova; on-chain path depends on outer compression, not the folding layer itself | Non-uniform IVC evaluated in paper / code lineage; practical multi-step recursion demonstrated | CC BY paper; inherits MIT-licensed Microsoft code lineage | No public third-party audit located | no |
| HyperNova | 2023 | Kothapalli, Setty, “HyperNova: Recursive arguments for customizable constraint systems” (ePrint 2023/573) | No — CCS folding over curve commitments, not RLWE-native | Better recursion circuit than Nova family, but still not directly attractive for lattice-native on-chain verification | Multi-instance folding and CycleFold-style recursion evaluated; practical recursive experiments reported | CC BY paper; Microsoft `Nova` repo MIT references HyperNova techniques | No public third-party audit located | fallback |
| ProtoStar | 2023 | Bünz, Chen, “ProtoStar: Generic Efficient Accumulation/Folding for Special Sound Protocols” (ePrint 2023/620) | No — generic accumulator over special-sound protocols, but main instantiation is still non-lattice | Good marginal recursive-verifier cost; still needs a non-lattice backend for efficient chain verification | IVC compiler and recursive construction analyzed; concrete depth framed generically rather than via RLWE deployments | CC BY | No public third-party audit located | fallback |
| ProtoGalaxy | 2023 | Eagen, Gabizon, “ProtoGalaxy: Efficient ProtoStar-style folding of multiple instances” (ePrint 2023/1106) | No — general folding from interactive/special-sound proof machinery, not lattice-native | Strong verifier asymptotics (logarithmic marginal work), but concrete chain path still depends on non-lattice commitments | Benchmarks include folding multiple instances per step; recursive depth explored experimentally in the Aztec line | CC0 | No public third-party audit located | fallback |
| LatticeFold | 2024 | Boneh, Chen, “LatticeFold: A Lattice-based Folding Scheme and its Applications to Succinct Proof Systems” (ePrint 2024/257 / ASIACRYPT 2025) | Partial — lattice-native and module-structured, but not explicitly tuned to RLWE P1 verifier plumbing | Plausible long-term, but today still research-grade; verifier simpler than curve-based recursion for PQ settings, yet no mature EVM path | Paper evaluates recursive lattice SNARK/PCD design and compares favorably to HyperNova; many-round folding is a stated design goal | CC BY | No public third-party audit located | primary |
| LatticeFold+ | 2025 | Boneh, Chen, “LatticeFold+: Faster, Simpler, Shorter Lattice-Based Folding for Succinct Proof Systems” (ePrint 2025/247) | Yes-ish — best current match for RLWE-friendly accumulation because it is lattice-native, small-field, and explicitly simplifies verifier/range-proof handling | Best native candidate; still hard for immediate EVM deployment, but simplest verifier among lattice-native rows and closest fit to P2’s foldable arithmetic verifier | Successive folding is core design target; improves prover 5–10× over LatticeFold and shortens folding proofs | CC BY | No public third-party audit located; brand-new research artifact | primary |
| MicroNova | 2024 | Zhao, Setty, Cui, Zaverucha, “MicroNova: Folding-based arguments with efficient (on-chain) verification” (ePrint 2024/2099) | No — KZG / pairing compression, not lattice-native | Strong: explicitly targets Ethereum verification at about 2.2M gas after compression | Concrete recursive implementation with compressed proofs; intended for long incremental computations | CC BY paper; implementation components exposed through Microsoft Nova repo under MIT | No public third-party audit located | fallback |
| NeutronNova | 2024 | Kothapalli, Setty, “NeutronNova: Folding everything that reduces to zero-check” (ePrint 2024/1606) | No — zero-check folding over standard commitments, not RLWE-native | Potentially very good verifier shape, but no lattice-native or audited chain stack yet | Designed for continual folding and multi-instance folding with logarithmic sum-check rounds | CC BY | No public third-party audit located | unknown |
| Rust-in-zkVM IVC (SP1 / RISC Zero) | 2024–2026 | SP1 docs / installer, RISC Zero docs, deployed zkVM ecosystems | No — wrapper approach, proves Rust verifier execution rather than native RLWE folding | High feasibility as delivery fallback: existing verifier contracts / ecosystems make on-chain checkpoints realistic | Deep recursion handled by zkVM / recursion stack; practical deployments exist, though not specialized for lattice folding | SP1 Apache-2.0/MIT; RISC Zero Apache-2.0 | Some ecosystem components receive security review, but no single audit covering “P1 verifier inside zkVM for this repo” | fallback |

## Viability analysis

### Viable primary candidates

1. **LatticeFold+**
   - Best fit to the P2 contract because it is lattice-native, explicitly improves verifier simplicity, and removes one of LatticeFold’s most awkward pieces: expensive bit-decomposition range proofs.
   - The P1 verifier equation is mostly arithmetic plus bounded-norm checks on `z_e`; LatticeFold+ is the clearest current line for keeping those checks in a lattice-native folding world instead of wrapping them in an unrelated commitment system.
   - Main risk: brand-new and unaudited, so it cannot be the only path.

2. **LatticeFold**
   - First scheme in the literature to make folding itself lattice-based rather than merely wrapping a lattice statement in a non-lattice recursive layer.
   - It already targets low-degree and CCS-style relations and explicitly handles low-norm witness preservation across many folds, which is directly relevant to P1’s bounded `z_e` and witness-opening constraints.
   - Main risk: heavier and less polished than LatticeFold+, and still not an immediately deployable on-chain verifier story.

### Viable fallback candidates

1. **Rust-in-zkVM IVC (SP1 / RISC Zero)**
   - This is the delivery fallback preserved by project guidance: instead of waiting for a perfect lattice-native accumulator, P2 can prove the Rust verifier for the frozen P1 proof format and reuse existing on-chain verifier stacks.
   - It directly absorbs SHA-256 transcript recomputation and byte-level deserialization, both of which are currently awkward for a purely algebraic lattice folding circuit.
   - Main downside: gives up the clean native-lattice story and typically pays much worse prover cost.

2. **MicroNova**
   - Best non-lattice “ship it” recursive accumulator in this matrix when verifier cost on Ethereum is the bottleneck: the paper explicitly reports efficient on-chain verification and small compressed proofs.
   - Architecturally, MicroNova is useful if P2 needs a realistic checkpointing path before lattice-native recursion matures; it can host a verifier circuit for the SLAP relation even though it is not RLWE-native.
   - Main downside: relies on KZG/pairing infrastructure and universal setup, so it is a systems fallback rather than a research-endgame fit.

### Overall selection signal for PVTHFHE P2

- **Primary track:** `LatticeFold+` and `LatticeFold`.
- **Fallback track:** `Rust-in-zkVM IVC` and `MicroNova`.
- **Useful comparison rows but not preferred end-state:** `Nova`, `SuperNova`, `HyperNova`, `ProtoStar`, `ProtoGalaxy`, `NeutronNova`.

The decisive repository-specific issue is not just asymptotic folding efficiency; it is whether the scheme can absorb the frozen P1 verifier equation, including SHA-256 transcript binding, exact byte parsing, and bounded `z_e` checks, without making on-chain verification impossible. That pushes the matrix toward a two-track strategy: a **lattice-native primary** (`LatticeFold+`, then `LatticeFold`) and a **deployment fallback** (`Rust-in-zkVM`, then `MicroNova`).
