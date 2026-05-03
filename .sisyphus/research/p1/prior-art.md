# P1 Prior-Art Matrix for Lattice NIZK Candidates

This note surveys prior art for proving knowledge of RLWE/Module-LWE-style secrets and decryption-share correctness for the P1 relation inherited from the frozen P4→P1 bundle.

## Target relation for PVTHFHE P1

The inherited P4 bundle is still a simulation artifact: shares are Shamir field elements over `2^61-1` with SHA-256 commitments, while the intended P1 relation is closer to a lattice statement of the form:

- `share s_i is consistent with the published PVSS commitment / transcript`, and
- `d_i = c · s_i + e_i mod q` with bounded error `e_i`, plus bounded witness norms and transcript binding.

Accordingly, the most relevant proof systems are those that can handle:

1. linear relations over Module/Ring-LWE secrets,
2. short-secret / bounded-norm constraints,
3. Fiat-Shamir transcript binding,
4. recursion-friendly verification for downstream P2 folding, and
5. verifier cost that does not obviously rule out an on-chain checkpoint.

All concrete metrics below are either from the cited line of work when the paper reports them, or are labeled **est.** / **TBD** when only asymptotics or adjacent-system benchmarks are available. The matrix intentionally distinguishes **proof-of-knowledge / argument** from **simulation-soundness**; many lattice PoKs are *not* simulation-sound by default.

## Prior-art matrix

| Scheme | Citation / year | Security notion / sim-sound? | Assumption | Prover time | Proof size | Verifier time | ROM / QROM | PQ? | Recursion-friendly? | On-chain feasibility | License / code | Fit for P1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Lyubashevsky Σ-protocol + Fiat-Shamir | Lyubashevsky 2009/2012 identification-to-signature / lattice Σ-PoK line | PoK via Σ-protocol; FS NIZK/argument in ROM/QROM variants; **not simulation-sound by default** | SIS / M-SIS / LWE depending instantiation | Quasi-linear to linear in witness dimension; several NTT/sample rounds | Typically large: tens to hundreds of KB for non-trivial vector statements (**est.**) | Linear-ish in statement size; much cheaper than prover but still arithmetic-heavy | ROM; many analyses also in QROM | Yes | Weak: verifier is algebra-heavy and not naturally folding-friendly | Poor directly on-chain; better as inner primitive only | Mostly papers/reference prototypes; no standard production library | **Fallback** — excellent baseline for bounded linear relations, but too bulky and too non-succinct for the final verifier target |
| LANES / LNS19 | Lyubashevsky-Nguyen-Seiler, ASIACRYPT 2019 | Statistical/perfect ZK argument of knowledge for linear relations; **not simulation-sound by default** | Module-SIS / Module-LWE style linear-relation assumptions | Quasi-linear prover with improved amortization for linear algebra | Reported as substantially smaller than older lattice Σ-proofs; still usually tens to low hundreds of KB depending dimension (**paper-dependent**) | Near-linear / sublinear in matrix dimensions; practical verifier, not succinct | ROM | Yes | Medium: better transcript shape than plain Σ-proofs, but still not a succinct recursive object | Direct EVM use unlikely; off-chain verifier plausible | Paper / academic code only, license unclear | **Viable fallback** — good direct fit to linear-relations-and-boundedness P1 witness, but verifier is still too heavy for the cleanest recursion path |
| LNS21 compressed / follow-on lattice arguments | Lyubashevsky-Nguyen-Seiler follow-on line, 2021 | Argument / PoK for richer lattice relations; **simulation-soundness generally absent unless added externally** | Module-SIS / Module-LWE | Similar to LNS19 but with better amortization / richer constraints | Usually in the same broad bucket: compact for lattices but not SNARK-succinct; tens-to-hundreds KB (**est.**) | Better than prover, still non-trivial FFT/NTT/hash work | ROM / QROM depending theorem statement | Yes | Medium | Same as above: plausible off-chain verifier, not attractive as raw on-chain verifier | Academic prototypes / unclear | **Fallback** — a stronger direct-lattice option than plain FS Σ-proofs, but still not obviously the primary recursive path |
| Esgin et al. MatRiCT / short-message lattice ZK | CCS 2019 and related short-message proofs | ZK argument / PoK for committed short messages; **not inherently simulation-sound** | SIS / Ring-SIS / M-SIS depending commitment layer | Quasi-linear to superlinear due to commitment opening and batching | Compact relative to older lattice ZK for short messages; often tens of KB for short statements, larger once lifted to RLWE-share relations (**est.**) | Verifier practical for short-message openings; grows when relation is widened to decryption-share correctness | ROM | Yes | Medium-low: better as a subcomponent for commitment/opening than as the whole P1 proof | Weak directly on-chain except for tiny statements | Paper / prototype, license unclear | **Watchlist** — useful if P1 is decomposed into commitment/opening plus separate linear-relation proof |
| Beullens one-shot lattice ZK | Beullens, CRYPTO 2023 / ePrint 2023/306 line | One-shot ZK / argument-of-knowledge flavor for lattice relations; **not simulation-sound by default** | SIS / M-SIS / code-based-style one-shot compression techniques adapted to lattices | Designed to cut interaction and reduce prover rounds; quasi-linear-ish prover with heavy hashing / linear algebra | Attractive for lattices: often discussed in the few-tens-to-low-hundreds KB regime rather than MB-scale (**est.**) | Moderately light verifier relative to older lattice ZKs | ROM | Yes | **Medium-high**: transcript is flatter and easier to wrap recursively than classic many-round Σ-proofs | Raw EVM verification still hard, but much closer to “outer proof wraps inner proof” territory | Paper / research code if available; no stable library standard | **Viable primary** — one of the best direct-lattice candidates if we insist on a native lattice proof rather than a zkVM |
| Bootle–Lyubashevsky–Seiler short-secret PoK | EUROCRYPT 2020 | PoK for short / bounded secrets; **not simulation-sound by default** | SIS / Module-SIS / short-secret assumptions | Efficient for norm-bounded witness proofs; prover scales roughly with vector length and bound checks | Proofs smaller than generic lattice ZK for short-secret statements; still not tiny for full RLWE-share relations (**est.:** tens of KB) | Verifier practical off-chain; arithmetic-heavy on-chain | ROM | Yes | Medium: especially useful as an inner gadget for norm bounds in a recursive wrapper | Poor as standalone on-chain proof; good as subproof | Paper / prototype | **Watchlist** — highly relevant to the bounded-`s_i` / bounded-`e_i` part of P1, likely as a component rather than the full proof system |
| Albrecht–Lai lattice SNARGs | Albrecht-Lai, CRYPTO 2021 / ePrint 2021/863 | Succinct argument / SNARG; simulation-soundness depends on transform/compilation, **do not assume it automatically** | Lattice assumptions (e.g. Module-LWE / SIS flavored assumptions in the construction) | Heavy prover with polynomial-commitment / PCP-style overhead; superlinear constants likely | Succinct compared with native lattice Σ-proofs; concrete proof sizes are paper-specific and still not “free” (**TBD in repo notes**) | Succinct / polylog-style verifier target is the main attraction | Usually ROM / FS-compiled argument | Yes | **High in principle**: succinct verifier makes it friendlier to recursion than classic lattice PoKs | Better than native lattice Σ-proofs if engineering exists, but concrete constants remain a major risk | Mostly paper / no mature ecosystem known | **Viable fallback** — architecturally appealing, but too immature / under-benchmarked to make the default choice today |
| Lattice Bulletproofs | Bootle-Cerutti-Lyubashevsky-style logarithmic inner-product / range-proof adaptations | Argument / PoK; **not simulation-sound by default** | SIS / Ring-SIS / IPA-style assumptions over lattice commitments | Prover quasi-linear with large constant factors from repeated inner-product reductions | Logarithmic-ish in number of constraints, but constants remain high; often tens-to-hundreds KB for realistic lattice vectors (**est.**) | Verifier logarithmic rounds but still arithmetic-heavy | ROM | Yes | Medium: inner-product structure is recursion-compatible in spirit, but concrete lattice versions remain expensive | Weak as a direct EVM verifier; could be wrapped | Paper / prototype | **Watchlist** — promising if the P1 statement is dominated by norm/range proofs and can be aggressively batched |
| SLAP (Short Lattice Argument of Plaintext) | ePrint 2023/1352 line | Short argument for plaintext knowledge / correctness; **simulation-soundness not default** | Module-LWE / Ring-LWE + commitment assumptions | Tailored prover for plaintext/ciphertext consistency checks | Shorter than generic lattice ZK for plaintext-style relations; concrete sizes vary by parameter set (**est.:** low-hundreds KB or below for medium instances) | Better than generic relation proofs for ciphertext/plaintext correctness | ROM | Yes | **Medium-high**: directly relevant to “ciphertext/share/plaintext consistency” relations | Off-chain plausible; on-chain still likely needs outer wrapper | Research code / unclear license | **Viable primary** — one of the better fits if P1 is phrased as ciphertext/share/plaintext consistency with bounded noise |
| Greyhound | ePrint 2024/1037 line | Transparent lattice argument / IOP-style proof; simulation-soundness depends on outer transform, **not automatic** | Lattice commitments + transparent IOP assumptions (FRI/sumcheck-like transparent layer) | Quasi-linear prover with hash/low-degree overhead | Typically larger than classic SNARKs but materially more structured than old lattice ZKs; tens-to-hundreds KB to low MB depending security (**est.**) | Polylog-ish / hash-heavy verifier is the key benefit | Transparent FS/ROM | Yes | **High**: transparent transcript, recursion story, and hash-based verifier are promising for P2 consumption | Direct EVM verifier still non-trivial but more plausible than raw lattice Σ-proof verification | Early research code only / unclear | **Viable primary** — strongest transparent-native route if we want recursion-friendly verification without abandoning lattice relations |
| Transparent lattice IOPs (generic sumcheck/FRI-over-lattice-commitments family) | 2023–2025 research direction | Argument systems; simulation-soundness generally requires extra compilation | Ring-/Module-SIS, LWE, or commitment soundness plus transparent IOP assumptions | Quasi-linear prover expected; constants still immature | Proofs usually sublinear but not tiny; broad range from ~100 KB to MB-scale (**TBD / family-level estimate**) | Polylog / hash-dominant verifier target | Transparent ROM | Yes | **High in principle** | Possibly acceptable for outer verification once constants mature; not ready as a final raw on-chain verifier today | Research prototypes | **Watchlist** — important strategic direction, but still too diffuse for immediate selection |
| Rust-in-zkVM (SP1 / RISC Zero / Jolt) | Current zkVM ecosystems, 2024–2026 | Succinct proof/argument of correct Rust execution; simulation-soundness depends on system and compilation assumptions | Security reduces to the zkVM’s proof system rather than directly to lattice assumptions | **Est.** for a Rust RLWE/share verifier: ~5–20 min prover wall-clock on commodity proving hardware; may be lower for a tiny verifier and higher once hashing/NTTs are included | SP1 / RISC0 class proofs are usually small enough for chain verification (hundreds of bytes to low hundreds of KB depending system and recursion mode); Jolt proof sizes also compact but system-specific | **Est.** ~milliseconds off-chain verifier; on-chain verifier generally feasible via existing verifier contracts / precompiles, at materially lower cost than native lattice verification | ROM / SNARK/STARK model of host zkVM, not a lattice-native ROM statement | Quantum resistance depends on backend: STARK-oriented paths more PQ-friendly than pairing-based recursion; call overall **partial / mixed** | **High** via native recursion/aggregation features in the zkVM stack | **Best short-term on-chain fallback**; verifier is realistic even if prover is slow | SP1 Apache-2.0/MIT; RISC Zero Apache-2.0; Jolt open-source (MIT/Apache-style academic ecosystem) | **Viable fallback** — operationally realistic and explicitly acceptable as the “worst case” path, but not lattice-native and prover cost is high |
| SNARK-friendly hash-of-RLWE-witness (Poseidon/Halo2/Plonky3 style) | Engineering pattern rather than one single paper | Conventional SNARK/zk proof of a circuit that checks a hash/commitment to RLWE witness; simulation-soundness available if chosen SNARK has it | Underlying outer SNARK assumptions + security of witness commitment/hash, not pure lattice assumptions | Prover dominated by circuit cost of NTT/Mod-q arithmetic or by witness-hash strategy; can range from minutes to hours unless relation is aggressively arithmetized | Proofs usually succinct (sub-kB to few-kB for pairing SNARKs; somewhat larger for transparent systems) | Very fast verifier, including on-chain | Depends on outer proof system, often ROM for FS | Usually **partial / mixed** unless using a transparent PQ-friendly outer system | **Very high** — easiest row to compose with folding / recursion | **Strongest on-chain profile** if witness hashing avoids full RLWE arithmetic inside the circuit | Halo2 / Plonky3 ecosystems are permissive open source | **Viable primary** — not lattice-native, but likely the best path if we prioritize recursive composition and an actually deployable verifier |

## Shortlist for PVTHFHE P1

### Viable primary candidates

1. **Beullens one-shot lattice ZK**
   - Best direct-lattice “native proof” candidate in this matrix when the goal is to prove bounded linear relations without accepting a huge interactive transcript.
   - Main risk: still not obviously cheap enough for direct on-chain verification, so it likely needs an outer recursive wrapper.

2. **SLAP**
   - Strong fit to the exact P1 need when the relation is phrased as ciphertext/share/plaintext consistency with bounded error.
   - Main risk: public benchmark coverage is thinner than for older baseline protocols, so constants must still be validated experimentally.

3. **Greyhound**
   - Most promising transparent/recursion-friendly lattice-native direction in the current literature.
   - Main risk: engineering immaturity and uncertain constants for RLWE-share circuits.

4. **SNARK-friendly hash-of-RLWE-witness**
   - Best systems-engineering route when P2 recursion and on-chain verification dominate the design objective.
   - Main risk: this weakens the “purely lattice-native proof” story and shifts trust/assumption weight to the outer SNARK stack.

### Viable fallback candidates

1. **Rust-in-zkVM (SP1 / RISC Zero / Jolt)**
   - Explicitly acceptable fallback; easiest to deploy with a real verifier contract and a Rust witness checker.
   - Main downside is prover latency and dependence on non-lattice proof machinery.

2. **LANES / LNS19 / LNS21 family**
   - Best mature direct-lattice fallback if the newer transparent or one-shot systems do not deliver acceptable constants.
   - Main downside is verifier/proof size overhead relative to recursion-first designs.

3. **Albrecht–Lai lattice SNARGs**
   - Attractive if succinct verifier cost becomes the overriding objective and implementation maturity improves.
   - Main downside is ecosystem immaturity and thin public benchmark data for our exact relation.

## Ranking against the inherited P4→P1 bundle

| Candidate | Why it matches the current bundle | Key blocker |
| --- | --- | --- |
| Beullens one-shot lattice ZK | Native lattice proof of bounded linear relations can potentially express `d_i = c·s_i + e_i mod q` plus norm bounds and transcript binding | Still needs a commitment story for the current SHA-256 transcript and probably an outer recursive wrapper |
| SLAP | Directly targets plaintext/ciphertext consistency, which is close to decryption-share correctness | Need explicit adaptation from plaintext proof to decryption-share + PVSS commitment consistency |
| Greyhound | Most recursion-friendly lattice-native direction for P2 consumption | Concrete prover/verifier constants are not yet well settled |
| SNARK-friendly hash-of-RLWE-witness | Best verifier path for on-chain and recursion, even with the current SHA-256 transcript placeholder | Gives up the cleanest native-lattice proof story |
| Rust-in-zkVM | Can prove the Rust verifier for the surrogate/share-consistency relation almost immediately | High proving cost and non-lattice assumptions |

## Takeaways

- **Do not equate PoK with simulation-soundness.** Nearly every lattice PoK row above needs extra compilation or an outer proof wrapper before it should be treated as simulation-sound.
- **Verifier cost is the strategic bottleneck.** Native lattice Σ/argument systems can match the witness relation well, but recursion and on-chain verification remain much easier in zkVM/SNARK-wrapper approaches.
- **The current P4 SHA-256 commitment is a mismatch for lattice-native recursion.** Any primary P1 design should expect either a commitment upgrade or a wrapper proof that binds the SHA-256 transcript externally.
- **Best near-term engineering fallback:** Rust-in-zkVM.
- **Best native-lattice research bets:** Beullens one-shot, SLAP, and Greyhound.

## References / named lines covered

- Lyubashevsky 2009/2012 Σ-protocol / Fiat-Shamir lattice PoK line.
- Lyubashevsky–Nguyen–Seiler 2019 / 2021 (LANES / LNS19 / LNS21).
- Esgin et al., MatRiCT and short-message lattice ZK (CCS 2019 line).
- Beullens one-shot lattice ZK (CRYPTO 2023 / ePrint 2023/306 line).
- Bootle–Lyubashevsky–Seiler short-secret PoK (EUROCRYPT 2020).
- Albrecht–Lai lattice SNARGs (CRYPTO 2021 / ePrint 2021/863).
- Lattice Bulletproofs / lattice IPA-style succinct arguments.
- SLAP (ePrint 2023/1352 line).
- Greyhound (ePrint 2024/1037 line).
- Transparent lattice IOPs (sumcheck/FRI-like research direction).
- SP1 / RISC Zero / Jolt as zkVM-as-NIZK.
- Halo2 / Plonky3 style SNARK-friendly hash-of-RLWE-witness wrapper.
