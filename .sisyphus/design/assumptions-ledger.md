# Assumptions Ledger — Real P2 + P3 (L5)

> Phase 0 / L5 artifact. Single source of truth for every cryptographic
> assumption, structural assumption, model choice, and conditional-soundness
> caveat introduced by the real P2 (Cyclo) + P3 (MicroNova-in-UltraHonk)
> design freeze (`spec-real-p2p3.md`, L4). Used by F1–F4 review wave and by
> README/SECURITY badges.

---

## 1. How to Read This Ledger

### 1.1 Status Keys

| Status | Meaning |
|--------|---------|
| **ASSUMED** | Taken as hard without reduction in this codebase; standard cryptographic assumption. |
| **REDUCED** | Explicitly reduced to another assumption listed here. |
| **PROVED** | Formally proved in `docs/security-proofs/`; see T-ID column. |
| **CONDITIONAL** | Asserted conditionally; the named caveat must be resolved before deployment. |
| **TABLED** | Proof deferred; skeleton or no proof present. See open-problems list in `SECURITY.md`. |

### 1.2 Assumption ID Scheme

| Prefix | Domain |
|--------|--------|
| `A-LATTICE-*` | Lattice / short-integer assumptions |
| `A-DLOG-*` | Discrete-log / pairing assumptions |
| `A-HASH-*` | Hash / symmetric assumptions |
| `A-MODEL-*` | Idealized-model choices (ROM, AGM, …) |
| `A-STRUCT-*` | Structural / protocol assumptions |
| `A-COND-*` | Conditional-soundness disclosures |

### 1.3 Column Definitions

Each table carries: **ID · Statement · Model · Where Used · Status · Target Hardness · Reduction Target · References**.

---

## 2. Computational Assumptions (Lattice)

| ID | Statement | Model | Where Used | Status | Target Hardness | Reduction Target | References |
|----|-----------|-------|------------|--------|----------------|-----------------|------------|
| **A-LATTICE-1** | **Module-SIS (Cyclo commitment ring).** For `A ∈ R_{q_commit}^{a×m}` with `φ_commit=256`, `q_commit≈2^50`, rank `a=13`, norm bound `B̂=2·β_T·(2γ)^1 ≤ 2·1344·32 = 86,016`, it is hard to find a nonzero `w` with `A·w = 0` and `‖w‖_∞ ≤ B̂`. | Standard | Cyclo folding (P2): Ajtai commitment binding; knowledge extractor fallback | **ASSUMED** | ≥128-bit PQ [CITATION NEEDED: concrete M-SIS estimate at φ=256, a=13, q≈2^50] | — | cyclo-digest.md §4.4, §6.5; Langlois–Stehlé DCC 2015 |
| **A-LATTICE-2** | **Module-LWE (PVTHFHE RLWE secret/error).** For `N=8192`, `log₂q≈174` (3 RNS limbs), ternary secret distribution, error `σ=3.19`, it is hard to distinguish RLWE samples `(a, a·s+e)` from uniform in `R_q^2`. | Standard | FHE correctness (P0); implicit in P1 relation well-formedness | **ASSUMED** | ≥128-bit PQ | — | parameters.toml `[rlwe]`; SECURITY.md |
| **A-LATTICE-3** | **Module-SIS (P1 NIZK algebraic binding).** The per-share Ajtai commitment `u = A·w_i` over `R_{q_commit}` is binding: finding `w_i ≠ w_i'` with `A·w_i = A·w_i'` and both within norm `B_Cyclo=2^10` reduces to A-LATTICE-1. | Standard / ROM | P1 NIZK (CycloNizkAdapter): prevents witness equivocation | **REDUCED** | → A-LATTICE-1 | A-LATTICE-1 | spec-real-p2p3.md §3.2; cyclo-digest.md §4.4 |
| **A-LATTICE-4** | **Invertibility of challenge samples (Lemma 9 heuristic).** For the power-of-two cyclotomic `X^{256}+1` with biased ternary challenge (p=1/3), the probability that a difference of two challenges is non-invertible is `κ_nu ≈ 2^{-94}`. This is a **heuristic** specialized to power-of-two cyclotomics; the general cyclotomic case is unproved. | Heuristic | Cyclo folding soundness error (κ formula in Theorem 3) | **CONDITIONAL** | κ_nu ≤ 2^{-94} ≪ 2^{-80} soundness target | — | cyclo-digest.md §5.5; Cyclo ePrint 2026/359 Lemma 9 |
| **A-LATTICE-5** | **Short-integer solution for norm growth.** After T=10 sequential folds (L=1), accumulator norm `β_10 = 1344 < q_commit/2 ≈ 2^49`. Extraction slack bound: `β̄ = 43,008 ≪ 2^49`. No intermediate norm refresh required. | Standard | Cyclo norm-growth accounting (spec-real-p2p3.md §4.3) | **ASSUMED** | Arithmetic check; no hardness claim | — | spec-real-p2p3.md §4.3; cyclo-digest.md §4.3 |

---

## 3. Computational Assumptions (Discrete-log / Pairing)

> ⚠️ **POST-QUANTUM: NO.** All assumptions in this section are broken by quantum adversaries. Accepted for the on-chain (P3) layer per `SECURITY.md` threat model.

| ID | Statement | Model | Where Used | Status | Target Hardness | Reduction Target | References |
|----|-----------|-------|------------|--------|----------------|-----------------|------------|
| **A-DLOG-1** | **q-SDH / KZG binding on BN254.** For the universal KZG SRS `(g, g^τ, …, g^{τ^D})` on BN254, it is hard to open a committed polynomial to two distinct values. Relies on the q-Strong Diffie-Hellman assumption. | AGM (see A-MODEL-4) | MicroNova HyperKZG polynomial commitment (P3 compression) | **ASSUMED** | ~128-bit classical; PQ: NO | — | micronova-digest.md §4.1; Kate–Zaverucha–Goldberg ASIACRYPT 2010 |
| **A-DLOG-2** | **Discrete log on BN254.** Computing `x` from `g^x` on BN254 is hard. Underlies all DLOG-based sub-arguments in MicroNova. | Standard | MicroNova NIFS, MicroSpartan (P3) | **ASSUMED** | ~128-bit classical; PQ: NO | — | micronova-digest.md §3 |
| **A-DLOG-3** | **Discrete log on Grumpkin.** Computing `x` from `g^x` on the Grumpkin curve (non-pairing-friendly, BN254-cycle partner) is hard. Underlies Pedersen commitments used in the NIFS layer. | Standard | MicroNova NIFS Pedersen commitments; half-pairing cycle | **ASSUMED** | ~128-bit classical; PQ: NO | — | micronova-digest.md §3.1, §4.1; Bowe–Grigg–Hopwood Halo |
| **A-DLOG-4** | **Bilinear pairing hardness (BN254).** The decisional / computational Diffie-Hellman problem in the pairing target group `G_T` of BN254 is hard. Required for KZG evaluation proofs to be sound. | Standard | MicroNova HyperKZG final pairing check (2 pairings on-chain) | **ASSUMED** | ~128-bit classical; PQ: NO | — | micronova-digest.md §3.2, §5.1 |

---

## 4. Hash / Symmetric Assumptions

| ID | Statement | Model | Where Used | Status | Target Hardness | Reduction Target | References |
|----|-----------|-------|------------|--------|----------------|-----------------|------------|
| **A-HASH-1** | **SHA-256 collision resistance (P4 commitment domain).** It is hard to find `s_i ≠ s_i'` with `SHA256(session_id ∥ i_le ∥ s_i_be) = SHA256(session_id ∥ i_le ∥ s_i'_be)`. The commitment domain is exactly `session_id ∥ participant_id_le ∥ secret_share_be`. | Standard | P1 NIZK hash-binding (D2 variant); T5 proved | **PROVED** (T5) | 128-bit collision resistance | — | theorem-inventory.md T5; SECURITY.md; spec-real-p2p3.md §3.2 |
| **A-HASH-2** | **Poseidon-BN254 collision resistance.** Poseidon instantiated over the BN254 scalar field is collision resistant (modeled as a random oracle in protocol proofs). Used for in-circuit hashing in MicroNova's recursive verifier and in Cyclo's Fiat-Shamir transcript. | ROM (A-MODEL-1) | Cyclo FS transcript; MicroNova in-circuit hash; UltraHonk transcript | **ASSUMED** | 128-bit (heuristic; no formal proof of Poseidon CR) | — | micronova-digest.md §3.3; cyclo-digest.md §7.4 |
| **A-HASH-3** | **Keccak-256 collision resistance.** Keccak-256 is collision resistant. Used on-chain for public input hashes and in MicroNova's HASH→HAC bridge (Construction 1). | Standard | On-chain public inputs (all 7 `bytes32` fields); MicroNova HAC RoK | **ASSUMED** | 128-bit collision resistance | — | micronova-digest.md §3.3, §4.2; spec-real-p2p3.md §2 |
| **A-HASH-4** | **HAC bridge soundness (MicroNova Construction 1 / Lemma 4.1).** The HASH→HAC reduction of knowledge is knowledge-sound under collision resistance of both Poseidon (A-HASH-2) and Keccak-256 (A-HASH-3), with negligible knowledge error. Bridges in-circuit Poseidon transcript to on-chain Keccak verification. | ROM (A-MODEL-1) | MicroNova Poseidon↔Keccak bridge; ensures on-chain verifier sees consistent digest | **ASSUMED** | Reduces to A-HASH-2 and A-HASH-3 | A-HASH-2, A-HASH-3 | micronova-digest.md §3.3, §4.2 |

---

## 5. Idealized Models

| ID | Model | Scope | Status | Notes |
|----|-------|-------|--------|-------|
| **A-MODEL-1** | **Random Oracle Model (ROM).** Hash functions (SHA-256, Poseidon, Keccak) are replaced by a uniformly random function accessible as an oracle. | Fiat-Shamir transforms throughout: P1 NIZK (Cyclo FS), MicroNova NIFS/MicroSpartan FS, UltraHonk transcript | **ASSUMED** (baseline) | QROM is a stretch goal; not part of the baseline claim. See A-MODEL-2. |
| **A-MODEL-2** | **QROM (Quantum ROM) — stretch goal.** Upgrade of A-MODEL-1 for post-quantum security of Fiat-Shamir. The Cyclo paper does not provide a QROM analysis; Kiltz–Lyubashevsky–Schaffner 2018 covers module-lattice sigma in QROM. | P1/P2 layers only (P3 is non-PQ) | **TABLED** | Do not block Phase 1. Surfaces in escape hatch (v) of spec-real-p2p3.md §9. |
| **A-MODEL-3** | **Generic Group Model (GGM).** Not explicitly invoked by any sub-argument in the frozen design; BN254 subarguments use standard DLOG / q-SDH without GGM. | — | Not used; listed for completeness | If an argument later requires GGM, this entry must be promoted to ASSUMED. |
| **A-MODEL-4** | **Algebraic Group Model (AGM).** KZG evaluation-binding proof uses AGM (standard practice since Fuchsbauer–Kiltz–Loss 2018). Required for A-DLOG-1 (q-SDH) to imply KZG binding. | MicroNova HyperKZG (P3 compression layer) | **ASSUMED** | Non-PQ; confined to P3. P1/P2 lattice layers do not require AGM. |

---

## 6. Structural / Protocol Assumptions

| ID | Statement | Where Used | Status | Notes |
|----|-----------|------------|--------|-------|
| **A-STRUCT-1** | **Trusted setup (KZG SRS — universal, BN254).** The SRS `(g^{τ^i})_{i=0}^{D}` was generated honestly and `τ` was securely discarded. Any existing universal Powers-of-Tau ceremony (Ethereum, Aztec) may be reused. Selection of specific ceremony is deferred to Phase 3 gate. | MicroNova HyperKZG; UltraHonk (BB) | **ASSUMED** | Trusted-setup selection is a Phase 3 gate artefact. |
| **A-STRUCT-2** | **No rewinding by the environment.** The composed prover (P1→P2→P3) is not rewound by an adversarial environment after proof generation. Sequential composition of P1→P2→P3 is sound under standard sequential-composition with no extra simulation queries. | Protocol-level; P1 T4 decision | **ASSUMED** | T4 records this as non-requirement under current threat model. |
| **A-STRUCT-3** | **Fiat-Shamir domain separation discipline.** Every FS challenge hash call uses a distinct, correctly domain-separated tag. P1/Cyclo uses `"pvthfhe/cyclo-ajtai-d2/v1/" ∥ session_id ∥ "/" ∥ participant_id_decimal`. Collisions in domain tags break transcript soundness. | All FS transforms (P1, P2, P3 circuits) | **ASSUMED** | Enforcement is an implementation invariant; tested by adversarial tests. |
| **A-STRUCT-4** | **Honest majority threshold (t-of-n DKG).** The P4 DKG produces a valid aggregate public key under honest-majority: at most `n − t` parties are corrupt, `t = ⌊n/2⌋ + 1`. The P1 NIZK verifies per-share well-formedness, not the DKG itself. | P4 (DKG/keygen); P1 relation inherits `dkg_root` | **ASSUMED** | Out-of-scope for P2/P3; inherited from P4 design. |
| **A-STRUCT-5** | **Sequential composition of P1→P2→P3.** The security properties of the composed system follow from sequential composition of knowledge-sound P1 NIZKs (conditional; see A-COND-1) → Cyclo folding (P2) → MicroNova compression → UltraHonk wrap (P3). No parallel composition with adversarial proofs is assumed. | End-to-end protocol | **ASSUMED** | Formal composability argument is not written; treated structurally. |
| **A-STRUCT-6** | **Power-of-two cyclotomic (Lemma 9 applicability).** PVTHFHE uses `X^{256}+1` as the Cyclo commitment ring and `X^{8192}+1` as the RLWE constraint ring. Both are power-of-two cyclotomic. Cyclo Lemma 9 (invertibility heuristic, A-LATTICE-4) applies only to this subfamily. | Cyclo folding (P2) | **ASSUMED** | Confirmed: φ_commit=256 = 2^8, N=8192 = 2^13. Lemma 9 scope satisfied. |

---

## 7. Conditional-Soundness Disclosures (the CONDITIONAL bin)

### A-COND-1 — P1 Knowledge Soundness (T2 SKELETON)

| Field | Value |
|-------|-------|
| **ID** | A-COND-1 |
| **Claim** | Per-share RLWE NIZK knowledge soundness: a rewinding ROM extractor outputs `(s_i, e_i)` satisfying `d_i = c·s_i + e_i mod q`, `‖e_i‖_∞ ≤ B_e`, `C_i = SHA256(...)`. |
| **Status** | **CONDITIONAL / TABLED** |
| **Condition** | Requires: (a) A-LATTICE-1 (M-SIS over R_{q_commit}), (b) Cyclo Theorem 3 extractor (cyclo-digest.md §4.3), (c) A-HASH-1 (SHA-256 binding, T5 proved). Joint extractor composing Cyclo T3 ∘ T5 is not written. |
| **T-ID** | T2 — `skeleton (reduction target: Cyclo T3 ∘ T5)` |
| **Banner surfaces** | `LatticeNizk::verify` rustdoc; `NizkProof::backend_id = "cyclo-ajtai-d2-conditional"`; `SECURITY.md §P1`; `CycloAdapter::fold` rustdoc; theorem-inventory.md T2 status |
| **References** | theorem-inventory.md T2; nizk-selection.md §5; spec-real-p2p3.md §3.5 |

### A-COND-2 — P1 Zero-Knowledge (T3 Partial)

| Field | Value |
|-------|-------|
| **ID** | A-COND-2 |
| **Claim** | Per-share NIZK is (honest-verifier) zero-knowledge. |
| **Status** | **CONDITIONAL** |
| **Condition** | T3 is **proved for the abstract randomized core only** (SLAP sigma base). The D2 Ajtai variant (Cyclo-companion NIZK) requires a new T3 argument for the Ajtai commitment mask. The deterministic SHA-256 mask derivation in the current prototype is explicitly non-ZK. |
| **T-ID** | T3 — `proved (abstract randomized core only)`; D2 Ajtai ZK argument: **TABLED** |
| **References** | theorem-inventory.md T3; spec-real-p2p3.md §3.5; nizk-selection.md §5.1 |

### A-COND-3 — Cyclo Lemma 9 Invertibility Heuristic

| Field | Value |
|-------|-------|
| **ID** | A-COND-3 |
| **Claim** | For `X^{256}+1`, biased ternary challenges (p=1/3), `κ_nu ≈ 2^{-94}` (probability that challenge-difference is non-invertible). |
| **Status** | **CONDITIONAL** (heuristic, not formally proved for general cyclotomic) |
| **Condition** | Lemma 9 of Cyclo ePrint 2026/359 covers power-of-two cyclotomics only. PVTHFHE qualifies (`φ=256 = 2^8`). Generalization to other conductors is left as future work by the authors. |
| **References** | cyclo-digest.md §5.5; Cyclo ePrint 2026/359 Lemma 9; A-STRUCT-6 |

### A-COND-4 — MicroNova R1CS Encoding Constraint Count

| Field | Value |
|-------|-------|
| **ID** | A-COND-4 |
| **Claim** | Encoding the final Cyclo accumulator as a single MicroNova IVC step fits within 2^21 R1CS constraints (≤ 2.2M-gas MicroNova plateau). |
| **Status** | **CONDITIONAL** |
| **Condition** | Estimated 2^20–2^22 constraints (micronova-digest.md §6.2); exact count requires L4 circuit design. Escape hatch (iv) activates if the Noir circuit exceeds 2^21 PLONKish gates. |
| **References** | micronova-digest.md §6.2–6.3; spec-real-p2p3.md §9 escape hatch (iv) |

---

## 8. Frozen Public Inputs

The following 7 public inputs are bound to the final on-chain UltraHonk proof (source: `spec-real-p2p3.md §2`, verbatim from `proof-boundary.md`). No additional public inputs are introduced by the real backends.

| # | Name | Type | Description |
|---|------|------|-------------|
| 1 | `ciphertext_hash` | `bytes32` | Keccak256 of CBOR-encoded ciphertext `c0 ∥ c1` |
| 2 | `plaintext_hash` | `bytes32` | Keccak256 of CBOR-encoded plaintext polynomial |
| 3 | `aggregate_pk_hash` | `bytes32` | Keccak256 of CBOR-encoded aggregate public key |
| 4 | `dkg_root` | `bytes32` | DKG transcript Merkle root |
| 5 | `epoch` | `uint64` | Decryption epoch (replay protection) |
| 6 | `participant_set_hash` | `bytes32` | Keccak256 of ABI-encoded participant set |
| 7 | `D_commitment` | `bytes32` | `Keccak256(D)`, `D = Σᵢ∈S dᵢ` (aggregate decryption sum) |

**Accumulator-internal** (not public): `acc_commit`, `fold_count`, `norm_bound` remain in the SNARK witness, invisible to the on-chain verifier.

---

## 9. Renegotiable Parameters (Escape-Hatch Register)

Mirroring `spec-real-p2p3.md §9`. Each knob is paired with the assumptions it touches.

| Priority | Knob | Trigger | Allowed Renegotiation | Assumptions Touched |
|----------|------|---------|----------------------|---------------------|
| (i) | `log₂q` (PVTHFHE RLWE) | Cyclo constraint emulation count > 2^22 gates | Reduce RNS limbs 3 → 2 (log₂q ≈ 116); accept reduced FHE noise budget | A-LATTICE-2, A-LATTICE-3 |
| (ii) | Cyclo `q_commit` | M-SIS security at φ=256, a=13 < 128-bit PQ | Increase to ≈2^60; accept +20% proof size; re-estimate | A-LATTICE-1, A-LATTICE-4 |
| (iii) | Sequential T | Aggregation time (≈730 s) unacceptable | L=2 batched with monitored norm refresh at T=5; re-run norm-growth | A-LATTICE-5, A-STRUCT-6 |
| (iv) | Option B (MicroNova-in-Noir) | Noir circuit > 2^21 PLONKish gates | Switch to Option A (Direct MicroNova Solidity verifier); update T39 | A-COND-4, A-STRUCT-1 |
| (v) | QROM stretch | Cyclo QROM analysis unavailable at Phase-1 start | Retain ROM baseline; flag in SECURITY.md | A-MODEL-2 |

---

## 10. Cross-Reference Matrix

`✓` = assumption is depended upon by component. `—` = not applicable.

| ID | P1-NIZK (Cyclo D2) | P2-Cyclo Folding | P3-MicroNova | P3-UltraHonk Wrap | On-Chain (Solidity) |
|----|-------------------|-----------------|-------------|------------------|---------------------|
| A-LATTICE-1 | ✓ | ✓ | — | — | — |
| A-LATTICE-2 | ✓ | — | — | — | — |
| A-LATTICE-3 | ✓ | ✓ | — | — | — |
| A-LATTICE-4 | — | ✓ | — | — | — |
| A-LATTICE-5 | — | ✓ | — | — | — |
| A-DLOG-1 | — | — | ✓ | ✓ | — |
| A-DLOG-2 | — | — | ✓ | ✓ | — |
| A-DLOG-3 | — | — | ✓ | — | — |
| A-DLOG-4 | — | — | ✓ | — | ✓ |
| A-HASH-1 | ✓ | — | — | — | — |
| A-HASH-2 | ✓ | ✓ | ✓ | ✓ | — |
| A-HASH-3 | — | — | ✓ | — | ✓ |
| A-HASH-4 | — | — | ✓ | — | ✓ |
| A-MODEL-1 | ✓ | ✓ | ✓ | ✓ | — |
| A-MODEL-2 | (stretch) | (stretch) | — | — | — |
| A-MODEL-3 | — | — | — | — | — |
| A-MODEL-4 | — | — | ✓ | — | — |
| A-STRUCT-1 | — | — | ✓ | ✓ | ✓ |
| A-STRUCT-2 | ✓ | ✓ | ✓ | ✓ | — |
| A-STRUCT-3 | ✓ | ✓ | ✓ | ✓ | — |
| A-STRUCT-4 | ✓ | — | — | — | — |
| A-STRUCT-5 | ✓ | ✓ | ✓ | ✓ | ✓ |
| A-STRUCT-6 | ✓ | ✓ | — | — | — |
| A-COND-1 | ✓ | ✓ | — | — | — |
| A-COND-2 | ✓ | — | — | — | — |
| A-COND-3 | — | ✓ | — | — | — |
| A-COND-4 | — | — | ✓ | ✓ | ✓ |

---

## 11. References

| Short | Full Citation |
|-------|---------------|
| Cyclo ePrint 2026/359 | Garreta, Lipmaa, Luhaäär, Osadnik — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks", Eurocrypt 2026, IACR ePrint 2026/359 |
| MicroNova ePrint 2024/2099 | Zhao, Setty, Cui, Zaverucha — "MicroNova: Folding-based Arguments with Efficient (On-Chain) Verification", IEEE S&P 2025, IACR ePrint 2024/2099 |
| KZG ASIACRYPT 2010 | Kate, Zaverucha, Goldberg — "Constant-Size Commitments to Polynomials and Their Applications", ASIACRYPT 2010 |
| Langlois–Stehlé DCC 2015 | Langlois, Stehlé — "Worst-case to Average-case Reductions for Module Lattices", Designs Codes Cryptography 75(3), 2015 |
| Kiltz–Lyubashevsky–Schaffner 2018 | Kiltz, Lyubashevsky, Schaffner — "A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random Oracle Model", EUROCRYPT 2018, IACR ePrint 2017/916 |
| Halo / Grumpkin | Bowe, Grigg, Hopwood — "Recursive Proof Composition without a Trusted Setup" (Halo), 2019 (informal); Grumpkin curve definition |
| Fuchsbauer–Kiltz–Loss 2018 | Fuchsbauer, Kiltz, Loss — "The Algebraic Group Model and its Applications", CRYPTO 2018 |
| LatticeFold+ ePrint 2025/247 | Boneh, Chen — "LatticeFold+", CRYPTO 2025, IACR ePrint 2025/247 |
| theorem-inventory.md | `docs/security-proofs/p1/theorem-inventory.md` (this repo) — T1–T5 |
| spec-real-p2p3.md | `.sisyphus/design/spec-real-p2p3.md` (this repo) — L4 freeze |
| cyclo-digest.md | `.sisyphus/research/cyclo-digest.md` (this repo) |
| micronova-digest.md | `.sisyphus/research/micronova-digest.md` (this repo) |
| nizk-selection.md | `.sisyphus/research/nizk-selection.md` (this repo) |
| parameters.toml | `.sisyphus/design/parameters.toml` (this repo) |

---

## 12. Milestone / Disclosure Surfaces

| ID | Event | References |
|----|-------|------------|
| A27 | Disclosure surfaces wired (N7) — 5 surfaces: LatticeNizk::verify rustdoc, BACKEND_ID const comment, SECURITY.md §P1, folding/mod.rs module banner, theorem-inventory.md T2 status | nizk-selection.md §5.2; spec-real-p2p3.md §3.5 |

## pvss-bfv-composition (added P0a, 2026-05-06)

**Source**: P0a feasibility spike verdict GoWithCaveat
**Assumption**: The composed Sigma+Ajtai + BFV-share-encryption NIZK is conditionally sound under the same RLWE hardness assumptions as the existing pvthfhe-nizk, PLUS the additional assumption that the BFV encryption relation is extractable from the composed transcript (i.e., a joint extractor exists that opens both the decrypt-share relation and the BFV encryption relation consistently).
**Status**: Unproven. The current conditional-soundness banner covers the existing Ajtai+RLWE share relation but does NOT close the new extraction obligation introduced by BFV share encryption.
**Required before production**: A formal joint extractor argument or a reduction to a standard lattice assumption.
**Impact**: P1–P4 may proceed under this assumption; the conditional-soundness banner must be updated to mention this additional obligation.
