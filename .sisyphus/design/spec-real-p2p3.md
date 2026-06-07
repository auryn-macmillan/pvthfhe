# Spec — Real P2 (Cyclo) + P3 (On-chain) Joint Freeze (L4)

> Phase 0 / L4 design freeze. Locks parameters and interfaces for Phases 1–4 of
> `pvthfhe-real-p2p3`. All section numbers below refer to this document unless
> noted otherwise.

---

## Canonical Parameters

The frozen production parameters for this spec are sourced from the repo-root
`parameters.toml` file and are authoritative unless renegotiated through §9.

| Family | Parameter | Canonical value | Source |
|---|---|---|---|
| RLWE | Ring degree `N` | **8192** | `parameters.toml [rlwe]` |
| RLWE | `log2_q` | **174** | `parameters.toml [rlwe]` |
| RLWE | `B_e` | **16** | `parameters.toml [rlwe]` |

Ring degree N=8192 is canonical.

The value RLWE_N=1024 (illustrative; see Canonical Parameters and `parameters.toml [rlwe]`) appearing in §3.4 is a sigma_proof_bytes sizing example only, not a production parameter.

## 1. Scope and Non-goals

### 1.1 In-scope

- **P1 NIZK candidate (D)**: Cyclo-companion Ajtai NIZK, D2 hash variant. Locks
  statement/witness shape, trait surface, proof byte layout, conditional-soundness
  disclosure plan, and FS domain separator.
- **P2 Cyclo backend**: Concrete ring parameters, folding pattern (sequential
  T=10), norm-growth budget, `CycloAdapter` trait surface replacing
  `SurrogateAdapter`.
- **P3 on-chain verifier decision**: Chosen encoding target (Option B — UltraHonk
  via Noir circuit wrapping MicroNova), public-input binding, and removal of
  the `ecrecover`/`TRUSTED_SIGNER` surrogate.

### 1.2 Non-goals

- **P1 formal soundness closure**: T2 (joint extractor) is a skeleton and
  remains tabled. This document intentionally does not assert formal knowledge
  soundness beyond the conditional disclosure in §3.5.
- **Parameter renegotiation**: Locked except through the escape hatches in §9.
- **Implementation**: No Rust/Noir/Solidity code is written here. Phase 1 starts
  from these interfaces.
- **KZG ceremony selection**: Implemented (Phase 4). Nova Nova uses `KZG<'static, Bn254>` for CS1 with runtime SRS generation via `KZG::<Bn254>::setup(rng, 1 << 17)`. The `bench/srs/bn254.srs` file is a text-only stub — production requires a real MPC ceremony output. `DeciderEth` Groth16 SNARK bridge is feature-gated on `nova-snark`.

---

## 2. Frozen Public Inputs (verbatim from `proof-boundary.md`)

The seven public inputs bound to the final on-chain SNARK are, in order
(source: `.sisyphus/design/proof-boundary.md` §Accumulator-to-SNARK Encoding):

| # | Name | Type | Description |
|---|------|------|-------------|
| 1 | `ciphertext_hash` | `bytes32` | Keccak256 of CBOR-encoded ciphertext `c0 ∥ c1` |
| 2 | `plaintext_hash` | `bytes32` | Keccak256 of CBOR-encoded plaintext polynomial |
| 3 | `aggregate_pk_hash` | `bytes32` | Keccak256 of CBOR-encoded aggregate public key |
| 4 | `dkg_root` | `bytes32` | DKG transcript Merkle root (from keygen) |
| 5 | `epoch` | `uint64` | Decryption epoch (replay protection) |
| 6 | `participant_set_hash` | `bytes32` | Keccak256 of ABI-encoded participant set `(uint32[])` |
| 7 | `D_commitment` | `bytes32` | `Keccak256(D)`, `D = Σᵢ∈S dᵢ` (aggregate decryption sum) |

**Accumulator-internal witness** (not public inputs): `acc_commit`, `fold_count`,
`norm_bound` remain inside the SNARK witness, invisible to the on-chain verifier.

---

## 3. P1 NIZK — Cyclo-companion Ajtai NIZK (Candidate D, D2 variant)

### 3.1 Statement and Witness Restatement

Per-share public statement (source: `nizk-selection.md` §1.2):

```
x_i = (session_id, i, t, c, d_i, C_i, q, N, k, B_e)
```

Per-share witness:

```
w_i = (s_i, e_i)
  where:
    C_i = SHA256(session_id ∥ i_le ∥ s_i_be)   [P4 commitment — hash-binding only, D2]
    d_i = c · s_i + e_i  mod q   in R_q = Z_q[X]/(X^N+1)   [RLWE decryption share]
    ‖e_i‖_∞ ≤ B_e ≈ 16   [shortness bound, 6σ for σ=3.19]
```

Parameters: N=8192, log₂q≈174, B_e≈16 (source: canonical table above and
`parameters.toml [rlwe]`).

### 3.2 Construction Summary (cite `nizk-selection.md` §2(D))

The Cyclo-companion Ajtai NIZK is **not** a separate proof system. Instead, the
per-share witness `(s_i, e_i)` is packed into a CCS instance over the Cyclo
commitment ring `R_{q_commit}` (φ=256, q_commit≈2^50) via the θ₂ map
(cyclo-digest.md §6.2):

```
θ₂ : F_q → R_{q_commit}^1   (174 < φ=256 ✓ — one ring element per RLWE coefficient)
```

The RLWE constraint `d_i = c·s_i + e_i mod q` becomes a single linear constraint
over `R_{q_commit}^{8192}`. The norm bound `‖e_i‖_∞ ≤ 16` is checked by Cyclo's
range protocol (Theorem 1, cyclo-digest.md §4.1). The first call to `CycloAdapter::fold`
**is** the NIZK prove call for party `i`.

The SHA-256 P4 commitment `C_i = SHA256(...)` is the **D2 variant**: it is
checked outside the fold as a hash-binding assertion (T5 proved). The RLWE
relation is fully algebraic in CCS; only the hash binding is conditional.

### 3.3 Trait Surface (Rust pseudo-code)

The existing `LatticeNizk` trait is **retained unchanged** as the external API.
The implementation type `RealNizkAdapter` is replaced by `CycloNizkAdapter`.

```rust
// pseudo-Rust — crates/pvthfhe-fhe/src/real_nizk.rs (replacement impl only)

pub struct CycloNizkAdapter;

const BACKEND_ID: &str = "cyclo-ajtai-d2-conditional";

/// Proof payload for the Cyclo-companion D2 NIZK.
/// Replaces the current `ProofPayload` (SLAP sigma with witness opens).
pub struct CycloProofPayload {
    /// Version tag; must equal CYCLO_PROOF_VERSION = 1.
    version: u16,
    /// Ajtai commitment: u = A · w_i  in R_{q_commit}^a (a=13 elements, φ=256 coeffs each).
    ajtai_commitment: [RqCommitElement; 13],
    /// CCS instance identifier (session_id ∥ participant_id, domain-separated).
    ccs_instance_id: [u8; 32],
    /// Hash-binding record for the SHA-256 P4 commitment (D2 variant).
    /// This is NOT part of the algebraic proof; it is a separate binding assertion.
    sha256_binding: Sha256Binding,
    /// Cyclo accumulator bytes at fold depth 0 (single-share fold input).
    /// Serialised as specified in §3.4.
    cyclo_accumulator_bytes: Vec<u8>,
}

pub struct Sha256Binding {
    /// C_i = SHA256(session_id ∥ i_le ∥ s_i_be) — the P4 commitment value.
    commitment: [u8; 32],
    /// The session_id and participant_id that were hashed (verifier re-derives C_i).
    session_id: String,
    participant_id: u16,
}

impl LatticeNizk for CycloNizkAdapter {
    /// Produce a per-share Cyclo fold input (first accumulator).
    /// `rng`: caller-supplied randomness for the Ajtai mask commitment.
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError>;

    /// Verify: (a) Ajtai commitment check, (b) Cyclo range check for ‖e_i‖_∞ ≤ B_e,
    /// (c) RLWE linear constraint check, (d) SHA-256 D2 hash-binding check.
    /// Returns `NizkError::ConditionalSoundnessDisclosure` when (d) fails in
    /// a folded-only context where SHA-256 re-derivation is unavailable.
    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    /// Calls `verify` sequentially. Aggregation is done at the CycloAdapter layer.
    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}
```

New `NizkError` variant required (`nizk-selection.md` §5.2 point 4):

```rust
// Added to NizkError enum in real_nizk.rs
#[error("conditional soundness: {0}")]
ConditionalSoundnessDisclosure(&'static str),
```

### 3.4 Proof Byte Layout

> **Spec amendment (N6, commit 1f21c59)**: The byte layout below was extended
> beyond the original §3.4 to embed (a) the RLWE sigma proof and (b) the public
> share `d_i` in RNS form. Both are required for stand-alone verifiability of
> the per-share proof. Cyclo accumulator bytes remain a Phase-2 placeholder
> (length 0) until F1-F12 land.

```
Offset   Size        Field
-------  ----------  -----
0        2           version = 0x0001  (u16 BE)
2        32          ccs_instance_id = SHA256(session_id
                       ∥ participant_id u16 BE
                       ∥ q u64 BE
                       ∥ degree u64 BE
                       ∥ error_bound u64 BE
                       ∥ "cyclo-ajtai-d2/v1")
34       26,624      ajtai_commitment: 13 × 256 coefficients × 8 bytes
                       (i64 LE per coefficient, centred mod Q_COMMIT)
26,658   4+sid+2+32  sha256_binding:
                       u32 BE session_id_len
                       + session_id bytes (variable)
                       + participant_id u16 BE
                       + 32-byte commitment = hash_bridge::commit(session_id, pid, secret_share)
var      4+var       sigma_proof_bytes:                     [SPEC EXTENSION — N6]
                       u32 BE total_sigma_section_len, then sigma section:
                         d_rns  : u32 BE count + count × u64 LE
                         t_rns  : u32 BE count + count × u64 LE
                         z_s    : u32 BE count + count × i64 LE
                         z_e    : u32 BE count + count × i64 LE
                         ch     : u32 BE count + count × i64 LE
var      4           cyclo_accumulator_bytes: u32 BE length = 0
                       (Phase-2 placeholder; no accumulator bytes written until F-series)
```

Fixed-size prefix: 2 + 32 + 26,624 = **26,658 bytes**.  
`sha256_binding` size: 4 + len(session_id) + 2 + 32 = 38 + len(session_id) bytes.  
`sigma_proof_bytes` size depends on RLWE_N and number of RNS limbs; for the standard
configuration (RLWE_N=1024 (illustrative; see Canonical Parameters and `parameters.toml [rlwe]`), 3 limbs): d_rns = 4+3×1024×8 = 24,580 bytes,
t_rns = 24,580 bytes, z_s/z_e/ch each 4+1024×8 = 8,196 bytes;
sigma section ≈ 89,128 bytes; plus 4-byte length prefix.  
Total per-share proof (standard config): ≈ 116 KB.

> **SPEC EXTENSION (N6)**: The `sigma_proof_bytes` field in the proof byte layout above
> was added beyond the original spec §3.4 to embed the RLWE sigma proof and public share
> `d_i` in RNS form. Both are required for stand-alone verifiability of per-share proofs.
> Present in code (adapter.rs proof byte layout comment) as of commit 1f21c59.

### 3.5 Conditional-Soundness Disclosure Surfaces

The following files/functions MUST carry a `# Security` or `⚠️` banner (source:
`nizk-selection.md` §5.2):

| File | Function / Location | Required Banner Text |
|------|--------------------|--------------------|
| `crates/pvthfhe-fhe/src/real_nizk.rs` | `LatticeNizk::verify` rustdoc | "Verification success is conditional on T2 (knowledge soundness — skeleton). See SECURITY.md §P1." |
| `crates/pvthfhe-fhe/src/real_nizk.rs` | `NizkProof::backend_id` const | Must equal `"cyclo-ajtai-d2-conditional"` so consumers detect conditional claim. |
| `SECURITY.md` | §Known Limitations P1 | Full paragraph per `nizk-selection.md` §5.2 point 1. |
| `crates/pvthfhe-aggregator/src/folding/mod.rs` | `CycloAdapter::fold` rustdoc | "Folding accumulates per-share witnesses conditionally sound under M-SIS + Cyclo Theorem 3 (ePrint 2026/359). T2 remains skeleton." |
| `docs/security-proofs/p1/theorem-inventory.md` | T2 status | Update to `skeleton (reduction target: Cyclo T3 ∘ T5)`. |

### 3.6 Acceptance Criteria

1. **Bit-exact serialisation**: The `cyclo_accumulator_bytes` field is the
   canonical encoding produced by the Cyclo fold prover. Any two honest provers
   with identical witness and randomness produce identical bytes (deterministic
   after FS).

2. **ROM FS transcript domain separator**: The Fiat-Shamir hash for the Cyclo
   fold uses the following domain-separated tag (ASCII, no null terminator):

   ```
   "pvthfhe/cyclo-ajtai-d2/v1/" ∥ session_id ∥ "/" ∥ participant_id_decimal
   ```

   This tag replaces the current `session_id ∥ pvss_commitment` tag in
   `RealNizkAdapter::challenge_bytes` and must be used in all FS calls within
   the Cyclo fold transcript for this PVTHFHE instantiation.

---

## 4. P2 Cyclo Backend — Folding over RLWE

### 4.1 Locked Cyclo Parameters

Based on `cyclo-digest.md` Table 2 (§5.1) scaled to φ=256, and validated against
PVTHFHE constraints in `nizk-selection.md` §6.4:

| Parameter | Locked Value | Source / Rationale |
|-----------|-------------|-------------------|
| Cyclotomic ring | `X^{256}+1`, power-of-two | cyclo-digest.md §6.5; Lemma 9 covers power-of-2 |
| Ring degree φ_commit | **256** | cyclo-digest.md §6.2: need φ ≥ 175 for θ₂(2^174); φ=256 ✓ |
| Commitment modulus q_commit | **≈ 2^50** (50-bit prime ≡ 1 mod 4·256) | cyclo-digest.md §6.5; independent of PVTHFHE 174-bit q |
| Ajtai rank a | **13** | cyclo-digest.md Table 2 (a=13 for φ=128; scaled to φ=256 — [CITATION NEEDED: exact rescaling rule from paper §C.1]) |
| Initial witness norm B | **2^10 = 1024** | cyclo-digest.md Table 2 |
| Base for decomposition b | **2** (binary) | cyclo-digest.md §6.5; ℓ₂(2^174)=174 < φ=256 ✓ |
| Extended commitment rank a' | **[CITATION NEEDED]** | Cyclo ePrint 2026/359 Appendix C.1 — not stated in digest |
| e (extension field degree) | **2** | cyclo-digest.md Table 2 (paper param e=2) |
| L (folds per round) | **1** | cyclo-digest.md §6.3 — avoid (2γ)^L norm explosion |
| k (inner product rank) | **3** | cyclo-digest.md Table 2 |
| n (inner relation count) | **1** | cyclo-digest.md Table 2 |
| Challenge set | Biased ternary p=1/3 over `{c: ‖c‖_∞ ≤ 1}` | cyclo-digest.md §5.5 |
| Approx. invertibility κ_nu | ≈ 2^{−94} | cyclo-digest.md §5.5, Lemma 9 |
| Sequential depth T | **10** (= ⌈log₂(1024)⌉) | cyclo-digest.md §6.3; norm explosion risk at L≥2 |
| Initial norm B_Cyclo | **2^10** | cyclo-digest.md Table 2 |

> **Backend lock (F1)**: Ring arithmetic for Cyclo folding uses
> `fhe-math` from `gnosisguild/fhe.rs` (git rev pinned in `pvthfhe-cyclo/Cargo.toml`).
> `q_commit = 562_949_953_438_721` (50-bit prime, already used by pvthfhe-nizk).
> `beta_at_t_10 = 1344` (= 1024 + 10·2·16); verifier checks `norm_bound ≤ beta_at_t`,
> not `norm_bound ≤ B`.

### 4.2 Nova substitute

`ProofCompressor` is the frozen backend boundary for the P2→P3 compression layer.
The implementation may use Nova today, but the contract is intentionally
defined as **migration: nova → micronova** with a **bounded migration surface**.
Only the backend-specific adapter behind the trait may change; the external
step-circuit/public-input contract stays fixed.

#### Invariant 1 — Trait surface

Any compressor backend MUST implement the same `ProofCompressor` surface:
`prove(acc, public_inputs) -> CompressedProof`,
`verify(vk, proof, public_inputs) -> bool`, `backend_id`, `vk_bytes()`, and
`compressed_proof_bytes()`. No backend-specific concrete types may appear in the
callers' signatures.

#### Invariant 2 — Step-circuit shape

The step circuit remains backend-agnostic. Input/output state width,
public-input layout, and the per-step relation are described as a shared R1CS
`StepCircuit` shape that both Nova and a future MicroNova backend must accept
without changing the surrounding PVTHFHE call graph.

#### Invariant 3 — Accumulator-state encoding

Accumulator bytes are frozen at the trait boundary: byte layout, BN254 scalar
field choice, and Poseidon parameterisation follow the Construction 1 bridge in
`micronova-digest.md`, so Nova-specific wrappers must convert to a
MicroNova-compatible encoding before crossing the `ProofCompressor` boundary.

#### Invariant 4 — Setup artifacts

Setup is exposed only through a `CompressorSetup` trait returning
`(prover_key_bytes, verifier_key_bytes, srs_id)`. Nova may source these bytes
using its own setup flow, but the exported artifact surface is the same one a
future MicroNova implementation must satisfy.

#### Invariant 5 — Verifier-key semantics

`vk_bytes` carries `srs_id`, `step_circuit_hash`, `backend_id`, and `version`.
A future MicroNova backend that preserves the same step circuit and SRS identity
must remain byte-compatible at the `public_inputs` boundary even though proof
encodings differ.

The bounded migration surface is tracked in `.sisyphus/design/nova-migration.md`.
That document enumerates every file touched by a future compressor-backend swap
and keeps the migration count intentionally small.

### 4.3 Aggregation Strategy

- **n = 1024 per-share NIZKs** each produce a CCS instance over R_{q_commit}.
  Per-share witness dimension: m ≈ 53,248 R_{q_commit} elements
  (nizk-selection.md §6.2) — well below the m=2^20 benchmark.
- **Sequential T=10 folds**, L=1 each: party proofs are folded one at a time
  into the running Cyclo accumulator. No batching (L≥2) is permitted at this
  parameter set.
- **Fold schedule**: fold order is deterministic and sorted by ascending
  `participant_id`. The aggregator performs folds off-chain; each fold step
  requires ≈36.6 s single-threaded (cyclo-digest.md §5.3, scaled for φ=256).
  Parties submit per-share CCS instances in parallel; aggregation is sequential.

### 4.4 Norm Growth Budget

From Cyclo Theorem 3 (cyclo-digest.md §4.3), with L=1, b=2, γ = operator norm
of biased ternary challenge ≈ √φ = √256 = 16 (see cyclo-digest.md §5.5):

```
β_T = β_0 + T · b · γ
β_10 = 1024 + 10 · 2 · 16 = 1024 + 320 = 1344
```

**Check**: β_10 = 1344 < B = 2^10 = 1024?  No — β grows beyond B.

> ⚠️ RISK: β_10 = 1344 > B = 1024. This means after T=10 folds the accumulator
> norm exceeds the initial bound B. This is expected by Theorem 3 (the relation
> type is `Ξ^lin_acc,β+T·bγ`). The actual norm budget for the **accumulator
> after T folds** is β_T, not B. The on-chain verifier must accept `norm_bound ≤ β_T`,
> not `norm_bound ≤ B`. Concretely: β_10 = 1344 < 2^{10.4} — well within the
> modulus headroom of q_commit ≈ 2^50. No intermediate norm refresh is required.
> ✓

Norm explosion check for (2γ)^L blow-up: with L=1 (not batched), the Theorem 3
slack factor is `(2γ)^1 = 32`. Final extraction bound: β̄ = β_10 · 32 = 43,008
≪ q_commit/2 ≈ 2^49. ✓

### 4.5 Trait Surface: `CycloAdapter` (Rust, sync'd to actual code)

This replaces the `SurrogateAdapter` / `FoldingScheme` + `RealFoldingScheme`
in `crates/pvthfhe-aggregator/src/folding/mod.rs`. The implementation lives
in `crates/pvthfhe-cyclo/src/lib.rs` and `crates/pvthfhe-cyclo/src/adapter.rs`.

```rust
// Actual trait surface — crates/pvthfhe-cyclo/src/lib.rs

/// Locked Cyclo LatticeFold+ parameters for PVTHFHE Phase 2.
pub struct CycloParams {
    pub phi_commit: usize,       // 256
    pub log2_q_commit: u32,      // 50
    pub q_commit: u64,           // 562_949_953_438_721
    pub ajtai_rank_a: usize,     // 13
    pub norm_bound_b: u64,       // 1024
    pub base_b: u32,             // 2
    pub sequential_t: u32,       // 10
    pub l_per_round: u32,        // 1
    pub beta_at_t: u64,          // 1344
}

/// Per-share CCS instance produced by CycloNizkAdapter::prove.
pub struct CcsPShareInstance {
    pub participant_id: u16,
    pub ajtai_commitment_bytes: ProtocolBytes,   // a=13 R_{q_commit} elements
    pub public_io_bytes: ProtocolBytes,           // (d_i, ciphertext snippet) encoded
    pub ccs_witness_bytes: CcsWitnessSecret,      // w_i in Fr-LE wire format
    pub sha256_binding_bytes: ProtocolBytes,      // D2 hash assertion bytes
    pub ccs_matrix_bytes: ProtocolBytes,          // CCS constraint matrix [rows:u32 BE][cols:u32 BE][data]
}

/// Running Cyclo accumulator after k folds (0 ≤ k ≤ T=10).
pub struct CycloAccumulator {
    pub fold_depth: u32,
    pub acc_commitment_bytes: Vec<u8>,       // serialised accumulated commitment
    pub acc_public_io_bytes: Vec<u8>,        // serialised accumulated public I/O
    pub norm_bound_current: u64,
    pub session_id: String,
    pub params_digest: [u8; 32],
}

/// Object-safe trait for Cyclo LatticeFold+ adapters.
pub trait CycloAdapter {
    /// Returns the backend identifier string.
    fn backend_id(&self) -> &'static str;

    /// Returns a reference to the locked CycloParams.
    fn params(&self) -> &CycloParams;

    /// Fold a single CcsPShareInstance into `acc`, producing a new accumulator.
    fn fold_one(
        &self,
        acc: CycloAccumulator,
        instance: &CcsPShareInstance,
        rng: &mut dyn RngCore,
    ) -> Result<CycloAccumulator, CycloError>;

    /// Verify that `acc` is a valid accumulator for the given instances.
    fn verify_accumulator(
        &self,
        acc: &CycloAccumulator,
        instances: &[CcsPShareInstance],
    ) -> Result<(), CycloError>;

    /// Fold all instances sequentially, returning the final accumulator.
    /// Instances must be sorted by ascending participant_id.
    fn fold_all(
        &self,
        instances: &[CcsPShareInstance],
        session_id: &str,
        rng: &mut dyn RngCore,
    ) -> Result<CycloAccumulator, CycloError>;
}
```

**Key changes from spec draft to actual code**:

| Spec draft | Actual code |
|---|---|
| `fn init(params, session_id) -> CycloAccumulator` | Removed; caller constructs `CycloAccumulator` directly |
| `fn fold(acc, share, params, rng)` | `fn fold_one(self, acc, instance, rng)` |
| `fn verify_final(acc, depth, params)` | `fn verify_accumulator(self, acc, instances)` |
| `fn serialise_for_p3(acc) -> Vec<u8>` | Removed; `acc_commitment_bytes` + `acc_public_io_bytes` serve as serialisation |
| `FoldingError` | `CycloError` (with variants `InvalidInstance`, `NormBoundExceeded`, `FoldDepthExhausted`, `AccumulatorVerificationFailed`) |
| `ajtai_commitment: Vec<u8>` | `ajtai_commitment_bytes: ProtocolBytes` |
| `acc_commitment: Vec<u8>` | `acc_commitment_bytes: Vec<u8>` |
| `acc_public_io: Vec<u8>` | `acc_public_io_bytes: Vec<u8>` |
| (absent) | `backend_id()` + `params()` accessors |
| (absent) | `ccs_matrix_bytes: ProtocolBytes` field |


### 4.6 Output: Cyclo Accumulator for P3

After T=10 folds the accumulator (`CycloAccumulator`) contains serialised
fields ready for hand-off to P3:

- `acc_commitment_bytes` (a=13 R_{q_commit} elements, each 256 coefficients × 8 bytes)
  = 13 × 256 × 8 = **26,624 bytes**
- `acc_public_io_bytes` (aggregated d = Σ dᵢ, ciphertext hash binding)
  ≈ 8,192 × 8 = **65,536 bytes** (uncompressed)
- fold metadata (`fold_depth`, `norm_bound_current`, `session_id`, `params_digest`) ≈ 100 bytes

Note: the spec draft's `serialise_for_p3()` method was removed from the actual
`CycloAdapter` trait. Callers extract `acc_commitment_bytes` and
`acc_public_io_bytes` directly.

Total serialised accumulator: ≈ **50–60 KB** (as estimated in cyclo-digest.md §6.5).

This blob is consumed by the P2→P3 encoding step (§5).

### 4.7 Estimated Performance

| Metric | Estimate | Source |
|--------|---------|--------|
| Per-fold prover time (single-threaded) | ≈ 73 s | cyclo-digest.md §5.3: 36.6 s at φ=128; ×2 for φ=256 |
| Total aggregation time (T=10 sequential) | ≈ 730 s | 10 × 73 s; parallelisable across sessions |
| Cyclo accumulator proof size | ≈ 50–60 KB | cyclo-digest.md §6.5 |
| Cyclo verifier time (per fold) | O(a)=O(13) R_{q_commit} mults | cyclo-digest.md §5.4 |

---

### 4.8 Multi-Track Fold Infrastructure (H.2)

The Cyclo folding crate supports batched two-track (sk + e_sm) instances via
the following types defined in `crates/pvthfhe-cyclo/src/lib.rs`:

#### `FoldTrackKind` enum

```rust
pub enum FoldTrackKind {
    Sk,                // Secret-key share witness commitment track
    ESm,               // Committed smudging error witness commitment track
    EncryptionWitness, // BFV encryption witness commitment track
}
```

Each variant has a domain-separated byte label for canonical fold metadata
encoding (e.g. `b"pvthfhe-fold-track-sk-v1"`).

#### `MultiTrackFoldMetadata`

```rust
pub struct MultiTrackFoldMetadata {
    pub session_id: String,
    pub participant_id: u16,
    pub party_binding: Vec<u8>,
    pub instance_count: u32,
    pub tracks: Vec<FoldTrackCommitment>,
}
```

Field-level validation is provided by `validate_for_instance()` which enforces:
- Session and participant ID match the enclosing fold instance
- All three track kinds (`Sk`, `ESm`, `EncryptionWitness`) are present
- `Sk` track must not have a slot_index; `ESm` and `EncryptionWitness` must
- All commitment bytes are non-empty and norm bounds are non-zero
- No norm bound exceeds the global `PVTHFHE_CYCLO_PARAMS.norm_bound_b`

#### Cross-track replay rejection

`validate_for_instance()` returns `CycloError::InvalidInstance` with a
descriptive error message if:
- The session_id or participant_id mismatches the instance (cross-session replay)
- Any track kind is missing (partial cross-track replay)
- A track's slot_index is present on `Sk` or absent on `ESm`/`EncryptionWitness`
  (cross-track proof substitution)
- Any track's commitment is empty or norm_bound is zero (null-track attack)

#### Backward compatibility

`CcsPShareInstance` has a `with_multi_track_metadata()` method that wraps the
legacy single-track instance in a `MultiTrackPShareInstance`. Callers that do
not supply metadata produce a `MultiTrackPShareInstance` with
`multi_track_metadata: None`, preserving backward compatibility with
single-track fold paths.

---

## 5. P2 → P3 Encoding Interface (the gap)

### 5.1 Encoding Target

> **DEFERRED (2026-05-12)**: The `MicroNovaAdapter` trait described in §7.1
> (`crates/pvthfhe-p3-encoder/`) is **not yet implemented**. The current
> codebase uses **Nova Nova IVC** directly via the `ProofCompressor` trait
> (`crates/pvthfhe-compressor/src/lib.rs`). Nova Nova serves as a
> substitute for MicroNova in the P2→P3 compression layer. The migration
> plan from Nova/Nova to MicroNova is tracked in
> `.sisyphus/design/nova-migration.md`. The 5 migration invariants in
> §4.2 remain the frozen boundary contract.
>
> The P3 on-chain verifier (§6) currently uses the BB `HonkVerifier.sol`
> path (Option B infrastructure) but the proof it verifies is produced by
> Nova Nova, not MicroNova. This distinction is cosmetic at the ABI level
> because both backends expose the same `ProofCompressor` trait surface.
>
> **P2/P3 structural gap — CycloFoldStepCircuit**: The current `CycloFoldStepCircuit`
> (Nova Nova step circuit in `crates/pvthfhe-compressor/src/nova/mod.rs`) folds
> 3 hashed field elements — `(commitment_hash, norm, fold_count)` — derived from
> SHA-256 of the Cyclo accumulator commitments. It does **not** perform full Ajtai
> commitment folding over `R_{q_commit}` within the IVC step. The design intentionally
> hashes the accumulator down before entering the IVC because lattice-native Ajtai
> folding is infeasible inside a Nova Nova step circuit (P2 OPEN). This means:
> - The compressed proof verifies hash-state consistency, not the full Cyclo
>   accumulator relation (Ajtai commitment check, norm-bound range checks, sum-check
>   transcript verification).
> - The Cyclo accumulator verification is performed off-chain (via `fold::verify_fold`)
>   and its state digest enters the IVC as pre-hashed public inputs.
> - Full Ajtai folding remains an open problem (P2) tracked in the
>   `interfold-equivalent-pvss` plan §Batch H.
> - This is a documented limitation; the same gap exists in the P2→P3 interface
>   regardless of whether Nova or MicroNova is the backend.

**Chosen target**: R1CS over the BN254 scalar field `F_p` (p ≈ 2^254), consumed
by MicroNova as an IVC step function.

Rationale: MicroNova operates over BN254/Grumpkin. The Cyclo accumulator
verifier (an R1CS circuit checking accumulator well-formedness) is expressed
as a single IVC step `F` in MicroNova's chain. The IVC chain length is 1
(one step = verify the final Cyclo accumulator). MicroNova then compresses
this single-step IVC proof to O(log N) BN254 group elements.

### 5.2 Adapter Responsibility

The `MicroNovaAdapter` (§7.1) is responsible for:
1. **Translating** the serialised Cyclo accumulator (`Vec<u8>`) into an R1CS
   witness over `F_p`.
2. **Expressing** the Cyclo verifier predicate as an R1CS constraint system:
   - Ajtai commitment check: `u = A·w` over R_{q_commit} → emulated in F_p.
   - Norm bound: `‖w‖_∞ ≤ β_T = 1344` → bit-decomposition range checks in F_p.
   - Norm-bound range check for each of the a=13 commitment elements.
3. **Binding** the 7 frozen public inputs (§2) as the IVC chain's final output `y`.

### 5.3 Estimated R1CS Constraint Count

From micronova-digest.md §6.2 (rough order-of-magnitude):

| Sub-circuit | Estimated constraints over F_p |
|-------------|-------------------------------|
| R_{q_commit} coefficient emulation (φ=256, q_commit≈2^50) | ≈ 256 × 50 = 12,800 per element |
| Ajtai commitment check (a=13 elements, m≈53,248 witness elts) | ≈ 13 × 53,248 × 13 ≈ 9M [CITATION NEEDED — exact gate model] |
| Norm bound range checks (β_T=1344 < 2^11) | ≈ 53,248 × 11 ≈ 586K |
| Sum-check transcript (Cyclo range proof, ≈60 KB of F_{q^e} elements) | ≈ 2^20 [CITATION NEEDED] |
| **Total (rough upper bound)** | **≈ 2^20 – 2^22** |

> ⚠️ OPEN: The 9M Ajtai gate count is a rough worst-case estimate assuming
> naive F_p emulation of R_{q_commit} arithmetic. If the Cyclo accumulator
> verifier is restructured to avoid re-checking the full witness (only checking
> the commitment consistency), the count may fall to ≈2^20. This must be
> concretely costed in Phase 1 before committing to Option B (§6). If the count
> exceeds 2^21, the escape hatch in §9 should be invoked.

micronova-digest.md §6.2 states the upper bound fits within MicroNova's 2.2M-gas
plateau at N ≤ 2^21.

### 5.4 Witness Pipeline: Post-Quantum Domain → BN254 Scalar Field

The "hash bridge" problem (Cyclo uses Poseidon/custom lattice hash; MicroNova's
on-chain verifier uses Keccak) is solved by **MicroNova's own Construction 1**
(micronova-digest.md §3.3):

- The in-circuit (R1CS / MicroNova IVC step) verifier uses Poseidon for
  accumulating the Cyclo transcript digest.
- The MicroNova prover additionally produces a Keccak fingerprint of the same
  data outside the circuit.
- The on-chain verifier checks the Keccak fingerprint cheaply, without
  re-running Poseidon.

This `HASH-to-HAC RoK` adds O(1) overhead and requires no extra SNARK
(micronova-digest.md Lemma 4.1).

The 7 frozen public inputs are bound as the IVC final output `y = (ciphertext_hash,
plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash,
D_commitment)` at MicroNova compression time.

---

## 6. P3 On-chain Verifier — DECISION

### 6.1 Option A: Direct MicroNova Solidity Verifier

**Approach**: Replace the BB UltraHonk verifier path with MicroNova's own
Solidity library (≈3,300 LoC, micronova-digest.md §5.3). A thin Solidity shim
(≈200 LoC) adapts MicroNova's ABI to `IPvthfheVerifier.sol`.

**Gas**: ≈2.2M gas (micronova-digest.md §5.1), stable up to N ≈ 2^21 R1CS.

**Pros**: One fewer recursion layer; no BN254-pairing-in-Noir complexity.

**Cons**: Dependency on unconfirmed Microsoft open-source repo
(micronova-digest.md §7.1 — repo URL unknown; likely `microsoft/MicroNova`).
Forces abandonment of existing `HonkVerifier.sol` infrastructure already
scaffolded in `PvtFheVerifier.sol` (T39 task planned). Shim contract introduces
a new trust surface.

### 6.2 Option B: Wrap MicroNova Proof in UltraHonk Noir Circuit (CHOSEN)

**Approach**: After MicroNova compresses the Cyclo accumulator verification to
O(log N) BN254 group elements, write a Noir circuit that:
1. Accepts the MicroNova compressed proof as a private witness.
2. Verifies the MicroNova verifier predicate in-circuit using BB's native BN254
   gadgets (O(log N) MSMs + 2 pairings in Noir = estimated ≈2^20 PLONKish
   gates [CITATION NEEDED — needs concrete Noir/BB gate count for BN254 pairing]).
3. Exposes the 7 frozen public inputs (§2) as Noir `pub` inputs.

This Noir circuit is compiled with Nargo and proved with BB UltraHonk. The
resulting UltraHonk proof is verified on-chain by the BB-generated
`HonkVerifier.sol` already imported by `PvtFheVerifier.sol`.

**Gas**: BB UltraHonk Solidity verifier at ≈2^20 Noir gates — estimated
≈2.5–3M gas [CITATION NEEDED — BB UltraHonk gas scaling at this gate count].
Within 5M budget.

**Pros**:
- Preserves the existing `IPvthfheVerifier.sol` ABI **unchanged**.
- Preserves `PvtFheVerifier.sol` / `HonkVerifier.sol` infrastructure (T39
  simply implements the Noir circuit, not a new Solidity library).
- Single P3 codebase in Noir + BB, consistent with the existing architecture.
- No unconfirmed external Solidity library dependency.

**Cons**: Two-layer compression (Cyclo → MicroNova → UltraHonk). BN254 pairing
in Noir is technically feasible but gate count is uncertain; if it exceeds
2^21 gates, Option A becomes the fallback (§9).

### 6.3 Option C: Skip MicroNova — Verify Cyclo Accumulator Directly in UltraHonk

**Approach**: Express the full Cyclo accumulator verifier (Ajtai check + norm
checks + sum-check transcript verification) directly as a Noir circuit and prove
it with BB UltraHonk.

**Why this is rejected**: The Cyclo accumulator verifier requires emulating
R_{q_commit} polynomial arithmetic over the BN254 scalar field (φ=256, 50-bit
coefficients) plus full sum-check verification of ≈60 KB of F_{q^e} elements.
Estimated total PLONKish constraint count: 2^20 – 2^22 (§5.3). At 2^22 gates,
BB single-shot proving time is estimated at several minutes and proof size
exceeds the 14 KB calldata budget. The sum-check transcript alone (≈2^20
constraints [CITATION NEEDED]) would saturate the practical BB gate budget
without the Ajtai emulation overhead. This approach also eliminates any
incremental verifiability benefit.

**Verdict**: Option C is **rejected** for Phase 1–3. It may be revisited only
if the combined constraint budget falls to ≤2^20 after a concrete Cyclo
verifier circuit analysis.

### 6.4 DECISION: Option B — Wrap MicroNova Proof in UltraHonk Noir Circuit

**Single chosen option**: **Option B**.

**Justification matrix**:

| Criterion | Option A | Option B (CHOSEN) | Option C |
|-----------|---------|-------------------|---------|
| Gas budget | ≈2.2M ✓ | ≈2.5–3M ✓ | [likely >5M] ✗ |
| Code surface | 3,300 LoC external + 200 LoC shim | Existing BB/Noir infra + new Noir circuit | New Noir circuit (large) |
| Time-to-MVP | Medium (repo TBD) | Medium (Noir circuit design) | Long (constraint budget risk) |
| Audit cost | High (new Solidity lib) | Medium (Noir circuit only) | High (large circuit) |
| ABI compatibility | Shim needed | **Preserved unchanged** | Preserved |
| PQ disposition | Non-PQ at P3 (accepted per SECURITY.md) | Non-PQ at P3 (accepted) | Non-PQ at P3 (accepted) |
| Architecture continuity | Breaks T39 plan | **Continues T39 plan** | Partial |

**Fallback**: Option A if Phase-3 gate measurement shows Option B's MicroNova-in-Noir
circuit exceeds 2^21 PLONKish gates (see §9 escape hatch iv).

**Post-quantum note**: BN254 is not post-quantum. The P3 layer breaks the lattice
PQ guarantees of P1/P2. This is a **known and accepted** trade-off per
`SECURITY.md` §Assumptions Ledger and micronova-digest.md §6.3.

### 6.5 Public-Input Binding in the Actual Circuit

> ⚠️ **TOY CIRCUIT — NOT PRODUCTION C7-EQUIVALENT.**
> The current Noir circuit (`circuits/aggregator_final/src/main.nr`) uses N=8
> (research-prototype ring dimension), performs **direct Lagrange recombination**
> over polynomial shares with **Poseidon hash commitment binding**, and does
> **not** verify a MicroNova proof. This is intentional for the research
> prototype. A production circuit would implement the Cyclo→MicroNova→UltraHonk
> compression chain described in §6.2/§6.4.

The Noir circuit exposes exactly 7 public inputs, ordered as in §2.
They are bound as follows:

```noir
// — circuits/aggregator_final/src/main.nr (toy circuit, N=8)
fn main(
    // Public inputs (7 frozen; order matches IPvthfheVerifier.sol §7.2)
    ciphertext_hash:       pub Field,      // Keccak256 of ciphertext
    plaintext_hash:        pub Field,      // Keccak256 of plaintext
    aggregate_pk_hash:     pub Field,      // Keccak256 of aggregate PK
    dkg_root:              pub Field,      // DKG Merkle root
    epoch:                 pub Field,      // Decryption epoch (u64 promoted to Field)
    participant_set_hash:  pub Field,      // Keccak256 of participant set
    d_commitment:          pub Field,      // Keccak256(D)
    // Private inputs (Lagrange recombination witnesses)
    n_participants:        pub Field,
    threshold:             pub Field,
    lagrange_coeffs:       [Field; MAX_PARTICIPANTS],
    participant_shares:    [[Field; N]; MAX_PARTICIPANTS],
    plaintext:             [Field; N],
    z_q:                   Field,
) {
    // 1. Sanity checks: epoch > 0, hash distinctness, bounds.
    assert(epoch as u64 > 0);
    assert(ciphertext_hash != plaintext_hash);
    assert(participant_set_hash != 0);
    assert(n_participants as u32 <= MAX_PARTICIPANTS);
    assert(threshold as u32 > 0);
    assert(threshold as u32 <= n_participants as u32);

    // 2. Poseidon CRH commitment binding (domain-separated):
    //    Hash each participant share → combine → check plaintext_hash,
    //    then compute d_commitment and assert equality with public input.
    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(participant_shares[i], DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    assert(vector_hash(plaintext, DOMAIN_VECTOR_MERKLE) == plaintext_hash);
    let d_commitment_computed = bind_8_with_domain([
        combined_share_hash, dkg_root, participant_set_hash,
        epoch, n_participants, threshold, 0, 0,
    ], DOMAIN_AGGREGATOR_D_COMMIT);
    assert(d_commitment_computed == d_commitment);

    // 3. Derive evaluation challenge r = Poseidon(7 public inputs ∥ 0).
    let r = bind_8_with_domain([
        ciphertext_hash, plaintext_hash, aggregate_pk_hash,
        dkg_root, epoch, participant_set_hash, d_commitment, 0,
    ], DOMAIN_CHALLENGE_DERIVE);

    // 4. Direct Lagrange recombination over N=8 (NOT production N=8192):
    let lhs = eval_poly(plaintext, r);
    let mut rhs = 0;
    let mut lagrange_sum = 0;
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            rhs = rhs + lagrange_coeffs[i] * eval_poly(participant_shares[i], r);
            lagrange_sum = lagrange_sum + lagrange_coeffs[i];
        }
    }
    assert(lagrange_sum == 1);

    // 5. R3 relation: rhs − lhs ≡ 0 (mod Q), Q from protocol_constants.
    //    No MicroNova proof verification is performed.
    assert(r_pow_n(r) + 1 != 0);
    assert(rhs - lhs == protocol_constants::Q * z_q);

    assert(aggregate_pk_hash != 0);
}
```

**Diff from spec Option B (§6.2/§6.4)**: The spec requires MicroNova proof
verification in-circuit. This toy circuit instead performs **direct Lagrange
recombination** over polynomial-degree N=8 shares and validates binding via
Poseidon hashes. It contains **no** MicroNova proof verification, **no** Cyclo
accumulator verifier (Ajtai commitment check, norm bound range checks,
sum-check transcript verification), and **no** BN254 pairing gadgets. This is
intentional for the research prototype; a full C7-equivalent production circuit
is scheduled for a future phase.

The `epoch` field is encoded as a `u64` value promoted to a BN254 `Field`
element (zero-padded to 32 bytes) and packed identically to the `uint64 epoch`
in the Solidity ABI.

**ABI encoding on-chain** (bit layout, matching `PvtFheVerifier.sol` slot order):
```
calldata slot  bytes  ABI type   Noir public input index
0              32     bytes32    0: ciphertext_hash
1              32     bytes32    1: plaintext_hash
2              32     bytes32    2: aggregate_pk_hash
3              32     bytes32    3: dkg_root
4               8     uint64     4: epoch (ABI-padded to 32 bytes in calldata)
5              32     bytes32    5: participant_set_hash
6              32     bytes32    6: d_commitment
7+             var    bytes      proof bytes (UltraHonk wrapping Lagrange recombination circuit)
```

### 6.6 Removal of `ecrecover` / TRUSTED_SIGNER

`contracts/src/P3RealVerifier.sol` is the current surrogate using ECDSA. The
following exact lines must be deleted or replaced in Phase 2 (do **not** modify
until the Noir circuit is complete and the BB-generated verifier passes the
Phase-3 gate):

| Location | Action |
|----------|--------|
| Line 30–31: `address public constant TRUSTED_SIGNER = 0xf39Fd...;` | Delete (replace with `HonkVerifier` import) |
| Lines 38–66: entire `verify(...)` function body | Replace with call to BB-generated `HonkVerifier.verify(proof, publicInputs)` |
| Line 63: `ecrecover(digest, v, r, s)` | Deleted as part of function body replacement |

The `P3RealVerifier.sol` contract is ultimately replaced by `PvtFheVerifier.sol`
(which already imports `HonkVerifier.sol`) once T39 is complete. No structural
ABI changes are needed.

---

## 7. Interface Contracts (frozen)

### 7.1 Rust Traits (sync'd to actual code)

```rust
// --- P1 NIZK (crates/pvthfhe-fhe/src/real_nizk.rs) ---
pub trait LatticeNizk {  // UNCHANGED external boundary
    fn prove(stmt: &NizkStatement, witness: &NizkWitness, rng: &mut impl RngCore)
        -> Result<NizkProof, NizkError>;
    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;
    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}
// Implementation: CycloNizkAdapter (replaces RealNizkAdapter)

// --- P2 Folding (crates/pvthfhe-cyclo/src/lib.rs) ---
pub trait CycloAdapter {  // REPLACES SurrogateAdapter / FoldingScheme
    fn backend_id(&self) -> &'static str;
    fn params(&self) -> &CycloParams;
    fn fold_one(&self, acc: CycloAccumulator, instance: &CcsPShareInstance,
                rng: &mut dyn RngCore) -> Result<CycloAccumulator, CycloError>;
    fn verify_accumulator(&self, acc: &CycloAccumulator,
                          instances: &[CcsPShareInstance]) -> Result<(), CycloError>;
    fn fold_all(&self, instances: &[CcsPShareInstance], session_id: &str,
                rng: &mut dyn RngCore) -> Result<CycloAccumulator, CycloError>;
}

// --- P2→P3 Encoding (DEFERRED — c.f. §5.1 note) ---
//
// The `MicroNovaAdapter` trait and `crates/pvthfhe-p3-encoder/` crate are
// DEFERRED. Current implementation uses Nova Nova IVC directly via the
// `ProofCompressor` trait in `crates/pvthfhe-compressor/src/lib.rs`.
// See `.sisyphus/design/nova-migration.md` for migration plan.
//
// pub trait MicroNovaAdapter {
//     fn encode_accumulator(acc_bytes: &[u8], public_inputs: &[u8; 7 * 32])
//         -> Result<MicroNovaR1cs, EncodingError>;
//     fn prove_compressed(r1cs: &MicroNovaR1cs, rng: &mut impl RngCore)
//         -> Result<MicroNovaProof, EncodingError>;
//     fn serialise_for_noir(proof: &MicroNovaProof) -> Vec<u8>;
// }
```

### 7.2 Solidity ABI: `IPvthfheVerifier` — Unchanged

The interface defined in `contracts/src/PvtFheVerifier.sol` (lines 8–40) is
**frozen and must not be modified**. The function signature is:

```solidity
function verify(
    bytes32 ciphertextHash,
    bytes32 plaintextHash,
    bytes32 aggregatePkHash,
    bytes32 dkgRoot,
    uint64  epoch,
    bytes32 participantSetHash,
    bytes32 dCommitment,
    bytes calldata proof
) external view returns (bool valid);
```

### 7.3 Noir Entry Circuit Signature (Option B)

See §6.5 for the full `main.nr` pseudo-Noir signature. The canonical entry point
is `circuits/aggregator_final/src/main.nr`. The current stub (`fn main(x: Field)`)
is replaced in Phase 2. The public inputs must be declared in **exactly** the
order of §2 (indices 0–6) to match the Solidity ABI calldata slot order.

### 7.4 Public-Input ABI Encoding (bit layout)

All 7 public inputs are encoded as 32-byte big-endian values in the Noir circuit
and in Solidity calldata. The `epoch` field (`uint64`) is zero-padded to 32 bytes
(24 leading zero bytes). The Keccak256 hashes are used verbatim as 32-byte
values. No further packing or compression is applied.

---

## 8. Parameter Compatibility Table (Phase-0 Gate Artifact)

| PVTHFHE parameter | Required value | Cyclo param | Cyclo value | MicroNova param | MicroNova value | Status |
|---|---|---|---|---|---|---|
| RLWE ring degree N | 8192 | (constraint side only) | — | (R1CS witness size) | ≤ 2^21 | **PASS** — RLWE N is constraint-side; Cyclo φ is independent |
| log₂q (RLWE) | 174 | φ_commit ≥ log₂q | φ=256 ≥ 174 ✓ | F_p field size | p≈2^254 ≫ 174 ✓ | **PASS** — θ₂ map requires φ ≥ 174; satisfied |
| RNS limbs | 3 (58-bit primes) | (irrelevant to Cyclo ring) | — | R1CS emulation | Each limb ≤ 58-bit; fits in F_p | **PASS** — RNS lives only in R1CS witness |
| Plaintext modulus t | 2^17 | — | — | (part of public IO) | Bound as Field element | **PASS** — t fits in F_p |
| Parties n | ≤ 1024 | sequential T | T=10 ≥ ⌈log₂(1024)⌉=10 ✓ | IVC chain length | 1 step | **PASS** — T=10 accommodates exactly n=1024 shares |
| Error bound B_e | ≈16 (6σ, σ=3.19) | B_Cyclo | 2^10=1024 ≥ 16 ✓ | (range check) | R1CS bit-decomp 11-bit | **PASS** — ‖e_i‖_∞ ≤ 16 ≤ B_Cyclo ✓ |
| Secret distribution | ternary | ‖s_i‖_∞ ≤ 1 | B_Cyclo=1024 ≫ 1 ✓ | — | — | **PASS** — ternary secret satisfies norm bound trivially |
| PQ security ≥128 bits | pq_bits=128 | M-SIS over R_{q_commit} | φ=256, q_commit≈2^50, a=13; [CITATION NEEDED: concrete M-SIS estimate at these params] | Non-PQ (BN254) | Known/accepted | **CONDITIONAL PASS** — P1/P2 layers PQ; P3 layer non-PQ (accepted) |
| Norm growth T=10 | β_10 ≤ q_commit/2 | β_T = 1344 | β_10=1344 ≪ 2^49 ✓ | — | — | **PASS** — see §4.3 |
| Witness count m | ≤ 2^20 | m ≈ 53,248 | 53,248 < 2^20=1,048,576 ✓ | R1CS size | ≤ 2^21 | **PASS** — well within benchmark m=2^20 |
| Proof size | ≤ 60 KB (Cyclo acc.) | 50–60 KB | cyclo-digest.md §6.5 | O(log N) BN254 | ≈3–5 KB | **PASS** — Cyclo acc fits; MicroNova compressed much smaller |
| On-chain calldata | ~14 KB | — | — | UltraHonk proof | ~14 KB (BB UltraHonk) | **PASS** — matches `PvtFheVerifier.sol` comment |
| Gas target | ≤ 5M | — | — | UltraHonk at ≈2^20 gates | ≈2.5–3M gas [CITATION NEEDED] | **CONDITIONAL PASS** — within budget; confirm in Phase 3 |
| Invertibility κ_nu | negligible | κ_nu ≈ 2^{-94} | Lemma 9, φ=256, q≈2^50 ✓ | — | — | **PASS** — 2^{-94} ≪ 2^{-80} soundness target |

---

## 9. Escape Hatches

Parameter renegotiation is permitted if the Phase-3 gate (`just phase3-gate`)
fails. Renegotiable knobs, in priority order:

| Priority | Knob | Trigger condition | Allowed renegotiation |
|----------|------|------------------|-----------------------|
| (i) | RLWE log₂q (PVTHFHE) | Cyclo constraint emulation count exceeds 2^22 gates | Reduce RNS limb count from 3 to 2 (log₂q ≈ 116 bits); accept reduced FHE noise budget |
| (ii) | Cyclo q_commit | M-SIS security at φ=256, a=13 falls below 128-bit PQ target | Increase q_commit to ≈2^60 (accept +20% proof size); re-estimate security |
| (iii) | Sequential T | Aggregation time (730 s) unacceptable for deployment | Increase parallelism (L=2 batched with monitored norm refresh at T=5); re-run norm-growth analysis |
| (iv) | Drop MicroNova-in-Noir (Option B) | MicroNova Noir circuit exceeds 2^21 PLONKish gates | Switch to Option A (Direct MicroNova Solidity verifier); update T39 |
| (v) | Drop QROM stretch | QROM analysis for Cyclo not available at Phase-1 start | Retain ROM baseline; flag in SECURITY.md; do not block Phase 1 |

Any renegotiation requires a plan amendment via the standard plan-control process
and must not be performed ad hoc in implementation code.

---

## 10. Open Items Pushed to Phase 1+

| Item | Pushed to | Notes |
|------|-----------|-------|
| Concrete R1CS/PLONKish constraint count for Cyclo accumulator verifier | Phase 1 | Circuit-design task; outcome gates Option B viability (§9 escape hatch iv) |
| Microsoft MicroNova repo URL and license confirmation | Phase 1 | Likely `microsoft/MicroNova`; confirm Apache-2.0 or MIT before vendoring |
| Exact BB UltraHonk version pin for Noir circuit | Phase 1 | Must match `REPRODUCING.md` toolchain pin; current stub uses nightly.20260324 |
| Exact a' (extended commitment rank) value from Cyclo ePrint §C.1 | Phase 1 | Required for accurate proof-size and performance estimates |
| Concrete M-SIS security estimate at (φ=256, q_commit≈2^50, a=13) | Phase 1 | Required for §8 PASS/FAIL for PQ security row |
| KZG ceremony selection (Powers-of-Tau source) | Phase 4 | Implemented: Nova Nova CS1 = `KZG<'static, Bn254>`, runtime SRS via `KZG::<Bn254>::setup(rng, 1<<17)`. Production ceremony still deferred (see `bench/srs/bn254.srs`). |
| Formal T2 joint extractor (RLWE ∘ M-SIS ∘ Cyclo T3) | Phase 4+ | Tabled per P1 policy; status remains `skeleton` |
| QROM analysis for Cyclo FS transcript | Phase 4+ | Not blocked; ROM baseline sufficient for Phases 1–3 |
| NTT-domain vs coefficient-domain CCS template | Phase 1 | Affects per-share witness packing strategy (nizk-selection.md §7 Q1) |
| D1 vs D2 final decision (Ajtai vs SHA-256 P4 commitment) | Phase 1 start | D2 is assumed here; D1 requires P4 interface change and plan amendment |

---

## 11. References

| Citation | Full reference |
|----------|---------------|
| cyclo-digest.md | Internal digest of: Garreta, Lipmaa, Luhaäär, Osadnik — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks", IACR ePrint 2026/359 (Eurocrypt 2026 major revision, 2026-04-13) |
| micronova-digest.md | Internal digest of: Zhao, Setty, Cui, Zaverucha — "MicroNova: Folding-based Arguments with Efficient (On-Chain) Verification", IACR ePrint 2024/2099 (IEEE S&P 2025) |
| nizk-selection.md | Internal L3 candidate selection document, 2026-05-04 |
| proof-boundary.md | `.sisyphus/design/proof-boundary.md` — PVTHFHE Proof Boundary Freeze (T25) |
| parameters.toml | Repo-root `parameters.toml` — canonical PVTHFHE parameter set |
| Cyclo ePrint | https://eprint.iacr.org/2026/359 |
| MicroNova ePrint | https://eprint.iacr.org/2024/2099 |
| LatticeFold+ | Boneh, Chen — "LatticeFold+", IACR ePrint 2025/247 (CRYPTO 2025) |
| NethermindEth/latticefold | https://github.com/NethermindEth/latticefold (Apache 2.0, Rust; closest LatticeFold+ reference implementation) |
| Module-SIS hardness | Langlois, Stehlé — "Worst-case to Average-case Reductions for Module Lattices", DCC 2015 |

---

*Document status*: L4 design freeze — read-only after Phase 1 start except via
escape hatches (§9) or plan amendment.
*Compiled*: 2026-05-04
*Chosen P3 option*: **Option B — Wrap MicroNova proof in UltraHonk Noir circuit**

## §5 Lattice PVSS Addendum

The lattice PVSS scheme and composed statement freeze for Phase P are specified
in `.sisyphus/design/spec-pvss.md`, which is the authoritative companion spec
for share reconstruction, per-recipient BFV share encryption, and the frozen
PVSS NIZK statement shape.

P0a routed this work as **GoWithCaveat**: the existing Sigma+Ajtai transcript can
absorb the BFV share-encryption relation structurally, but doing so widens the
extractor obligation beyond the current conditional-soundness banner. The extra
assumption is recorded in `.sisyphus/design/assumptions-ledger.md` and must
remain in force until a joint extractor argument closes the composition gap.
