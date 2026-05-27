# Security

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **on-chain verifier uses Nova substitution (off-chain Nova + on-chain commitment)**
> - **Noir circuits implement the real aggregation and wrapping logic**
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Implementation status

- **FHE backend**: real threshold BFV via `gnosisguild/fhe.rs`, under an **honest-but-curious** threat model.
- **Greco / well-formedness ZK proofs**: **Implemented** (code exists: CycloNizkAdapter + bfv_sigma.rs). Formal joint-extractor proof is OPEN (P1, line 48).
- **Folding accumulator**: implemented via Nova substitution.
- **On-chain verifier**: real UltraHonk verifier (committing to Nova state) + off-chain attestation.

## Threat Model

The PVTHFHE security model is evaluated across 6 axes:

1.  **Adversary**: Malicious, computationally bounded (PPT).
2.  **Corruption**: Honest-majority threshold $t = \lfloor n/2 \rfloor + 1$. Up to $n-t$ parties can be maliciously corrupted and collude.
3.  **Network**: Synchronous communication for DKG and decryption rounds.
4.  **Identity**: Authenticated channels; party identities are known and fixed for the duration of a protocol instance.
5.  **Liveness**: Guaranteed as long as $t$ honest parties participate.
6.  **Abort**: Abort-with-public-blame; malicious behavior is detected and the offending party is identified.

## Assumptions Ledger

The security of the system relies on the following cryptographic assumptions:

- **RLWE / Module-LWE**: Security of the underlying FHE scheme.
- **SIS / knLWE**: Hardness of finding short vectors, used in NIZK proofs.
- **DDH (Grumpkin)**: Used in the recursive SNARK layer.
- **KZG Binding**: Security of the polynomial commitment scheme.
- **AGM (Algebraic Group Model)**: Assumed for the security analysis of the proving system.

For a full list of formal assumptions, see [.sisyphus/design/security-proofs.md](.sisyphus/design/security-proofs.md).

## Known Limitations & Open Problems

This is a research prototype and contains components where formal soundness proofs are still being developed:

- **P1 (CRITICAL)**: **Lattice NIZK Soundness** — Trust boundary documented (T3). Per-share RLWE NIZK knowledge soundness is conditional on (a) Module-SIS hardness over R_{q_commit}, (b) Cyclo Theorem 3 soundness (ePrint 2026/359), and (c) collision resistance of SHA-256 for the P4 commitment domain. T2 is PROVED — rewinding extractor (ROM, forking lemma, Lemma 9 accepted assumption) (code exists, see §Implementation status line 17). Any relying party must treat per-share proofs as computationally binding under these assumptions only. **Zero-knowledge**: The serialized proof achieves computational ZK — fresh random masks (OsRng, non-deterministic) per invocation; masked sigma transcript (z_s, z_e, t_bytes) reveals nothing about the witness. No witness openings (secret_share, error, randomness) are serialized. Struct-level regression test (`nizk_share_no_witness_leak.rs`) and byte-level tests (`nizk_share_zk.rs`) enforce ZK. **Keygen NIZK (C0)**: BFV keypair correctness NIZK implemented at `crates/pvthfhe-pvss/src/nizk_keygen.rs` using `sigma::prove` with the RLWE relation `pk_0 = pk_1·sk + e`. The `KeygenSimulator` calls `generate_keygen_nizk()` which produces a real sigma proof from the party's secret key and error polynomial. Falls back to stub `vec![0x00, 0x01]` only on error. See `crates/pvthfhe-fhe/src/fhers.rs` for `party_keygen_witness` retrieval and `crates/pvthfhe-aggregator/src/keygen/simulator.rs` for wiring. **R4 fixes applied**: (i) Algebraic sigma equation `c*z_s+z_e == t+ch*d_i` now verified in `verify_algebraic_relation` (was missing; `2fd44e5`). (ii) BFV plaintext domain check `|z_m_i| < t/2` enforced in `bfv_sigma::verify` (`5dee0f8`). (iii) 8 soundness RED tests added confirming tampered d_rns/z_s rejection. **D.2 batched share-encryption proof** (`aadabff`): batched verifier covers sk+esm tracks with independent commitments via `batch_verify_share_encryption`; tampering one track while keeping the other valid fails the batched check (see `crates/pvthfhe-pvss/tests/nizk_share_batched_tracks.rs`). **D.3 domain separation** (`a8e2db2`): per-track domain tags in `pvthfhe-domain-tags` prevent cross-track proof replay (sk proof cannot be replayed as e\_sm proof).
**Share provenance (R5 CLOSED)**: Per-party secret key commitments `sk_commit_i = AjtaiHash(sk_i)` are published during DKG. The verifier checks `proof.pvss_commitment == sk_commitments[party_index]` in the pipeline. `combined_sk_commitment_hash` (Poseidon of all sk_commitments) is a Noir aggregator_final public input, enabling on-chain share provenance verification.
- **P2 (HIGH)**: **LatticeFold+ Linearity** — Trust boundary documented (T3). Real — Cyclo LatticeFold+ over RLWE, T=10. Lemma 9 is accepted as a documented protocol assumption (see `docs/security-proofs/lemma9.md` §0): formal proof deferred; the risk of a non-invertible challenge difference in the Cyclo commitment ring (φ=256, q≈2^50) is believed negligible. Soundness remains conditional on M-SIS hardness over R_{q_commit}, Cyclo Theorem 3 (ePrint 2026/359), and the Lemma 9 invertibility assumption.
- **P3 (MEDIUM)**: **MicroNova-lattice Encoding** — Trust boundary documented (T3). Substituted by off-chain Nova + on-chain commitment topology. The aggregator submits an UltraHonk proof of the Nova state commitment, which is checked on-chain alongside an off-chain attestation. MicroNova heterogeneous IVC is available as an opt-in compressor via `PVTHFHE_COMPRESSOR=micronova` (`HeterogeneousCircuitFamily` + `LatticeFoldTreeCircuitFamily`). See ARCHITECTURE.md §MicroNova.
  MicroNova per-variant verifier enforcement is a known Nova architecture
  limitation — the current framework uses a single verifier key for all
  circuit variants. See heterogeneous-ivc.md:96-99 for details.
- **C5 (PK Aggregation Gap)**: **No verifiable PK aggregation proof**. The DKG ceremony aggregates public keys internally via `ShareManager` without producing a public transcript or verifiable proof that `pk_agg = Σ pk_i` for the accepted participant set. Neither the DKG ceremony nor the aggregator folding produces a C5-equivalent proof. See `interfold-equivalence.md` §C5.
- **DKG aggregate key assertion**: Aggregate key consistency is verified by a runtime assertion comparing the DKG-transcript and backend-aggregation paths. The assertion catches implementation bugs but provides no protection against a malicious keygen participant or a dual-path implementation bug.
- **Aggregate decryption**: Correctness partially verifiable through aggregator_final Noir circuit (N=8 research prototype, Poseidon binding, 8 adversarial tests pass). Full N=8192 dimension and CRT reconstruction verification deferred. See `circuits/aggregator_final/` and `.sisyphus/plans/interfold-equivalent-pvss.md` Batch G.
- **C3 (Share Encryption Binding)**: **Fully implemented (native adapter)**. The `CycloNizkAdapter::verify` at `adapter.rs:192` enforces `pvss_commitment` hash binding via `ct_eq`. The pipeline `run_full_pipeline` (lines 641-653) adds a secondary assertion `statement.pvss_commitment == sk_commitments[party_index]` to catch share provenance mismatches. A tampered commitment triggers verification failure in both paths. The D.1 containment holds at the adapter and pipeline layers. **R10 parity-check hardening**: Cross-share RS parity checks (`parity.rs`) validate that all n encrypted shares are evaluations of a single degree-≤t polynomial, catching structural deviations. Each dealer generates ONE parity proof replacing per-recipient NIZK proofs.
R10 hardening: cross-share RS parity check is now unconditional (with parity-check proofs, see C3 above). Decrypt byte cross-validation added. LegacyLocalSmudge deprecated for production.
- **C2 (Encryption Correctness Gap)**: **Encryption is trusted; no verifiable proof of correct encryption exists**. `backend.encrypt()` produces a ciphertext without a proof that it matches the plaintext under the aggregate key. A malicious encryptor can produce a semantically incorrect ciphertext. Mitigation: the semantic roundtrip check detects errors at the aggregate level only. See `threat-model-v1.md` §7.2 item 12.
- **C7 (Final Aggregation Gap)**: **Partially addressed**. C7 Nova step circuit (P1.3) folds Lagrange recombination into Nova accumulator at N=8. Phase 2 N=8192 off-circuit Merkle-proof verification implemented (8-ary Keccak256 Merkle tree; `verify_merkle_proofs()` called before Nova folding; trust boundary: if Merkle verifier is executed, Nova external inputs are sound). Phase B (real Poseidon R1CS) is complete. `C7MerkleStepCircuit` at depth-5 (N=8192) uses real Poseidon hash in R1CS constraints. See `c7-phase3-in-circuit-merkle.md`. Noir aggregator_final circuit provides standalone verification. **C7 Phase B**: Real Poseidon R1CS in-circuit Merkle verification is implemented (`poseidon_gadget.rs`, `c7_merkle_circuit.rs`). G18 real tree constraints (leaf share-accumulation + internal Poseidon hashing) are code-complete. Noir aggregator_final circuit uses MAX_PARTICIPANTS=128.

### P1 Soundness Budget

The ternary scalar challenge (`ch ∈ {-1,0,1}`) used in `derive_challenge_scalar`
(`crates/pvthfhe-nizk/src/sigma.rs`) provides approximately log₂(3) ≈ 1.58 bits of
soundness per execution. With a single round, the soundness error is 2/3 — a malicious
prover can guess the challenge correctly 66% of the time and produce a convincing
transcript.

| Round count | Soundness error | Effective bits |
|------------|----------------|----------------|
| 1          | 2/3 (≈ 0.67)   | ~1.58          |
| 10         | (2/3)¹⁰ ≈ 0.017 | ~15.8          |
| 45         | (2/3)⁴⁵ ≈ 2⁻⁶⁶ | ~71.2          |
| 90         | (2/3)⁹⁰ ≈ 2⁻¹³² | ~142.4         |
| 137        | (2/3)¹³⁷ ≈ 2⁻²⁰⁰ | ~216.9         |

**Resolution paths** (both deferred):
1. **Parallel repetition**: ~90 non-interactive rounds to achieve 2⁻¹²⁸ soundness via
   sequential Fiat-Shamir hashing. Adds linear overhead per proof.
2. **Binary polynomial challenges**: Switch to `ch ∈ {0,1}^N` (2^N challenge space) with
   NTT-optimized gadgets for sub-linear proof growth.

Tracked as **OPEN PROBLEM P1** (critical). See `crates/pvthfhe-nizk/src/sigma.rs:derive_challenge_scalar`.

### R6 Adversarial Audit Findings (2026-05-14)

SmudgeSlotRegistry enforcement is now unconditional (was gated behind pipeline-extra-checks). See round6-adversarial-remediation.md.

Known limitations (documented, not exploitable):
- e_i=0 in algebraic proof (defense-in-depth; BFV proof provides RLWE soundness)
- Circular pvss_commitment in algebraic proof (defense-in-depth; D2/BFV layers bind independently)
- BFV sigma challenge internally binds to session_id/participant_id (R6 defense-in-depth hardening). All known callers provide full binding.
- Ajtai witness bound enforced only at commit time (verifier relies on binding + sigma bounds)
- Compressor hash-accumulates (full lattice fold deferred to P3)
- Keygen NIZK uses real BFV sigma proofs per dealer (see `nizk_keygen.rs`; falls back to stub only on error)

Cross-session replay hardening:
- aggregate_decrypt now checks session_id against external expectation
- D2 hash binding now includes dkg_root
- FhersBackend::aggregate_keygen now detects duplicate party_id
- Epoch hash expanded from 8 bytes to full 32-byte SHA-256

### Off-Circuit Merkle Trust Model (C7 Phase 2)

The C7 Phase 2 Merkle verification is performed off-circuit before Nova folding. The
trust model assumes:

1. **Merkle verifier is executed**: `c7_fold_witnesses()` calls `verify_merkle_proofs()`
   before Nova folding. If a malicious prover skips this check, the verifier still
   runs it before accepting the proof (pipeline-level trust boundary).

2. **Hash collision resistance**: The Merkle tree uses Keccak256 (SHA-3) for the
   compression function. Breaking proof integrity requires finding a Keccak256
   collision or preimage, which is infeasible under standard assumptions.

3. **Root binding**: The `merkle_root` is bound into the Nova external inputs as
   `ExternalInputs3.2`. A prover cannot use a different root without detection
   because the verifier checks the Merkle proof against the committed root.

4. **No in-circuit constraints**: The Merkle proof is NOT constrained inside the
   R1CS circuit. This means the Nova proof alone does not attest to Merkle
   soundness. The verifier must run the Merkle check as a separate step.
   Phase 3 will move this into the circuit.

5. **Pipeline integration**: The `c7_fold_witnesses` function enforces the Merkle
   check before any Nova operations occur, providing a defense-in-depth barrier.

- **Bench stub phases**: `onchain_verify`, `noir_decrypt_share`, `noir_aggregator_final`, `noir_nova_wrap` phases in the bench binary (`pvthfhe_e2e.rs`) are timing-only markers when the `nova-snark` feature is disabled. With the feature enabled, Groth16 wrapping is available. See `.sisyphus/design/spec-real-p2p3.md` §6 for the production verification plan.

## Trust Boundary — In-Circuit vs Native

Only the Noir `aggregator_final` circuit is verified on-chain (via HonkVerifier.sol). 
All other protocol proofs run natively and are NOT verifiable by the on-chain verifier.

| Protocol Proof | In-Circuit | Native-Only | Notes |
|---------------|-----------|-------------|-------|
| Threshold/Lagrange recombination | ✓ | — | Fully constrained in Noir |
| Plaintext derivation | ✓ | — | Computed from shares via Lagrange |
| ciphertext_hash ≠ plaintext_hash | ✓ | — | Weak check (≠ only) |
| BFV encryption sigma | — | ✓ | Native NIZK via pvthfhe-nizk |
| PVSS DKG NIZK | — | ✓ | Native DKG ceremony |
| Share Schnorr signatures | — | ✓ | Folded via Nova Nova |
| Cyclo NIZK (lattice fold) | — | ✓ | CycloFoldStepCircuit |
| Nova Nova fold soundness | — | ✓ | Native Nova IVC |
| Ajtai commitment verification | — | ✓ | Native Nova-folded |
| C7 decryption aggregation | — | ✓ | CompressionTree (native) |
| Epoch replay protection | — | ✓ | On-chain SessionRegistry |

## Proving Backend Inventory

| Backend | Role | Technology |
|---------|------|-----------|
| Cyclo (fhe-math) | Ring equation + Ajtai commitment | Lattice-native |
| Nova Nova (folding-schemes) | IVC folding + C7 aggregation | R1CS Nova |
| Noir + BB UltraHonk | Final Lagrange recombination | Noir R1CS → Honk |
| HonkVerifier.sol | On-chain verification | Solidity |

### G7b Norm Enforcement

G7b norm enforcement is now implemented in CycloFoldStepCircuit with state_len=7, using z_s_sq_acc and z_e_sq_acc accumulators to track norm growth across fold steps. This provides defense-in-depth against unbounded norm growth in the Cyclo folding path.

**Upgrade path**: The current R1CS L2-accumulation approach is functional but imposes Ω(N) constraints per fold step. Labrador (Fenzi et al. 2023) provides sub-linear lattice ZKPs for norm bounds via rejection-sampling compressed proofs, with projected O(log N) constraint cost. Documented as the recommended production upgrade in `.sisyphus/notepads/labrador-norm-proofs.md`. Deferred to T4 (post P2 resolution).

### Parity-Check Proofs

Parity-check proofs provide RS polynomial verification with O(1) per-recipient DKG verification cost. Instead of verifying n separate NIZK proofs per party, the verifier checks a single parity proof that all n encrypted shares lie on the same degree-≤t polynomial.

### Nova-Folded DKG Verification

AjtaiCommitmentStepCircuit folds n per-recipient verifications into one compressed proof via Nova folding. This replaces O(n) per-recipient verification work with a single compressed proof, achieving the O(polylog n) verifier cost target.

### Track A Deprecated

Track A (Nova hash-then-fold) is deprecated. Track B (norm enforcement, tree-based C7, on-chain UltraHonk) is the sole production path. All new development targets Track B only.

## Logging Hygiene

All FHE plaintext-slot logging in `crates/pvthfhe-fhe/src/fhers.rs` is gated behind the
Cargo feature `trace-decrypt`, which is **disabled by default**. This includes:

- `[FHE-ENCODE]` slot content in `encode_plaintext_slots`
- `[FHE-DECODE]` failure diagnostics in `decode_plaintext_slots`
- `[FHE-DECRYPT]` aggregate-decrypt slot content

The `trace-decrypt` feature exists **solely for debugging and development**. It must
**never** be enabled in:

1. Any production build or deployment
2. Any environment where plaintext confidentiality is required
3. Any benchmark or measurement that interacts with real plaintext data

To enable for local debugging only:

```bash
cargo build -p pvthfhe-fhe --features trace-decrypt
```

## Smudging

To prevent leakage from decryption shares, we use a conservative smudging parameter:
$\sigma_{\text{smudge}} = 2^{40} \cdot \sigma_{\text{err}}$.
This provides $> 100$ bits of statistical security against noise-based leakage, assuming the noise budget is sufficient (validated for $N=8192$).

### Smudging Modes

PVTHFHE supports two distinct smudging modes with different security guarantees:

| Mode | API | Noise source | Interfold-equivalent |
|------|-----|-------------|---------------------|
| `legacy_local_smudge` | `FheBackend::partial_decrypt` | Fresh Gaussian sampled per-decryption via local RNG | **No** (Non-equivalent mode) |
| `committed_smudge_pvss` | `FheBackend::partial_decrypt_committed_smudge` | Committed `e_sm` polynomial from DKG transcript | **Target Committed Mode** |

**`legacy_local_smudge`** (default): Each party samples fresh Gaussian smudging noise
locally during `partial_decrypt`. The noise provides honest-but-curious LWE-based
hiding (prevents secret-key recovery from observed partial decryption shares), but
is **not** Interfold-equivalent because the noise is not a committed, shared PVSS
object. This mode is preserved only as an explicit non-equivalent path for legacy
testing. It lacks a distribution/freshness proof linking the local sample to a
publicly verifiable commitment.

**`committed_smudge_pvss`** (Interfold-equivalent): This is the target
Interfold-equivalent mode. The smudging noise polynomial `e_sm` is a first-class
committed, shared, and proved PVSS object produced during DKG (batch C in the
Interfold-equivalence plan). At decryption time, the backend adds the committed
`e_sm` polynomial instead of sampling fresh noise. This mode requires
DKG-committed `e_sm` slots and public freshness enforcement via the on-chain
`SessionRegistry` to prevent slot reuse. Verification is performed using
the on-chain `PvtFheVerifier` which binds the decryption share to the
DKG commitments and F.1 proof statement; the raw `e_sm` witness material
remains private to the prover.

The committed-smudge path is the foundation for batch F (C6-equivalent threshold
decryption with committed smudging). See `.sisyphus/design/smudging.md` for the
full smudging parameter derivation and `.sisyphus/plans/interfold-equivalent-pvss.md`
for the equivalence roadmap.

## Responsible Disclosure

If you find a security vulnerability, please do not open a public issue. Instead, follow the standard research disclosure process by contacting the maintainers at `security@example.com` (placeholder).

## Disclaimer

This software is provided "as is" for research purposes only. It has not undergone a professional security audit. Use in production environments is strictly discouraged.
