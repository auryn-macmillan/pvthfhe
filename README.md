# PVTHFHE: Private-Verifiable Threshold FHE

> ⚠️ **RESEARCH PROTOTYPE — NOT PRODUCTION-READY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE.
> Two security audits (2026-05-08: 70 findings; 2026-05-09: 188 findings) and three MPC
> audits (22+ findings across threshold, sigma, and aggregation layers) have been completed
> and all automatable findings have been remediated. Three open cryptographic problems remain
> (see §Open Problems). The end-to-end pipeline is **not** a formally verified cryptographic
> artifact and has **not** undergone adversarial dress rehearsal.
>
> See [SECURITY.md](SECURITY.md), [WARNING.md](WARNING.md),
> [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md),
> [`.sisyphus/audit/AUDIT-2026-05-09.md`](.sisyphus/audit/AUDIT-2026-05-09.md), and
> [`.sisyphus/audit/EXTERNAL-PACKET.md`](.sisyphus/audit/EXTERNAL-PACKET.md) for details.

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with O(n) per-party work and O(polylog n)
verifier cost. The current prototype uses:

| Layer | Implementation | Status |
|-------|---------------|--------|
| DKG | Pedersen-DKG over BFV/RLWE secret domain (`.sisyphus/design/dkg-construction.md`) | ✅ Real (BN254 Shamir, OsRng, smudging) |
| NIZK | Cyclo-companion Ajtai D2 sigma + BFV sigma (k-round repetition, configurable soundness) | ✅ Real (SIGMA_REPETITIONS, prove/verify_multi) |
| Folding (P2) | nova-snark (Microsoft) Nova IVC with high-arity batch folding + FS outside circuit (`.sisyphus/design/fold-construction.md`) | ✅ Real (Symphony T1+T2+T3+T4 enabled by default) |
| Compression (P3) | nova-snark Nova IVC with KZG\<Bn254\> commitments + CycloFoldStepCircuit (arity=8) | ✅ Real (transparent IVC, no ceremony; demo ACCEPTs at n=128) |
| On-chain verifier | OpenZeppelin AccessControl + TimelockController | ✅ Real (AccessControl, multisig, runId) |
| IVC SNARK (P4) | 6-field IVC binding (proof_hash, vk_hash, pp_hash, z0/zi_commitment, steps) + Solidity verifyWithIvc | ✅ Real (no Groth16 ceremony; IVC proof binding on-chain) |
| Decrypt (smudge) | `legacy_local_smudge` (non-equivalent) vs `committed_smudge_pvss` (target committed mode) | ✅ Doc split (F.3) |
| Shamir/RS validity (C2) | BN254-scalar Shamir + P(0) commitment binding + batched sk/e_sm share-computation relation | ✅ Implemented (`share_computation.rs`, `dealer_parity_circuit.rs`) |
| Share encryption (C3) | BFV sigma + Ajtai commitment + BfvEncryptionStepCircuit (in-circuit S-Z verification across L=3 RNS moduli) | ✅ Implemented (BFV encryption relation verified in-circuit) |
| Keygen NIZK (C0) | BFV keypair correctness NIZK via `sigma::prove` (`sigma.rs`, keygen NIZK integrated) | ✅ Implemented (replaces `vec![0x00, 0x01]` stub) |
| Parity check (C2) | In-circuit H·shares==0 via Schwartz-Zippel + Poseidon P(0) binding | ✅ Implemented (`dealer_parity_circuit.rs`, `parity.rs`) |
| Final aggregation (C7) | Nova C7DecryptAggregationCircuit (N=8) + C7MerkleStepCircuit (N=8192, Poseidon R1CS) + Noir aggregator_final | ✅ Implemented (Nova C7DecryptAggregationCircuit N=8 + C7MerkleStepCircuit N=8192 Poseidon R1CS + Noir aggregator_final) |

## Audit Status

**Two security audits and three MPC audits completed. All automatable findings remediated.**

### Security Audits

| Layer | Post-Remediation Status |
|-------|--------------------------|
| FHE backend (BFV via fhe.rs) | ✅ Real lattice crypto; `Secrecy<T>` + `Zeroize` on keys † |
| DKG / Shamir resharing | ✅ Pedersen-DKG over BFV; BN254 Shamir; OsRng reshare |
| PVSS encryption | ✅ BN254 scalar Shamir; OsRng encryption randomness |
| Lattice NIZK well-formedness | ✅ Witness-free proofs; D2-preimage binding; CRS-bound Ajtai |
| Cyclo folding (RLWE fold) | ✅ Real ∞-norm; CCS satisfiability; \|C\|=2¹⁶ challenge space |
| Aggregator folding | ✅ CCS-based fold; single canonical path |
| Nova compression (Nova) | ✅ CycloFoldStepCircuit; epoch-bound SRS |
| On-chain verifier (Solidity) | ✅ AccessControl (3 roles); multisig (≥2/3 + 48h); runId liveness |
| End-to-end pipeline | ✅ Fold binding; atomic plaintext; semantic roundtrip verified |

† FHE backend assumes honest-but-curious threshold parties (see SECURITY.md §Threat Model).

### MPC Audits (3 passes)

| Pass | Findings | Status |
|------|----------|--------|
| MPC Audit I (threshold layer) | 14 findings (6 HIGH, 4 MEDIUM, 4 LOW) | ✅ All remediated |
| MPC Audit II (post-migration) | 8 findings (4 HIGH, 4 MEDIUM) | ✅ Completed (`.sisyphus/plans/mpc-audit-post-migration.md`) |
| MPC Audit III (final pass) | 3 findings (1 HIGH, 2 MEDIUM) | ✅ Completed (`.sisyphus/plans/mpc-audit-final-pass.md`) |

**Remediation plans**: `.sisyphus/plans/pvthfhe-remediation.md` (179/179 ✅) and
`.sisyphus/plans/audit-2026-05-09-remediation.md` (55/55 ✅). All gate-level checkboxes
are closed under `.sisyphus/plans/pvthfhe-gate-resolution.md`.

## Symphony Techniques

The compressor crate includes four optimization techniques from the Symphony
paper. As of S8, all techniques are compiled unconditionally (no feature flags):

| Technique | Description |
|-----------|-------------|
| **T1: High-arity folding** | Batches n iterative `prove_step` calls into a single fold using random linear combination β (Symphony §4) |
| **T2: FS outside circuit** | Moves Fiat-Shamir hashing outside the Nova circuit via identity step circuits with Keccak256 commitments to step inputs (Symphony §6) |
| **T3: Monomial embedding range proofs** | Replaces fixed 31-bit decomposition with adaptive bit-count range checks based on monomial embedding (Symphony §5.2) |
| **T4: Random projection** | Reduces sigma witness size by ~n/256× using JL projection J∈{0,±1}^{256×n}; verifies norms on projected vectors (Symphony §5.3) |

## Soundness Budget

| Parameter | Value | Source |
|-----------|-------|--------|
| Folding soundness (ε_fold) | 2⁻¹⁶⁰ (exponential bound, 10 rounds, 2¹⁶ challenges; aspirational — P1 OPEN, P2 Nova substitute, P3 partially resolved) | `.sisyphus/design/fold-soundness-budget.md` |
| DKG secrecy | ≤ 2⁻¹²⁸ (t−1 shares indistinguishable from uniform) | `pvthfhe-keygen/tests/dkg_secrecy.rs` |
| Composed soundness | R1.5 ⊕ R2.4 ⊕ R3.1+R3.2 ⊕ R4.4 ⊕ R5.2 ⊕ R6.1 ⊕ R8.5 ≥ 2⁻¹²⁸ (aspirational — P1 OPEN, P2 Nova substitute, P3 partially resolved) | Plan gate-level verification |
| BFV parameters | n=8192, log₂q=174, σ_smudge=2⁴⁰·σ_err | `.sisyphus/design/smudging.md` |

### Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS reduction for BFV) | **OPEN** |
| P2 | Lattice folding over RLWE (LatticeFold+/Cyclo Lemma 9) | **OPEN** (Nova substitute) |
| P3 | Parametrized Nova step circuit verification (same ext-scaling) | **PARTIALLY RESOLVED** — Nova IVC works end-to-end; CycloFoldStepCircuit arity=8 fixed |

## Threat Model

See [`.sisyphus/design/threat-model-v1.md`](.sisyphus/design/threat-model-v1.md) for:
- Adversary model (PPT, active network, ≤ t−1 corrupted parties)
- 8 required security properties for Interfold core component
- Residual assumptions and open risks

## Status: Research Prototype

- **NOT a formally verified cryptographic artifact.**
- **NOT battle-tested** (no adversarial dress rehearsal).
- **FHE backend**: Real `gnosisguild/fhe.rs` BFV library. Parameters are production-grade but have not undergone independent parameter review.
- Folding uses **nova-snark (Microsoft) Nova IVC** as a substitute for lattice-native folding (P2). Soundness budget assumes Nova soundness over BN254+grumpkin cycle.
- **Transparent IVC**: No Groth16 trusted ceremony required. IVC proof bytes are hashed with Keccak256 and embedded directly in the compressed proof format for on-chain verification via the Poseidon hash shortcut.
- **Stage 0 Build-time Tripwire**: Release builds require `PVTHFHE_ALLOW_RESEARCH_BUILD=1`. See `SECURITY.md`.
- **Benchmarks**: Need re-running against the rebuilt pipeline. See `bench/results/`.

## Quickstart

### Dependencies

- **Rust**: 1.95.0
- **Foundry**: 1.6.0–1.7.0
- **Noir**: 1.0.0-beta.20
- **BB CLI**: 5.0.0-nightly.20260324
- **Just**: casey/just

### Local Setup

```bash
git clone https://github.com/auryn-macmillan/pvthfhe
cd pvthfhe

# Build (research mode)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build

# Run the end-to-end demo (defaults: n=10, t=4, seed=1)
just demo-e2e
```

The demo exercises the current threshold-FHE pipeline end-to-end using real cryptographic
primitives. **The NIZK witness uses real BFV secret key material. The folding path uses real
CCS satisfiability. The compressor uses nova-snark (Microsoft) Nova IVC with transparent
decider (no Groth16 ceremony).** See `WARNING.md` for known limitations.

Verified at up to n=128. Larger n may exceed practical wall time due to O(n²) threshold setup.

### Per-Node Timing Output

The end-to-end demo reports per-node distributed timing estimates for O(n) work scaling:

```
per_node_keygen_ms=12.3
per_node_dkg_deal_ms=45.7
per_node_partial_decrypt_ms=8.1
aggregator_total_ms=234.0
distributed_estimate_ms=279.7
```

Per-node work is dominated by `dkg_deal` (BFV encryption + sigma NIZK proof generation).
The aggregator serial bottleneck (compressor prove + verify, cyclo fold, key aggregation)
is the only O(polylog n) component.

## Key Commands

- `just demo-e2e`: End-to-end demo (n=10, t=4; all 9 steps with real crypto).
  - Threshold `t` is the number of shares required for reconstruction (1 ≤ t ≤ ⌊(n-1)/2⌋).
  - FHE and PVSS layers use the same threshold: `t` shares suffices for decryption.
- `just test-all`: Full test suite across Rust, Noir, and Solidity.
- `just bench-scaling`: Scaling benchmarks (n=128 to 1024).

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): System design and protocol details.
- [SECURITY.md](SECURITY.md): Threat model, assumptions, and limitations.
- [REPRODUCING.md](REPRODUCING.md): Detailed steps for reproducing benchmarks.
- [WARNING.md](WARNING.md): Known cryptographic surrogates and their status.
- [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md): First audit (70 findings).
- [`.sisyphus/audit/AUDIT-2026-05-09.md`](.sisyphus/audit/AUDIT-2026-05-09.md): Second audit (188 findings).
- [`.sisyphus/audit/EXTERNAL-PACKET.md`](.sisyphus/audit/EXTERNAL-PACKET.md): External audit packet bundle.
- [`.sisyphus/plans/mpc-audit-remediation.md`](.sisyphus/plans/mpc-audit-remediation.md): MPC audit I — 14 findings.
- [`.sisyphus/plans/mpc-audit-post-migration.md`](.sisyphus/plans/mpc-audit-post-migration.md): MPC audit II — 8 findings.
- [`.sisyphus/plans/mpc-audit-final-pass.md`](.sisyphus/plans/mpc-audit-final-pass.md): MPC audit III — 3 findings.
- [`.sisyphus/design/threat-model-v1.md`](.sisyphus/design/threat-model-v1.md): Formal threat model and soundness budget.
- [`.sisyphus/design/`](.sisyphus/design/): Design documents (DKG, folding, NIZK, smudging, parameter freeze).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
