# Security

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **on-chain verifier uses Sonobe substitution (off-chain Sonobe + on-chain commitment)**
> - **Noir circuits implement the real aggregation and wrapping logic**
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Implementation status

- **FHE backend**: real threshold BFV via `gnosisguild/fhe.rs`, under an **honest-but-curious** threat model.
- **Greco / well-formedness ZK proofs**: **Implemented** (CycloNizkAdapter + bfv_sigma.rs, conditional soundness — see P1).
- **Folding accumulator**: implemented via Sonobe substitution.
- **On-chain verifier**: real UltraHonk verifier (committing to Sonobe state) + off-chain attestation.

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

- **P1 (CRITICAL)**: **Lattice NIZK Soundness**. P1 (CRITICAL): Per-share RLWE NIZK knowledge soundness is conditional on (a) Module-SIS hardness over R_{q_commit}, (b) Cyclo Theorem 3 soundness (ePrint 2026/359), and (c) collision resistance of SHA-256 for the P4 commitment domain. Formal joint-extractor proof (T2) is deferred. Any relying party must treat per-share proofs as computationally binding under these assumptions only. Sigma masking seeds: fresh per proof (OsRng, non-deterministic). **Keygen NIZK stubs**: `KeygenSimulator` uses a hardcoded `nizk: vec![0x00, 0x01]` placeholder. No verifiable lattice NIZK exists for dealer key shares or public-key contributions. Real lattice NIZK for key shares requires wiring `CycloNizkAdapter` per dealer. See `interfold-equivalence.md` §C1.
- **P2 (HIGH)**: **LatticeFold+ Linearity**. Real — Cyclo LatticeFold+ over RLWE, T=10, Lemma 9 heuristic (conditional soundness). The active backend is `cyclo-rlwe-t10-lemma9-heuristic`; soundness remains conditional on M-SIS hardness over R_{q_commit}, Cyclo Theorem 3 (ePrint 2026/359), and the Lemma 9 invertibility heuristic, while the joint extractor (T2) remains a skeleton.
- **P3 (MEDIUM)**: **MicroNova-lattice Encoding**. Substitituted by off-chain Sonobe + on-chain commitment topology. The aggregator submits an UltraHonk proof of the Sonobe state commitment, which is checked on-chain alongside an off-chain attestation.
- **C5 (PK Aggregation Gap)**: **No verifiable PK aggregation proof**. The DKG ceremony aggregates public keys internally via `ShareManager` without producing a public transcript or verifiable proof that `pk_agg = Σ pk_i` for the accepted participant set. Neither the DKG ceremony nor the aggregator folding produces a C5-equivalent proof. See `interfold-equivalence.md` §C5.
- **Aggregate decryption**: Correctness is trusted — no verifiable proof exists for participant selection, Lagrange coefficients, or decimal decoding (C7 pending).
- **C3 (Share Encryption Gap)**: **Algebraic sigma proves hash-preimage, not Shamir/BFV structure**. The verifier checks hash bindings but cannot independently confirm that the ciphertext encrypts the committed share under the recipient's BFV public key. The D.1 containment fails closed. See `interfold-equivalence.md` §C3.
- **C2 (Encryption Correctness Gap)**: **Encryption is trusted; no verifiable proof of correct encryption exists**. `backend.encrypt()` produces a ciphertext without a proof that it matches the plaintext under the aggregate key. A malicious encryptor can produce a semantically incorrect ciphertext. Mitigation: the semantic roundtrip check detects errors at the aggregate level only. See `threat-model-v1.md` §7.2 item 12.
- **C7 (Final Aggregation Gap)**: **No verifiable Lagrange+CRT+decode proof**. The Noir toy circuit (N=8, direct Lagrange) does not verify Cyclo accumulators, MicroNova proofs, or perform full BFV reconstruction. `recover` runs locally in Rust without producing a proof. See `interfold-equivalence.md` §C7.
- **Bench stub phases**: `onchain_verify`, `noir_decrypt_share`, `noir_aggregator_final`, `noir_sonobe_wrap` phases in the bench binary (`pvthfhe_e2e.rs`) are timing-only markers. No Solidity verifier or Noir circuit is executed during these phases. See `.sisyphus/design/spec-real-p2p3.md` §6 for the production verification plan.

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
