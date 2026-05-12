# Interfold Equivalence Matrix — PVTHFHE Target Statements Mapped to Interfold C0-C7

**Status**: draft (Batch A.1)
**Date**: 2026-05-11
**Plan**: `.sisyphus/plans/interfold-equivalent-pvss.md`

---

## Pinned Interfold Reference

| Field | Value |
|---|---|
| **Repository** | `gnosisguild/enclave` (the current monorepo) |
| **Commit** | `c7e98029193f548ac4575fd05d007b034b75385c` |
| **Branch** | `main` (as fetched 2026-05-11) |
| **Circuits path** | `circuits/bin/` |
| **Circuit index** | `circuits/README.md` |

**Historical note**: The archived `gnosisguild/pvss` repository is **not** the comparison target. That repo represented an earlier standalone PVSS implementation before the PVSS and PV-TBFV circuit layers were moved into the `enclave` monorepo. All comparisons in this document reference the current `gnosisguild/enclave/circuits` tree.

---

## Circuit-to-Module Equivalence Table

Each Interfold circuit (C0-C7) is mapped to the PVTHFHE module(s) that currently implement, approximate, or plan to cover the corresponding relation. Status values follow a simple taxonomy:

- **`implemented`**: A real, non-stub, verifiable relation exists in the current codebase and is exercised by tests.
- **`partial`**: Some structure exists (types, sketch, hash placeholder, or related logic) but the relation is not fully proved or is missing critical sub-relations.
- **`missing`**: No corresponding module or logic exists in the current codebase.
- **`deferred-with-rationale`**: Intentionally postponed with a documented reason in the plan or architecture.

| Interfold ID | Interfold Path | `CircuitName` Enum | Guarantee Role (1 sentence) | PVTHFHE Module(s) | Status | Rationale |
|---|---|---|---|---|---|---|
| **C0** | `circuits/bin/dkg/pk` | `PkBfv` | Commit to each party's individual BFV public key. | `crates/pvthfhe-keygen-spec` (`Commitment`, `KeygenSession`), `crates/pvthfhe-keygen/src/dkg.rs` | **partial** | `keygen-spec` defines `Commitment` (scheme + digest) and `KeygenSession` types. The DKG ceremony (`dkg.rs`) generates per-party keygen shares and aggregates a collective public key, but there is no circuit-style proof that each individual BFV pk was committed to during DKG. The `Commitment` type is generic (no BFV-specific binding), and individual pk commitments are not surfaced as public verification outputs. |
| **C1** | `circuits/bin/threshold/pk_generation` | `PkGeneration` | Prove threshold public-key contribution and commit to threshold secret material and smudging material. | `crates/pvthfhe-keygen-spec` (`PublicVerificationArtifact`, `BfvPublicKey`), `crates/pvthfhe-pvss/src/encrypt.rs` (`deal`) | **partial** | `PublicVerificationArtifact` carries `share_commitments`, `transcript_root`, and `proof_bytes` — the skeleton of a public pk-contribution verification. However, the type only tracks the dealer's share commitments, not a threshold-wide pk contribution with committed `sk` and `e_sm` secret material as C1 requires. No `e_sm` commitment exists in any current type; the `bfv_derivation_label` in `BFVPublicKey` is a stub (format strings appended to hex). |
| **C2a** | `circuits/bin/dkg/sk_share_computation` | `SkShareComputation` | Prove Shamir / Reed-Solomon structure for secret-key shares. | `crates/pvthfhe-pvss/src/shamir.rs` | **partial** | `shamir.rs` implements BN254-scalar Shamir `split` and `recover` with Lagrange interpolation. This covers the functional behaviour of C2a (the computation itself works) but there is **no proof** that the shares lie on a degree-`(t-1)` polynomial (no batched RS parity proof, no low-degree check). The existing code computes Shamir shares correctly; it does not generate a verifiable proof of that computation. |
| **C2b** | `circuits/bin/dkg/e_sm_share_computation` | `ESmShareComputation` | Prove Shamir / Reed-Solomon structure for smudging-noise shares. | `crates/pvthfhe-cyclo/src/lib.rs` (`FoldTrackKind::ESm`, `MultiTrackFoldMetadata`), `crates/pvthfhe-fhe/src/fhers.rs` (`partial_decrypt_committed_smudge`) | **partial** | Two-track infrastructure exists in `pvthfhe-cyclo`: `FoldTrackKind::ESm` variant, `MultiTrackFoldMetadata` with per-track commitments and norm bounds, and `validate_for_instance()` cross-track replay rejection. The `FhersBackend` has `partial_decrypt_committed_smudge()` which accepts a committed `e_sm` polynomial. However: no Shamir-split or Shamir-validity proof for `e_sm` shares exists yet; the smudge slots are not yet DKG-committed via a public transcript. The plumbing is ready; the proof circuit is not. |
| **C3** | `circuits/bin/dkg/share_encryption` | `ShareEncryption` | Prove BFV encryption of DKG shares under recipient individual BFV keys. | `crates/pvthfhe-pvss/src/nizk_share.rs`, `crates/pvthfhe-pvss/src/encrypt.rs` (`deal`) | **partial** | `nizk_share.rs` implements a Fiat-Shamir NIZK for share well-formedness with a real Ajtai commitment and lattice-binding tag. However, the proof relies on a **hash-based commitment verification** (`compute_share_commitment` uses SHA-256, not a lattice relation check) and the verifier confirms the BFV encryption via the FHE backend rather than via a Greco/BFV-specific relation. The binding is D2-preimage (SHA-256 of share + session), which is real but not BFV-native — a Greco-equivalent BFV encryption relation is not yet wired. The `deal` method in `encrypt.rs` wires the full flow (Shamir split → encrypt → prove), so the pipeline exists; the proof is just not a full Greco BFV well-formedness proof. The concrete adapter `LatticePvssBfvAdapter` (defined in `crates/pvthfhe-pvss/src/encrypt.rs` at line 43, `BACKEND_ID = "lattice-pvss-bfv-d2"`) implements `PvssAdapter` and wires the full flow: Shamir split (`shamir::split`) → BFV encrypt via `FhersBackend` → NIZK prove via `ShareNizkProver` → return `EncryptedShares`. The adapter uses `ChaCha20Rng` seeded from `OsRng` for encryption randomness and the BFV sigma protocol (v4) for share-encryption NIZK proofs. |
| **C4** | `circuits/bin/dkg/share_decryption` | `DkgShareDecryption` | Prove decryption, opening, and aggregation of received DKG shares and commitments forwarded to P4. | `crates/pvthfhe-pvss/src/encrypt.rs` (`recover`, `verify_decrypted_share`, `verify_shares`) | **partial** | `recover` in `encrypt.rs` uses Lagrange interpolation to combine at least `t` decrypted shares back into the original secret, with per-share NIZK verification (`verify_decrypted_share` calls the Cyclo NIZK adapter) and duplicate-index detection. `verify_shares` checks all per-recipient NIZKs match their ciphertexts. The aggregation logic works end-to-end. However, the commitments forwarded to "P4" (Interfold's internal phase notation) are not produced — there is no `DkgAnchorSet` or aggregate share commitment output. The recovery step is functional but not wrapped in a provable circuit. |
| **C5** | `circuits/bin/threshold/pk_aggregation` | `PkAggregation` | Prove aggregation of honest public-key shares into the threshold pk. | `crates/pvthfhe-keygen/src/dkg.rs` (`aggregate_keygen`), `crates/pvthfhe-aggregator/src/folding/mod.rs` | **partial** | The DKG ceremony (`dkg.rs:108`) calls `backend.aggregate_keygen` to produce a collective public key from per-party shares. The aggregator crate (`folding/mod.rs`) has real Cyclo CCS-based folding with NormTracker, `fold`, and `fold_all`. But neither path produces a C5-style proof that the aggregated pk is the sum of honest individual contributions: the DKG ceremony aggregates keys internally without a public transcript; the aggregator folding targets decryption-share instances, not pk-contribution aggregation. The `PublicVerificationArtifact` type has `share_commitments` but does not encode pk-contribution aggregation. |
| **C6** | `circuits/bin/threshold/share_decryption` | `ThresholdShareDecryption` | Prove partial decryption uses committed aggregated `sk` and committed aggregated `e_sm`. | `crates/pvthfhe-pvss/src/nizk_decrypt.rs`, `crates/pvthfhe-fhe/src/fhers.rs` (`partial_decrypt`) | **partial** | `nizk_decrypt.rs` wraps the Cyclo/Ajtai NIZK adapter to prove `d_i = c*s_i + e_i` with bounded error. The adapter (`CycloNizkAdapter`) is real lattice-based (not a hash placeholder) and the verifier checks the RLWE relation. However: (a) the proof uses a pk-derived binding (`derive_party_binding`) rather than a committed aggregated sk; (b) there is no committed `e_sm` — the `DecryptNizkWitness` carries `decryption_noise` bytes but these are local, not DKG-committed; (c) the smudging in `partial_decrypt` (line 578 of `fhers.rs`) samples fresh noise per-call, disconnected from any DKG transcript. Without committed sk and committed e_sm, this is not a C6-equivalent proof. |
| **C7** | `circuits/bin/threshold/decrypted_shares_aggregation` | `DecryptedSharesAggregation` | Prove Lagrange combination, CRT reconstruction, and decoding. | (none) | **missing** | No final aggregation proof module exists. `recover` in `encrypt.rs` performs Lagrange interpolation and byte reconstruction from Fr elements, but this is done locally in Rust, not in a circuit, and produces no proof that the combination is correct. There are no proofs for: participant selection correctness, Lagrange coefficient correctness, CRT reconstruction correctness, or BFV plaintext decoding correctness. This is the final "missing" link in the chain — the aggregator can recover a plaintext, but a public verifier cannot check the reconstruction without redoing it from scratch. A **Noir circuit** (planned under Batch G, `.sisyphus/plans/interfold-equivalent-pvss.md` §Batch G) would prove the full Lagrange + CRT + decode chain; this remains open and is tracked as a deferred circuit-design task. |

---

## Key Differences in Proof Architecture

The target relationship between PVTHFHE and Interfold is:

> **Same objects verified; different proof architecture.**

Interfold proves each guarantee with a separate Noir circuit (C2a, C2b, C3, C4, C6, C7) and uses recursive proof aggregation (`circuits/bin/recursive_aggregation/`) with wrapper circuits that re-verify inner proofs and compress public inputs. This means the DKG stage runs at least two separate Shamir share-computation circuits (one for `sk`, one for `e_sm`), separate BFV encryption circuits per share, and separate decryption/aggregation circuits — each producing independent proofs that are later folded or wrapped.

PVTHFHE targets a **batched two-track lattice proof** architecture:

- A single proof (or a folded instance) covers both `sk` and `e_sm` tracks simultaneously: Shamir validity for both tracks, BFV encryption of both track shares, and commitment binding to the same transcript root.
- Instead of separate C2a/C2b circuits, PVTHFHE baches the share-computation relations into one lattice statement.
- Instead of repeated C3/C4-style per-recipient encryption proofs, PVTHFHE folds per-recipient proof instances into a single compressed proof using Cyclo CCS-based folding with `NormTracker`.
- The folding/compression layer (Sonobe Nova IVC) targets O(polylog n) verifier cost, while Interfold's wrapper circuits target a different cost model.

The architectural differences are summarised:

| Aspect | Interfold (current) | PVTHFHE (target) |
|---|---|---|
| sk and e_sm tracks | Separate C2a/C2b circuits, each with its own proof | Single batched two-track lattice statement |
| Share encryption | Per-recipient C3 proofs, then recursive wrapping | Per-recipient instances folded into one compressed proof |
| Share decryption/aggregation | Separate C4 circuit per recipient, then aggregation | Single folded aggregation proof (C4-equivalent baked into fold tree) |
| pk contribution | C1 pk generation circuit with committed sk/e_sm | Batched pk contribution + sk/e_sm commitment in one foldable instance |
| Threshold decryption | C6 circuit with committed aggregated sk and e_sm per party | Folded decryption-share proof with DKG-root binding |
| Final decryption aggregation | C7 circuit proving Lagrange/CRT/decode | Planned folded final aggregation proof (C7-equivalent, Batch G) |
| Proof compression | Recursive wrapper circuits | Sonobe Nova IVC compression over BN254+grumpkin |
| Verifier cost | Depends on recursive aggregation depth | Target: O(polylog n) or constant after compression |

---

## Component Mapping: PVTHFHE Modules to Interfold Circuits

| PVTHFHE Module | Interfold Circuit(s) | Role |
|---|---|---|
| `crates/pvthfhe-pvss/src/encrypt.rs` (`LatticePvssBfvAdapter`) | C3 (ShareEncryption), C4 (DkgShareDecryption) | BFV-backed PVSS adapter; provides `deal()` (encrypt+prove) and `recover()` (verify+reconstruct) |
| `crates/pvthfhe-pvss/src/nizk_share.rs` (`ShareNizkProver`) | C3 (ShareEncryption) | v4 BFV sigma NIZK; proves encryption well-formedness per recipient |
| `crates/pvthfhe-pvss/src/nizk_decrypt.rs` (`DecryptNizkProver`) | C6 (ThresholdShareDecryption) | Per-party decryption share NIZK; wraps CycloNizkAdapter |
| `crates/pvthfhe-pvss/src/shamir.rs` | C2a (SkShareComputation) | BN254-scalar Shamir split/recover (no proof) |
| `crates/pvthfhe-cyclo/src/lib.rs` (`FoldTrackKind`, `MultiTrackFoldMetadata`) | C2a, C2b (two-track infra) | Multi-track fold metadata; sk + e_sm + encryption witness tracks |
| `crates/pvthfhe-fhe/src/fhers.rs` (`FhersBackend`) | C0 (PkBfv), C1 (PkGeneration), C6 (ThresholdShareDecryption) | Concrete BFV backend; provides encrypt, partial_decrypt, partial_decrypt_committed_smudge |
| `crates/pvthfhe-keygen/src/dkg.rs` | C0 (PkBfv), C5 (PkAggregation) | DKG ceremony; generates per-party keygen shares, aggregates collective pk |
| `crates/pvthfhe-aggregator/src/folding/mod.rs` | C5 (PkAggregation), C6 (ThresholdShareDecryption) | Cyclo CCS-based folding with NormTracker |

## Summary

| Status | Count | Circuits |
|---|---|---|
| `implemented` | 0 | (none currently reach full implementation) |
| `partial` | 8 | C0, C1, C2a, **C2b**, C3, C4, C5, C6 |
| `missing` | 1 | C7 |
| `deferred-with-rationale` | 0 | (none) |

The two-track infrastructure for C2b (`FoldTrackKind::ESm`, `MultiTrackFoldMetadata`, `partial_decrypt_committed_smudge`) has moved it from `missing` to `partial`. C7 (final decryption aggregation) remains the largest gap between PVTHFHE's current state and the Interfold guarantee surface. The `partial` entries are further along: types exist, Shamir implementation works, encryption/decryption flows are wired, and the NIZK layer has real lattice proofs (though not yet the full Greco BFV well-formedness relation). Closing C2b and C7 is the primary architectural work of Batches C through G in the plan.

---

*Document maintained under `.sisyphus/design/`. Reference commit pinned above. Update commit hash and statuses after each batch gate passes.*
