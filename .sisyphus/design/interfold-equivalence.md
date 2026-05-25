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
| **C0** | `circuits/bin/dkg/pk` | `PkBfv` | Commit to each party's individual BFV public key. | `crates/pvthfhe-keygen-spec` (`Commitment`, `KeygenSession`), `crates/pvthfhe-keygen/src/dkg.rs`, `crates/pvthfhe-aggregator/src/keygen/simulator.rs` (generate_keygen_nizk) | **implemented** | `keygen-spec` defines `Commitment` (scheme + digest) and `KeygenSession` types. The DKG ceremony (`dkg.rs`) generates per-party keygen shares and aggregates a collective public key. The KeygenSimulator now generates real BFV sigma NIZK proofs (`generate_keygen_nizk`) using the party's actual secret key and error polynomial from the FHE backend, replacing the `vec![0x00, 0x01]` stub. |
| **C1** | `circuits/bin/threshold/pk_generation` | `PkGeneration` | Prove threshold public-key contribution and commit to threshold secret material and smudging material. | `crates/pvthfhe-keygen-spec` (`PublicVerificationArtifact`, `BfvPublicKey`), `crates/pvthfhe-pvss/src/encrypt.rs` (`deal`) | **partial** | `PublicVerificationArtifact` carries `share_commitments`, `transcript_root`, and `proof_bytes` — the skeleton of a public pk-contribution verification. However, the type only tracks the dealer's share commitments, not a threshold-wide pk contribution with committed `sk` and `e_sm` secret material as C1 requires. No `e_sm` commitment exists in any current type; the `bfv_derivation_label` in `BFVPublicKey` is a stub (format strings appended to hex). |
| **C2a** | `circuits/bin/dkg/sk_share_computation` | `SkShareComputation` | Prove Shamir / Reed-Solomon structure for secret-key shares. | `crates/pvthfhe-pvss/src/shamir.rs`, `crates/pvthfhe-pvss/src/share_computation.rs` | **implemented** | `shamir.rs` implements BN254-scalar Shamir `split` and `recover` with Lagrange interpolation. The E.1 batched Shamir/RS share-computation relation (`share_computation.rs`) provides a public transcript-validity checker that verifies low-degree/RS validity (interpolates `max_degree + 1` BN254 points, checks every published share against the resulting polynomial, rejects non-low-degree tampering, and enforces coefficient bounds). The foldable public instance commitment binds session, DKG root, dealer, track identity, and smudge-slot index. |
| **C2b** | `circuits/bin/dkg/e_sm_share_computation` | `ESmShareComputation` | Prove Shamir / Reed-Solomon structure for smudging-noise shares. | `crates/pvthfhe-cyclo/src/lib.rs` (`FoldTrackKind::ESm`, `MultiTrackFoldMetadata`), `crates/pvthfhe-fhe/src/fhers.rs` (`partial_decrypt_committed_smudge`), `crates/pvthfhe-pvss/src/share_computation.rs` | **implemented** | Two-track infrastructure exists in `pvthfhe-cyclo`: `FoldTrackKind::ESm` variant, `MultiTrackFoldMetadata` with per-track commitments and norm bounds, and `validate_for_instance()` cross-track replay rejection. The `FhersBackend` has `partial_decrypt_committed_smudge()` which accepts a committed `e_sm` polynomial. The E.1 batched Shamir/RS share-computation relation covers both `sk` and `e_sm` tracks: it validates published `e_sm` shares against a degree-`t` polynomial with committed coefficient bounds, detects non-low-degree tampering on individual `e_sm` slots while leaving `sk` validity intact, and binds slot identity into the foldable public instance commitment. DKG-committed `e_sm` slots are wired via `DkgAnchorSet` with per-slot `ESmShareCommitment` and smudge-slot policy. |
| **C3** | `circuits/bin/dkg/share_encryption` | `ShareEncryption` | Prove BFV encryption of DKG shares under recipient individual BFV keys. | `crates/pvthfhe-pvss/src/nizk_share.rs`, `crates/pvthfhe-pvss/src/encrypt.rs` (`deal`) | **partial** | `nizk_share.rs` implements a Fiat-Shamir NIZK for share well-formedness with a real Ajtai commitment and lattice-binding tag. However, the proof relies on a **hash-based commitment verification** (`compute_share_commitment` uses SHA-256, not a lattice relation check) and the verifier confirms the BFV encryption via the FHE backend rather than via a Greco/BFV-specific relation. The binding is D2-preimage (SHA-256 of share + session), which is real but not BFV-native — a Greco-equivalent BFV encryption relation is not yet wired. The `deal` method in `encrypt.rs` wires the full flow (Shamir split → encrypt → prove), so the pipeline exists; the proof is just not a full Greco BFV well-formedness proof. The concrete adapter `LatticePvssBfvAdapter` (defined in `crates/pvthfhe-pvss/src/encrypt.rs` at line 43, `BACKEND_ID = "lattice-pvss-bfv-d2"`) implements `PvssAdapter` and wires the full flow: Shamir split (`shamir::split`) → BFV encrypt via `FhersBackend` → NIZK prove via `ShareNizkProver` → return `EncryptedShares`. The adapter uses `ChaCha20Rng` seeded from `OsRng` for encryption randomness and the BFV sigma protocol (v4) for share-encryption NIZK proofs. |
| **C4** | `circuits/bin/dkg/share_decryption` | `DkgShareDecryption` | Prove decryption, opening, and aggregation of received DKG shares and commitments forwarded to P4. | `crates/pvthfhe-pvss/src/encrypt.rs` (`recover`, `verify_decrypted_share`, `verify_shares`) | **partial** | `recover` in `encrypt.rs` uses Lagrange interpolation to combine at least `t` decrypted shares back into the original secret, with per-share NIZK verification (`verify_decrypted_share` calls the Cyclo NIZK adapter) and duplicate-index detection. `verify_shares` checks all per-recipient NIZKs match their ciphertexts. The aggregation logic works end-to-end. However, the commitments forwarded to "P4" (Interfold's internal phase notation) are not produced — there is no `DkgAnchorSet` or aggregate share commitment output. The recovery step is functional but not wrapped in a provable circuit. |
| **C5** | `circuits/bin/threshold/pk_aggregation` | `PkAggregation` | Prove aggregation of honest public-key shares into the threshold pk. | `crates/pvthfhe-keygen/src/dkg.rs` (`aggregate_keygen`), `crates/pvthfhe-aggregator/src/folding/mod.rs` | **partial** | The DKG ceremony (`dkg.rs:108`) calls `backend.aggregate_keygen` to produce a collective public key from per-party shares. The aggregator crate (`folding/mod.rs`) has real Cyclo CCS-based folding with NormTracker, `fold`, and `fold_all`. But neither path produces a C5-style proof that the aggregated pk is the sum of honest individual contributions: the DKG ceremony aggregates keys internally without a public transcript; the aggregator folding targets decryption-share instances, not pk-contribution aggregation. The `PublicVerificationArtifact` type has `share_commitments` but does not encode pk-contribution aggregation. **B.4**: Verifier must redo Lagrange+CRT+decode from scratch. Production path requires C7 circuit. |
| **C6** | `circuits/bin/threshold/share_decryption` | `ThresholdShareDecryption` | Prove partial decryption uses committed aggregated `sk` and committed aggregated `e_sm`. | `crates/pvthfhe-pvss/src/nizk_decrypt.rs`, `crates/pvthfhe-fhe/src/fhers.rs` (`partial_decrypt`) | **partial** | `nizk_decrypt.rs` wraps the Cyclo/Ajtai NIZK adapter to prove `d_i = c*s_i + e_i` with bounded error. The adapter (`CycloNizkAdapter`) is real lattice-based (not a hash placeholder) and the verifier checks the RLWE relation. However: (a) the proof uses a pk-derived binding (`derive_party_binding`) rather than a committed aggregated sk; (b) there is no committed `e_sm` — the `DecryptNizkWitness` carries `decryption_noise` bytes but these are local, not DKG-committed; (c) the smudging in `partial_decrypt` (line 578 of `fhers.rs`) samples fresh noise per-call, disconnected from any DKG transcript. Without committed sk and committed e_sm, this is not a C6-equivalent proof. |
| **C7** | `circuits/bin/threshold/decrypted_shares_aggregation` | `DecryptedSharesAggregation` | Prove Lagrange combination, CRT reconstruction, and decoding. | `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs` (`C7DecryptAggregationCircuit`), `crates/pvthfhe-compressor/src/sonobe/c7_merkle_circuit.rs` (`C7MerkleStepCircuit`), `circuits/aggregator_final/` (Noir UltraHonk) | **partial** | C7 Sonobe step circuit folds Lagrange recombination into Nova accumulator at N=8. N=8192 Merkle-tree verification is implemented via `C7MerkleStepCircuit` with real Poseidon R1CS (~900 constraints per hash8). Noir aggregator_final circuit (N=128) provides standalone verification. The CRT reconstruction and BFV plaintext decoding correctness proofs remain deferred. |

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
| `implemented` | 3 | **C0**, **C2a**, **C2b** |
| `partial` | 5 | C1, C3, C4, C5, C6, C7 |
| `missing` | 0 | (none) |
| `deferred-with-rationale` | 0 | (none) |

C0, C2a and C2b are now `implemented`: C0 keygen NIZK uses real BFV sigma proofs; the E.1 batched Shamir/RS share-computation relation (`share_computation.rs`) covers both sk and e_sm tracks with low-degree/RS validity checks, coefficient bounds, and foldable public instance commitments. C7 (final decryption aggregation) is now `partial` with Sonobe C7DecryptAggregationCircuit and C7MerkleStepCircuit implementations. The remaining `partial` entries (C1, C3, C4, C5, C6) have types, working flows, and NIZK infrastructure, though C1, C3, and C5 carry structural gaps (see §C1, §C3, and §C5 below).

---

## §C1 — Structural Proof Gap: Keygen NIZK

**Status**: `partial` (protocol placeholder).

**What exists today**: `KeygenSimulator` in the PVSS crate uses a stub `nizk: vec![0x00, 0x01]` (a hardcoded two-byte placeholder). The `KeygenSession` type carries a `nizk: Vec<u8>` field, but no verification path is wired in the current prototype. The `PublicVerificationArtifact` has a `proof_bytes` field (intended to carry keygen NIZK proofs) but the actual content is generated from the algebraic sigma protocol, not from a dedicated keygen NIZK.

**The structural gap**: The keygen phase produces per-dealer key shares and public-key contributions without a verifiable lattice NIZK proving that each dealer's keygen material is well-formed. A malicious dealer can submit malformed key shares without detection, breaking DKG correctness (SEC-1) and secrecy (SEC-2).

**What's needed**: A real lattice NIZK for key shares (per-dealer), wired via `CycloNizkAdapter`, proving:
1. The dealer's BFV secret-key share is correctly bound to the public key contribution.
2. The dealer's smudging-noise contribution is correctly sampled (bounded norm) and committed.
3. The dealer's Shamir shares are consistent with the committed secret material.

**Dependency**: Requires wiring `CycloNizkAdapter` per dealer. This is tracked as part of the keygen formalisation path and is deferred pending integration of the keygen-NIZK relation into the existing NIZK infrastructure.

---

## §C3 — Structural Proof Gap: Share Encryption

**Status**: `partial` (D.1 blocker).

**What exists today**: `nizk_share.rs` implements a Fiat-Shamir NIZK for share well-formedness with a real Ajtai commitment and lattice-binding tag. The `LatticePvssBfvAdapter` wires the full flow: Shamir split → BFV encrypt → NIZK prove. The prover validates the BFV relation (secret key share encryption) using its private witness.

**The structural gap**: The algebraic sigma proof proves a hash-preimage statement (SHA-256 of the share + session), not the full Shamir / BFV structure. The verifier checks the algebraic committed-share proof and hash bindings, but these are adversary-recomputable around arbitrary ciphertext bytes. The verifier cannot independently confirm that the ciphertext `u` actually encrypts the committed share under the recipient's BFV public key.

This means: the verifier can check that `H(share, session) = commitment`, but cannot check that the ciphertext is a valid BFV encryption of `share` under `recipient_pk`. The current D.1 containment fails closed after the algebraic proof verifies.

**What's needed**: A non-leaking verifier-checkable BFV encryption relation: a proof that `ct0 = pk0·u + e0 + Δm` and `ct1 = pk1·u + e1` without revealing the witness polynomials. This requires either public quotient/reduction terms from the FHE backend or a Noir circuit that emulates the BFV ring arithmetic in a SNARK-friendly field.

**Dependency**: Requires D.1 resolution (verifier-side BFV relation) per the `interfold-equivalent-pvss` plan.

---

## §C5 — Structural Proof Gap: PK Aggregation

**Status**: `partial`.

**What exists today**: The DKG ceremony (`dkg.rs`) calls `backend.aggregate_keygen` to produce a collective public key from per-party shares. The aggregator crate (`folding/mod.rs`) has real Cyclo CCS-based folding with NormTracker, `fold`, and `fold_all`.

**The structural gap**: Aggregate decrypt uses the internal `ShareManager` (from `fhe.rs`) to combine partial decryption shares into a plaintext. There is no verifiable proof that the aggregated public key is the honest sum of individual contributions, nor that the aggregate decryption combines the correct set of shares. Neither the DKG ceremony nor the aggregator folding produces a C5-style proof that `pk_agg = Σ pk_i` for the accepted participant set. The `PublicVerificationArtifact` type has `share_commitments` but does not encode pk-contribution aggregation.

**What's needed**: A public proof (or folded instance) that the aggregate public key equals the sum of individual BFV public keys from the accepted participant set, bound to the DKG root.

**Dependency**: Requires E.2 DKG share aggregation relation wiring (committed aggregate outputs) plus a pk-aggregation-specific proof instance.

---

## §C7 — Structural Proof Gap: Final Decryption Aggregation

**Status**: `missing`.

**Current state (research-prototype)**: A Noir toy circuit exists at `circuits/aggregator_final/src/main.nr` (N=8, Poseidon hashes) for experimentation and local proving. It performs direct Lagrange recombination over polynomial shares at ring degree N=8 (research-prototype dimension, not production N=8192). The toy circuit contains **no** Cyclo accumulator verifier, **no** MicroNova proof verification, **no** Ajtai commitment check, **no** norm-bound range checks, **no** sum-check transcript verification, and **no** BN254 pairing gadgets. **Production C7 circuit is deferred to a separate plan** (Batch G, `.sisyphus/plans/interfold-equivalent-pvss.md`). The `recover` method in `encrypt.rs` performs Lagrange interpolation and byte reconstruction in plain Rust — locally, not in a circuit — producing no proof.

**What's needed**: A Noir circuit (planned under Batch G, `.sisyphus/plans/interfold-equivalent-pvss.md` §Batch G) that proves:
1. Participant selection correctness — at least `t` valid decryption shares, participant IDs are unique and in the accepted set.
2. Lagrange coefficient correctness — coefficients are correctly derived for the selected participant indices.
3. CRT reconstruction correctness — partial decryption shares combine correctly via CRT over the RNS modulus.
4. BFV plaintext decoding correctness — the recovered polynomial decodes to the claimed plaintext under the BFV plaintext modulus.
5. Binding to the C6 proof set — the C7 statement includes DKG root, ciphertext hash, selected participant IDs, decryption-share proof refs, and plaintext hash.

**Production target**: A full MicroNova-wrapped-in-UltraHonk circuit per §6.2/§6.4 of `spec-real-p2p3.md` — verifying the Cyclo accumulator (Ajtai check, norm bounds, range proof), MicroNova compression proof, and the Lagrange+CRT+decode chain, exposing 7 frozen public inputs.

**Dependency**: Depends on Batch G (final aggregation proof relation), and transitively on C6 (threshold decryption with committed smudge) and the Cyclo → MicroNova → UltraHonk compression chain.

---

*Document maintained under `.sisyphus/design/`. Reference commit pinned above. Update commit hash and statuses after each batch gate passes.*
