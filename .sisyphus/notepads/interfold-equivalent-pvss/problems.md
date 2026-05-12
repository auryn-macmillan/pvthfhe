# Problems — interfold-equivalent-pvss

## 2026-05-11 — D.1 blocked: no verifier-checkable BFV share-encryption relation in v3 proofs

- Atlas review found the v3 share proof forgeable by directly constructing `ShareNizkOpenedProof` around arbitrary `ciphertext_u` while recomputing all public digest bindings.
- A RED regression now demonstrates this attack path without calling `ShareNizkProver::prove` for the final proof object.
- Existing public verifier primitives only validate the committed-share algebraic Sigma relation and hash bindings. They do not prove `ciphertext_u` encrypts that same hidden committed share under `recipient_pk`.
- Prover-side BFV replay via `encrypt_with_witness` is insufficient because malicious proof bytes can bypass the honest prover.
- A complete fix requires a new non-leaking proof section (for example a v4 multi-relation BFV sigma/Greco proof) tying the same hidden plaintext and encryption randomness/noise to the BFV equations and to the share commitment. Current code should not fake this with digest bindings or witness openings.
- Current containment is fail-closed verification for v3 share proofs. Consequently `just pvss-gate` fails at CLI lattice PVSS e2e and must remain blocked until the real BFV relation proof exists.

## 2026-05-11 — D.2 gate evidence: pvss-gate still blocked only by D.1 fail-closed CLI e2e

- After adding the D.2 batched `sk`/`e_sm` proof surface and e_sm-only tamper regression, `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss` passes.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just pvss-gate` still fails at `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss`.
- Failure evidence: `[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation` followed by `pvss verify_shares: PVSS lattice binding verification failed`.
- This is the documented D.1 fail-closed containment, not a D.2 batched-binding failure. Do not weaken v3 verification or accept digest-only BFV bindings to make the gate pass.

## 2026-05-11 — E.2 gate evidence: pvss-gate remains blocked only by D.1 fail-closed CLI e2e

- After adding the E.2 recipient-side DKG share aggregation checker and anchor-output helpers, focused E.2 tests pass and `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss` passes.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-keygen-spec` also passes after wiring PVSS to keygen-spec anchor types.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just pvss-gate` still fails only at `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss`.
- Failure evidence: `[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation` followed by `pvss verify_shares: PVSS lattice binding verification failed`.
- This is the documented D.1 fail-closed containment, not an E.2 aggregation/anchor failure. Do not weaken v3 share-encryption verification to make the gate pass.

## 2026-05-11 — E.3 follow-on: on-chain/circuit participant-set digest canonicalization remains broader work

- This E.3 unit binds the explicit accepted set into off-chain `DkgAnchorSet` roots and PVSS recipient aggregation anchor verification.
- Background trace found broader end-to-end gaps outside this atomic unit: the aggregator decryption API still accepts a caller-supplied `allowed_parties` list, `circuits/aggregator_final` uses a `participant_set_hash` public input without reconstructing the explicit list, and `PvtFheVerifier.sol` does not compare the proof `participantSetHash` to `SessionRegistry`'s stored roster hash.
- There is also a canonicalization mismatch to resolve in a later task: keygen-spec/PVSS currently uses SHA-256/lowercase hex for DKG anchors, while `SessionRegistry` stores an on-chain roster hash with keccak-style semantics. Do not silently conflate these digests; standardize or add an explicit on-chain-compatible roster digest in a follow-on.
- D.1 remains fail-closed for BFV share-encryption relation verification; no witness openings, plaintext shares, seeds, or BFV randomness were added to public proof objects for E.3.

## 2026-05-11 — F.1 gate evidence: pvss-gate remains blocked only by D.1 fail-closed CLI e2e

- After F.1 committed-smudge decrypt NIZK changes, `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss` passes, including the new committed-smudge decrypt tests.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just pvss-gate` still fails only at `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss`.
- Failure evidence remains the known D.1 containment: `[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation` followed by `pvss verify_shares: PVSS lattice binding verification failed`.
- This is unrelated to F.1 threshold-decryption committed-smudge binding; do not weaken D.1 share-encryption verification to make this gate pass.

## 2026-05-11 — F.2 verification note: full contract suite has unrelated UltraHonk fixture failure

- F.2 focused contract tests pass after adding the public smudge-slot registry and verifier acceptance hook.
- `forge test --root contracts` compiles and runs most suites, but still has one unrelated failure in `test/UltraHonkVerifier.t.sol:UltraHonkVerifierTest.test_valid_proof_verifies` with `valid proof must verify`.
- This failure is in the existing UltraHonk generated/fixture path and is not caused by F.2 smudge-slot registry logic; the F.2-affected suites pass independently:
  - `forge test --root contracts --match-contract SessionRegistryTest -vv`: 26/26 pass.
  - `forge test --root contracts --match-contract PvtFheVerifierTest -vv`: 14/14 pass.
- Solidity LSP diagnostics are unavailable in this environment (`No LSP server configured for extension: .sol`), so `forge test` compilation plus `forge fmt --check` on modified files were used as the verification gate.

## 2026-05-11 — G.1 follow-on: pre-existing aggregator partial-decrypt NIZK surrogate tests still fail

- G.1 added the final aggregation proof relation surface and focused G.1 tests pass, but broader aggregator decrypt guard tests still expose a pre-existing surrogate path in `crates/pvthfhe-aggregator/src/decrypt/mod.rs` that is outside this atomic G.1 proof-relation unit.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test decrypt_aggregation_real_nizk` fails because `partial_decrypt` still returns hardcoded `nizk: vec![1]`, `pk_i_hash: [0u8; 32]`, and `aggregate_decrypt` still contains the old `payload.nizk[0] != 1` surrogate check.
- Exact failure summary: `no_hardcoded_nizk_or_zero_pk_hash_in_source` reports hardcoded `vec![1]`; `no_trivial_nizk_byte_check_in_source` reports `L157: if payload.nizk.is_empty() || payload.nizk[0] != 1 {`.
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test no_plaintext_without_proof` also fails because tampering bytes after the leading `1` in a mock share NIZK is still accepted and returns plaintext (`Ok([2, 2, 3, 0])`).
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test decrypt_rejections` fails to compile because the test expects a `DecryptError::NizkVerify { party_id }` variant that the current enum does not define.
- These failures are not introduced by G.1's final aggregation statement/proof validation; they are the existing aggregator per-share proof production/verification gap noted by the older RED tests. Fixing them requires a separate unit that wires real `DecryptNizkProver`/`DecryptNizkVerifier` into aggregator partial-share handling.

## 2026-05-11 — H.1 blocker note

- No new H.1 blockers were found in focused verification. H.1-focused commands passed:
  - `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test public_anchor_surface`: 3/3 pass.
  - `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test final_aggregation_proof`: 10/10 pass.
  - `cargo test -p pvthfhe-compressor --test compressed_anchor_surface`: 2/2 pass.
  - `forge test --root contracts --match-contract PublicAnchorSurfaceTest -vv`: 3/3 pass.
  - `forge test --root contracts --match-contract PvtFheVerifierTest -vv`: 14/14 pass.
- Observed warnings are pre-existing/unrelated: Rust missing-doc warnings in existing test/build files and `pvthfhe-cyclo`, plus Solidity warnings in `SurrogateNotice.sol` and existing mutability suggestions in `PvtFheVerifier.t.sol`.

## 2026-05-11 — H.2 blocker note

- No new H.2 blockers were found in focused verification.
- Observed warnings are pre-existing/unrelated: `pvthfhe-cyclo` missing-doc warnings for existing modules/functions and an unused import in `extension.rs`, plus existing aggregator/PVSS missing-doc/build-script warnings.
- Broader known aggregator per-share NIZK surrogate blockers remain out of scope for H.2 and were not modified.


## 2026-05-11 — H.3 blocker note

- No new H.3 blockers were found in focused verification.
- Observed Solidity warnings are pre-existing/unrelated: `SurrogateNotice.sol` unused local variable and existing mutability suggestions in `PvtFheVerifier.t.sol`.
- The H.3 contract tests used the existing placeholder `HonkVerifier` behavior for proof acceptance (`keccak256(proof) == publicInputs[0]`), then checked anchors before epoch consumption; this does not address the unrelated UltraHonk fixture failure documented earlier.
- D.1 fail-closed share-encryption relation was not weakened; no witness openings or private BFV/smudge material were added to public verifier storage or tests.


## 2026-05-11T22:53:38Z — I.1 blocker: fair two-track overhead benchmark unavailable on current branch

- Full non-bypassed benchmark probe command: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e -- --n 5 --t 2 --seed 1 --dry-run`.
- Exact failure recorded in `bench/results/i1-one-vs-two-track.json`: return code 1 with `[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation` and `Error: pvss verify_shares: PVSS lattice binding verification failed`.
- This is the known D.1 fail-closed containment and was not weakened for benchmarking.
- The one-track fallback uses `--features demo-seeded-rng`, which skips `verify_shares`; it is therefore labeled fallback/dryrun, not a full apples-to-apples benchmark.
- The two-track sk/e_sm DKG proof-producing path is represented by focused batched-proof tests, but it is not integrated into `pvthfhe-e2e` or a real-BFV benchmark runner that emits comparable DKG prover time, verifier time, fold/compression time, proof/wire size, and peak memory.
- Focused committed-smudge decrypt tests measure a real FhersBackend code path, but only as whole test-command wall time including setup/keygen/encrypt; it is not a per-party decryption proof benchmark.
- Result artifact gate status: `not_fairly_measurable_current_branch`; overhead ratio is `unavailable` with reason preserved in JSON/Markdown.

## 2026-05-11 I.2 Comparison Caveats
- Documented that D.1 remains a fail-closed blocker for complete share encryption proof soundness.
- Noted that two track DKG proof producing path metrics are currently unavailable (`not_fairly_measurable_current_branch`) and depend on dry-run fallbacks.

## 2026-05-11 — Batch I.3: Proof limitation - distributional sampling

- The security note documents a limitation regarding the distributional sampling of smudging noise (`e_sm`).
- If only boundedness (norm) is proved, a malicious prover could sample from a distribution that leaks information while still being within the bound.
- This remains an open theoretical gap in the current prototype's relation enforcement.

## 2026-05-12 — D.1 re-check: real BFV verifier relation still blocked by current public APIs

- Re-read `nizk_share.rs`, D.1/D.3 tests, `FheBackend`, `FhersBackend`, witness types, and the R3.1/R3.4 design notes before editing.
- Existing `encrypt_with_witness` / `try_encrypt_extended` support is prover-side only: it exposes plaintext, encryption randomness `u`, and BFV error polys to the prover, but there is no public verifier gadget or non-leaking proof object for the BFV modular equations.
- Publishing the available witness polys, deterministic seeds, raw quotient terms, or reduction openings would violate the D.1 privacy constraints. No safe real verifier-checkable BFV relation was implemented.
- Preserved the current fail-closed v3 boundary (`[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation`) rather than adding a hash-only acceptance path.
- Added a focused regression in `nizk_share_soundness.rs` that directly constructs `ShareNizkOpenedProof` for a ciphertext encrypting share A while the algebraic proof/share commitment bind share B; public verification rejects it under fail-closed containment.
- Verification: focused D.1 commands and full `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss` pass. `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just pvss-gate` remains intentionally blocked only at CLI lattice PVSS e2e with the known D.1 fail-closed message.

## 2026-05-12 — Acceptance benchmark criterion remains blocked: no fair current-branch advantage measurement

- Bounded non-bypassed benchmark probe command: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo run -p pvthfhe-cli --bin pvthfhe-e2e -- --n 5 --t 2 --seed 1 --dry-run`.
- Return code: `1`.
- Failure mode: `[NIZK-VERIFY] FAIL: v3 proof lacks verifier-checkable BFV encryption relation` followed by `Error: pvss verify_shares: PVSS lattice binding verification failed`.
- Interpretation: D.1 fail-closed containment is still active and must not be bypassed for an acceptance-level benchmark. The existing `bench/results/i1-one-vs-two-track.*` artifacts quantify fallback/dry-run one-track costs and focused non-comparable two-track probes, but they do not demonstrate the intended PVTHFHE performance advantage or the `<= 1.5x` two-track DKG overhead target.
- Missing path: an integrated real-BFV one-track/two-track benchmark runner that does not use `demo-seeded-rng` or dry-run bypasses and emits comparable DKG prover time, verifier time, fold/compression time, proof/wire size, and peak memory for the proof-producing DKG path.

## 2026-05-12 — Final boulder blocker state: D.1 cryptographic prerequisite remains

- Remaining unchecked plan items are the D.1 GREEN/GATE requirements and the acceptance criterion requiring a real BFV encryption relation with explicit witnesses.
- Oracle feasibility review rejected implementing D.1 with current APIs: the repo has prover-side `EncryptionWitness` extraction but lacks a non-leaking public verifier gadget/proof for BFV modular equations, bounded hidden plaintext/randomness/noise, and quotient/reduction terms.
- Atlas marked only independently verified evidence/benchmark bookkeeping items complete. The real BFV relation items remain unchecked to avoid falsely claiming completion.
- Next required work is a new cryptographic proof component, likely in `pvthfhe-nizk` plus `pvthfhe-pvss`, that proves BFV encryption correctness in zero knowledge and binds the proof to session, dealer, recipient, params digest, DKG root, ciphertexts, recipient pk commitment, and share commitment.

## 2026-05-12 — D.1 implementation aborted: missing ZK primitives in pvthfhe-nizk

- Attempted to implement the D.1 GREEN/GATE requirements for a real verifier-checkable BFV encryption relation.
- Implementation is impossible because `pvthfhe-nizk` currently only supports Schnorr-style Sigma protocols for simple RLWE relations (`d_i = c * s_i + e_i (mod Q)`) and lacks the necessary cryptographic primitives for BFV encryption.
- Exact missing primitives include:
  1. **No polynomial commitment scheme / opening protocol** capable of hiding the BFV plaintext share `m` and encryption randomness `u` while proving properties about them.
  2. **No zero-knowledge range proof** to prove that the hidden encryption noise/error polynomials (`e0`, `e1`) and randomness (`u`) are bounded, which is required for BFV soundness.
  3. **No verifier arithmetization or modular quotient proof** to zero-knowledge prove the BFV modular equations (`c0 = pk_0 * u + e0 + m * (Q/t) (mod Q)` and `c1 = pk_1 * u + e1 (mod Q)`) without leaking the witness polynomials.
- Without these primitives, any attempt to construct the proof would either fail to bind the relation cryptographically or would leak secret witness material (plaintext shares, BFV randomness, error polynomials), violating the D.1 privacy constraints.
- Plan checkboxes remain untouched. The D.1 blocker stands until a new non-leaking proof section (e.g., a generalized multi-relation BFV sigma protocol or generic ZKP like Plonk/Halo2) is added to `pvthfhe-nizk`.

## 2026-05-12 — Enclave C3 / Greco assessment for D.1

- Checked the current Interfold/Enclave circuit docs and source paths after the background librarian research task failed due provider/model errors.
- `gnosisguild/enclave` explicitly maps `circuits/bin/dkg/share_encryption` to C3 `ShareEncryption`: "BFV encryption of shares under recipient keys". This is semantically the same relation needed by PVTHFHE D.1.
- Source evidence: `circuits/lib/src/core/dkg/share_encryption.nr` proves public-key commitment equality, message/share commitment equality, range bounds for `u`, `e0`, `e1`, message, pk, and quotient witnesses, CRT consistency for `e0`, computes scaled message `k1`, and verifies the BFV equations at Fiat-Shamir challenge points using Schwartz-Zippel batching:
  - `ct0[l](gamma) = pk0[l](gamma)*u(gamma) + e0[l](gamma) + k1(gamma)*k0[l] + r1[l](gamma)*q_l + r2[l](gamma)*(gamma^N + 1)`
  - `ct1[l](gamma) = pk1[l](gamma)*u(gamma) + e1(gamma) + p1[l](gamma)*q_l + p2[l](gamma)*(gamma^N + 1)`
- Interfold docs state C3 encrypts each DKG share under the recipient's individual key and that P3 user encryption uses a GRECO-style valid BFV encryption proof pattern. The `gnosisguild/greco` repo is described as an older Rust workspace for BFV encryption-correctness proof generation but notes the Greco Noir library moved into Enclave and is no longer maintained separately.
- Practical conclusion: Enclave C3/Greco can be used as a correctness specification and likely as a heavy fallback proof path for D.1, but adopting it directly means adding Noir/BB proof generation/verification and witness conversion for PVTHFHE share ciphertexts. At production BFV dimensions this is likely much heavier than the lattice-native direction motivating PVTHFHE.
- Preferred unblocker remains lattice-native: implement a native proof of knowledge of bounded hidden `(m, u, e0, e1, quotient terms)` satisfying the same C3 equations and bound/equality checks, avoiding generic Noir arithmetization where possible. The Enclave C3 equations and bound list should be the reference relation for that native proof.
