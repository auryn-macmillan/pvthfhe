# Stage 1 Learnings

## [2026-05-04] Initialization

### Locked Constraints
- FHE backend: `gnosisguild/fhe.rs` (locked)
- Ring backend: `fhe-math` from same repo, rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- Parameters: N=8192, log₂q≈174, B_e≈16 (6σ for σ=3.19)
- Design freeze: spec-real-p2p3.md §4.1 addendum selects BRANCH-B

### Key Public Inputs (7, from proof-boundary.md)
1. `ciphertext_hash` (bytes32 Keccak256)
2. `plaintext_hash` (bytes32 Keccak256)
3. `aggregate_pk_hash` (bytes32 Keccak256)
4. `dkg_root` (bytes32 Merkle root)
5. `epoch` (uint64)
6. `participant_set_hash` (bytes32 Keccak256)
7. `D_commitment` (bytes32 Keccak256)

### Stage 0 Preserved Invariants
- Stage 0 T2 build-time surrogate tripwire MUST survive Stage 1
- Stage 0 T3 opt-in mock policy (`PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1`) MUST survive Stage 1

### Forbidden Patterns
- No `#[allow]` suppressions
- No `nargo prove` / `nargo verify`
- No `cargo test --workspace`
- No `ConditionalSoundnessDisclosure` returning success
- No SHA-256 hash chain in production fold path
- No XOR-Merkle (must use Poseidon)

## [2026-05-05] T13-F2 Re-audit
- Reviewed , , , and .
- Check A passed: repo-wide grep  returned zero matches.
- Check B failed: repo-wide grep  returned two matches in  lines 77 and 234.
- Check C passed:  is absent from .
- Check D passed: no new  lines were added in Rust files since .
-  succeeded with warnings only.
- Verdict for T13-F2 re-audit: REJECT until the remaining production TODO markers are removed or re-scoped to satisfy check B.

## [2026-05-05] T13-F2 Re-audit
- Reviewed crates/pvthfhe-nizk/src/lib.rs, crates/pvthfhe-nizk/src/adapter.rs, crates/pvthfhe-fhe/src/mock_impl.rs, and crates/pvthfhe-fhe/src/real_nizk.rs.
- Check A passed: repo-wide grep Ok.*ConditionalSoundness returned zero matches.
- Check B failed: repo-wide grep TODO(N4)|TODO(F-series returned two matches in crates/pvthfhe-nizk/src/ajtai.rs lines 77 and 234.
- Check C passed: #[allow(dead_code)] is absent from crates/pvthfhe-fhe/src/mock_impl.rs.
- Check D passed: no new #[allow( lines were added in Rust files since d306ceb.
- cargo build -p pvthfhe-nizk -p pvthfhe-fhe succeeded with warnings only.
- Verdict for T13-F2 re-audit: REJECT until the remaining production TODO markers are removed or re-scoped to satisfy check B.

## R7.1+R7.2+R7.3 Implementation (2026-05-09)

### R7.1: Poseidon CRH Replacement
- Replaced `rolling_digest` (linear accumulator, non-CRH) with `poseidon::poseidon::bn254::sponge` with domain-separation tag prepended as first element.
- For 8-element binding hashes, used `poseidon::poseidon::bn254::hash_9` (8 elements + domain tag = arity 9).
- Domain tags defined in `protocol_constants` library: `DOMAIN_VECTOR_MERKLE`, `DOMAIN_STATEMENT_BINDING`, `DOMAIN_CHALLENGE_DERIVE`, `DOMAIN_CIPHERTEXT_BINDING`, `DOMAIN_DKG_BINDING`, `DOMAIN_AGGREGATOR_D_COMMIT`.
- N=8 for research prototype (production: N=8192).
- Added collision-finding tests (`test_collision_different_vectors_same_hash`, `test_collision_domain_tag_separation`) and relation-constraint tamper tests.

### R7.2: q Bound to Protocol Constant
- Removed `q` from function parameters in both circuits.
- `q` is now `protocol_constants::Q = 288230376173076481` (one of the RNS primes from the production backend).
- Added `z_q` witness for proper R3 relation: `rhs - lhs == Q * z_q`.
- Tests verify that wrong `z_q` values cause assertion failure.

### R7.3: share_wf Deletion
- DEFAULT decision: DELETE `share_wf` circuit.
- Rationale: `share_wf` was a surrogate for LatticeFold+ NIZK well-formedness proofs. R3 NIZK output from `decrypt_share` is what gets aggregated. No other Stage 1 task depends on `share_wf`.
- Removed from `circuits/Nargo.toml` workspace.
- Decision documented in `.sisyphus/notepads/redteam-stage1-cryptographic-core/decisions.md`.

### Test Results
- aggregator_final: 7 tests passed (2 collision, 1 honest, 4 tamper)
- decrypt_share: 8 tests passed (2 collision, 1 honest, 5 tamper)
- Retained circuits: 22 tests total
- `nargo execute --package aggregator_final --prover-name Prover_re`: exits 0

### Technical Notes
- Noir 1.0.0-beta.20 requires ASCII-only comments (replaced em-dashes with `--`).
- Library globals must be `pub` to be visible from dependent packages.
- `std::println` output captured with `nargo test --show-output`.
- `poseidon::poseidon::bn254::sponge` uses variable-length input (good for vector hashing with domain tag).
- `poseidon::poseidon::bn254::hash_N` requires exact arity, used for fixed-size bindings.

## [2026-05-10] Unique NIZK verification error variants

### Context
Task: Replace each `PvssError::InvalidShare` in `ShareNizkVerifier::verify` and its callees
with unique error variants so callers can distinguish which verification check failed.

### New PvssError variants added (7 total)
1. `InvalidDomainSeparator` — proof envelope domain separator mismatch
2. `StatementMismatch` — opened statement doesn't match verification statement
3. `ChallengeVerificationFailed` — Fiat-Shamir challenge recomputation doesn't match
4. `CiphertextVMismatch` — reconstructed ciphertext_v differs from statement
5. `InvalidCommitmentStructure` — commitment CT empty, too large, or unrecoverable
6. `LatticeBindingVerificationFailed` — lattice binding tag recomputation mismatch
7. `D2HashBindingFailed` — Ajtaï D2 hash binding / share commitment verification failed

### Changes made
- `lib.rs`: Added 7 variants to `PvssError`, updated `Debug` and `Display` impls
- `nizk_share.rs`: Updated verify body (split domain_separator||statement OR into two checks)
  and all callees: `verify_commitment_ct_validity`, `verify_lattice_binding`,
  `verify_d2_hash_binding`, `recover_share_from_commitment_ct`,
  `compute_ajtai_d2_binding`, `encode_share_as_ajtai_witness`

### Key decisions
- Kept `InvalidShare` variant for backward compatibility with non-verify-path uses
  (deserialization errors, validate_statement, validate_witness)
- Split the combined OR-check (domain_separator || statement) into two independent
  checks to provide distinct errors
- Used `InvalidCommitmentStructure` for both empty/too-large CT and unrecoverable CT
  (semantically related failures)
- Used `D2HashBindingFailed` for the entire Ajtaï computation chain (matrix creation,
  witness encoding, commitment computation) since they all contribute to the same
  verification

### Result
- `cargo build -p pvthfhe-pvss` — clean
- All existing tests pass (2 pre-existing failures in nizk_decrypt_soundness unchanged)
