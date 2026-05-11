# Learnings — interfold-equivalent-pvss

## 2026-05-11 — Batch A.3: Freeze Target Relations in nizk-construction.md

### Document structure
- `nizk-construction.md` follows a clear pattern: status line → scope → context → candidates → comparison matrix → recommendation → integration sketch → open questions → references. Each major section is delimited by `---`.
- The existing R3.1 and R3.2 relation descriptions (lines 18-34) served as the template for the R3.4 relation descriptions, using a prose-heavy format with bold labels and inline code blocks.

### Domain separator conventions
- Codebase uses `"pvthfhe-{layer}-{purpose}-v{n}"` convention (e.g., `"pvthfhe-pvss-share-encryption-v2"`, `"pvthfhe-cyclo-fs-v1"`).
- The new R3.4 DS strings use `"pvthfhe-R-{relation-name}-v1"` pattern, consistent with the `"pvthfhe-"` prefix convention.
- The `"-R-"` infix distinguishes these as relation-bound domain separators rather than implementation-bound ones.

### Mapping to Interfold
- The five relations map to Interfold C0-C7 as follows:
  - R3.4.1 → C0 (pk) + C3 (ShareEncryption), batched for sk/e_sm
  - R3.4.2 → C2a (SkShareComputation) + C2b (ESmShareComputation), batched
  - R3.4.3 → C4 (DkgShareDecryption) + C5 (PkAggregation), two-track
  - R3.4.4 → C6 (ThresholdShareDecryption), committed-smudge extension
  - R3.4.5 → C7 (DecryptedSharesAggregation)
- C1 (PkGeneration) is captured across R3.4.2 (secret contributions) and R3.4.3 (aggregation).

### Editing approach
- Used two edit operations: one for the status line, one for the bulk content insertion before `## References`.
- The insertion anchor used a 4-line unique context snippet spanning the last paragraph of "Open Questions", the section separator, and the start of References.
- Nested the content within the existing `---` separator structure to maintain formatting consistency.
- File grew from 493 to 670 lines (177 lines added).

### Style notes
- The existing document uses em dashes (`—`) in prose (e.g., status line, description fields). New content followed this convention for consistency.
- All field descriptions use the pattern: `` `field_name: Type` — description ``.
- Commitment bindings use numbered lists for verificaton check descriptions.

## 2026-05-11 — Batch B.1: BFV Encryption Witness

### Key discovery: try_encrypt_extended exists upstream
- The locked `fhe` crate rev `5f24d0b62a7329b789db07a065b68accd614a47b` exposes
  `BfvPublicKey::try_encrypt_extended(&self, pt, rng) -> Result<(Ciphertext, Poly, Poly, Poly)>`
  which returns `(ct, u, e1, e2)` — the encryption randomness `u` and error polynomials
  `e1` (ct₀ leg) and `e2` (ct₁ leg).
- No need for feature-flag fallback or incomplete witness. The upstream method is
  fully functional and tested in the `fhe` crate's own test suite.
- This was confirmed by reading `crates/fhe/src/bfv/keys/public_key.rs` at the
  locked rev.

### Type design following pvthfhe-types conventions
- `EncryptionWitness` follows the same pattern as `ShareSecret`, `EncRandomness`,
  `CcsWitnessSecret`: `#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]`
  with a custom `Debug` impl that prints `<redacted>`.
- No `Serialize`/`Deserialize` — witness material is secret. Field reconstruction
  is used for wire tests, mirroring `to_wire_bytes()`/`from_wire_bytes()` patterns.
- `is_complete()` helper verifies all fields are non-empty.

### Trait method pattern
- `encrypt_with_witness` added to `FheBackend` trait with a default impl returning
  `Err(FheError::Backend { reason: "encrypt_with_witness not implemented" })`.
- This follows the existing pattern of `keygen_share_with_session` which also has
  a default error impl.
- Mock backend (`MockBackendInner`) inherits the default without changes.

### Field naming bridge
- `fhe.rs` names: `u` (randomness), `e1` (ct₀ error), `e2` (ct₁ error)
- `EncryptionWitness` names: `u_poly_bytes`, `e0_poly_bytes`, `e1_poly_bytes`
- Mapping: `e0 ← e1`, `e1 ← e2`. This is the BFV convention where ct₀ = pk₀·u + e₁ + m,
  ct₁ = pk₁·u + e₂, and our witness uses e₀/e₁ indexed by ciphertext leg.

### Test structure
- RED→GREEN TDD flow: wrote test first, confirmed failure with default impl,
  then implemented in `FhersBackend`.
- Three roundtrip tests: extended material extraction, compatibility with normal
  encrypt (identical ciphertext bytes with seeded RNGs), and Debug redaction.
- Two wire tests: field reconstruction roundtrip and minimum size assertions.
- All 5 new tests pass. Existing 26 tests pass (1 pre-existing RED test for
  decryption witness from Batch B.2 is unaffected).

### Verification summary
- `cargo build -p pvthfhe-fhe -p pvthfhe-types`: clean (pre-existing warnings only)
- `cargo test -p pvthfhe-fhe --test encryption_witness_roundtrip`: 3/3 pass
- `cargo test -p pvthfhe-fhe --test encryption_witness_serialization`: 2/2 pass
- `cargo test -p pvthfhe-fhe`: all 31 self-contained tests pass (1 pre-existing
  decrypt_witness RED test fails as expected)
- LSP diagnostics: zero errors across all modified files

### Files modified
- `crates/pvthfhe-types/src/lib.rs`: added `EncryptionWitness` struct + Debug + `is_complete()`
- `crates/pvthfhe-fhe/src/lib.rs`: added trait method + re-export
- `crates/pvthfhe-fhe/src/fhers.rs`: added `encrypt_with_witness` impl using `try_encrypt_extended`

### Files created
- `crates/pvthfhe-fhe/tests/encryption_witness_roundtrip.rs`: 3 tests (GREEN)
- `crates/pvthfhe-fhe/tests/encryption_witness_serialization.rs`: 2 tests (GREEN)

## 2026-05-11 — Batch B.2: Decryption-Share Witness

### Key insight: Replicating decryption_share_poly_from_coeffs logic
- `partial_decrypt` calls `decryption_share_poly_from_coeffs` internally, but that function
  consumes the sk_poly and esi_poly without exposing them.
- For `partial_decrypt_with_witness`, I replicated the internal logic inline rather than
  calling the helper, to capture intermediate values (sk_agg_poly_bytes, pre-smudge d_share).
- This avoids modifying the existing helper or duplicating the mutex lock.

### Type design mirroring EncryptionWitness
- `DecryptionWitness` follows the same pattern: `#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]`
  with a custom `Debug` impl that prints `<redacted>`.
- Field naming: `ct0_poly_bytes`, `ct1_poly_bytes`, `sk_agg_poly_bytes`, `esm_noise_poly_bytes`,
  `quotient_poly_bytes`, `d_share_poly_bytes`, `decrypted_share_bytes`, `esm_committed`.
- `quotient_poly_bytes` is `Vec<Vec<u8>>` (one per limb); currently empty because
  `ShareManager::decryption_share` doesn't expose reduction quotients. Batch F will wire
  committed e_sm and may add quotient tracking.

### Smudging noise capture
- The noise polynomial (difference between pre- and post-smudge d_share) is serialized
  directly as `esm_noise_poly_bytes`. This is computed as `noise_poly.to_bytes()` before
  adding to d_share.
- `esm_committed: false` — fresh local smudging. Batch F will make this `true` for
  committed e_sm mode.

### Trait method pattern
- `partial_decrypt_with_witness` added to `FheBackend` trait with default fallback
  returning `Err(FheError::Backend { ... })`, matching the pattern of `encrypt_with_witness`.
- Mock backend (`MockBackendInner`) inherits the default without changes.
- `DecryptionWitness` is re-exported from `pvthfhe-fhe` alongside `EncryptionWitness`.

### RED→GREEN flow
- Wrote test first that failed to compile (missing `DecryptionWitness` type and
  `partial_decrypt_with_witness` method).
- After adding types and implementation, both tests pass GREEN.
- Test 1: verifies `partial_decrypt` only returns bytes (no witness access).
- Test 2: calls `partial_decrypt_with_witness`, verifies witness fields are non-empty,
  checks `esm_committed == false`, cross-verifies ct0/ct1 match original ciphertext.

### BfvCiphertext structure
- `BfvCiphertext` has `pub c: Vec<Poly>` — public field with c[0]=ct0, c[1]=ct1.
  Confirmed by reading the upstream source at `crates/fhe/src/bfv/ciphertext.rs` line 25.
- `Poly::to_bytes()` serializes via `fhe_traits::Serialize`.

### Verification
- `cargo build -p pvthfhe-fhe -p pvthfhe-types`: clean (pre-existing warnings only)
- `cargo test -p pvthfhe-fhe --test decrypt_witness_roundtrip`: 2/2 pass
- `cargo test -p pvthfhe-fhe --lib`: 6/6 pass
- LSP diagnostics: zero errors across all modified files.

### Files modified
- `crates/pvthfhe-types/src/lib.rs`: added `DecryptionWitness` struct (after `EncryptionWitness`) + Debug impl
- `crates/pvthfhe-fhe/src/lib.rs`: added `partial_decrypt_with_witness` trait method + `DecryptionWitness` re-export
- `crates/pvthfhe-fhe/src/fhers.rs`: added `partial_decrypt_with_witness` impl (after `partial_decrypt`)

### Files created
- `crates/pvthfhe-fhe/tests/decrypt_witness_roundtrip.rs`: 2 tests (GREEN)
