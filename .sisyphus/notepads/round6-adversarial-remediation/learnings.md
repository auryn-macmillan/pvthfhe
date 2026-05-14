# Learnings — Round 6 Adversarial Remediation, Batch B

## B.1: e_i=0 trade-off (nizk_share.rs)
- Added comment at line 555 explaining the zero-error shortcut in the algebraic proof.
- The RLWE soundness comes from the separate BFV sigma proof (v4), not this algebraic layer.
- The e_i=0 path provides defense-in-depth algebraic binding only.

## B.2: Circular pvss_commitment (nizk_share.rs)
- Added comments at lines 576 and 1140 documenting the SHA256(d_rns) self-reference.
- The overall ShareNizkVerifier has independent layers (D2 binding, BFV proof) that bind to
  the real statement, providing defense-in-depth despite the circularity.

## B.3: Caller-dependent binding (bfv_sigma.rs)
- Added comment at line 378 documenting that `derive_challenge` relies entirely on
  the caller to provide complete `binding_data` including session_id, participant_id, epoch.
- Callers in nizk_share.rs and adapter.rs provide full binding via `bfv_sigma_binding_data()`.

## C.1: Duplicate party_id check (fhers.rs)
- Added HashSet<u32> to aggregate_keygen() at line 627 to detect duplicate party IDs.
- Follows the existing pattern in mock_impl.rs (line 126-133) which uses BTreeSet.
- Used HashSet (not BTreeSet) per the task specification for O(1) duplicate detection.
- The existing MalformedKeygenShare variant only has `party_id: u32` (not `reason`), so
  the error follows the existing enum shape — no new field was needed.

## C.2: dkg_root binding in D2 hash (nizk_share.rs)
- Added `hasher.update(stmt.dkg_root.as_slice())` to both:
  1. Prover-side D2 binding computation (line 385, in the prove() method)
  2. Verifier-side verify_d2_hash_binding (line 1257)
- The other binding functions (compute_relation_binding, compute_commitment_binding,
  compute_lattice_binding) already included dkg_root — only the D2 binding was missing it.
- This ensures the D2 hash binds to the full DKG context, preventing cross-session
  replay of D2 preimages.

## Build verification
- `cargo build --workspace`: fhers.rs and nizk_share.rs compiled cleanly (zero LSP diagnostics).
- The only build failure is pre-existing: `tracing` crate missing from `encrypt.rs:407`.
  This is unrelated to Batch C changes.

## Batch D+E: Infrastructure Hardening + Docs (2026-05-14)

### D.1 - share_proof_dkg_root warning
- Made `share_proof_dkg_root` `pub` and added `tracing::warn!()` for empty dkg_root fallback
- Required adding `tracing = "0.1"` to `pvthfhe-pvss/Cargo.toml` (was not a dependency)
- Build succeeds; triggers `missing-docs` warning for newly-public function (acceptable)

### D.2 - epoch_hash expansion
- Changed from 8-byte seed copy to full 32-byte SHA-256 hash
- `sha2` was already imported and available as a dependency
- `Sha256::digest().into()` produces `[u8; 32]` matching `Compressor::new` signature

### D.3 - fold.rs satisfiability comment
- Added documentation comment noting satisfiability is deferred to `verify_fold`
- Duplicate rejection handled by `verify_fold` recomputation
- No code changes, purely documentation

### E.1 - SECURITY.md update
- Added `### R6 Adversarial Audit Findings (2026-05-14)` subsection
- Added known limitations (e_i=0, circular pvss_commitment, BFV sigma, Ajtai witness, compressor, keygen NIZK)
- Added cross-session replay hardening summary

## Batch A Critical Fixes - A.2 and A.3 (2026-05-14)

### A.2: session_id check in aggregate_decrypt
- **Already applied**: `crates/pvthfhe-aggregator/src/decrypt/mod.rs` lines 311-316 already checks `opened.statement.session_id.as_slice() != session_id.as_bytes()` and returns `DecryptError::InvalidShare` with reason "session_id mismatch".
- The `session_id` is passed as a `&str` parameter to `aggregate_decrypt()` (line 274).

### A.3: session_id param to FheBackend
- **Already applied**: `crates/pvthfhe-cli/src/full_pipeline.rs` lines 617 and 625 both pass `session_id.as_bytes()` to `aggregate_decrypt_with_poly` and `aggregate_decrypt` respectively.

### Build Fix: bench_scaling.rs missing session_id
- `crates/pvthfhe-bench/src/bin/bench_scaling.rs` line 201 was missing the `session_id: &str` argument in its `aggregate_decrypt` call.
- Fixed by adding `"bench"` as a static session_id between `&ct_hash` and `1`.
