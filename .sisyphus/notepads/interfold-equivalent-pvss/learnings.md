...

## 2026-05-12 — E.2-E.5 Documentation Updates + F.1-F.2 Code/Doc Changes

### E.5 — C2 Status Update
- Changed C2a and C2b from `partial` to `implemented` in:
  - `.sisyphus/design/interfold-equivalence.md` (table rows + summary)
  - `bench/results/interfold-equivalent-pvss-comparison.md`
- README.md and SECURITY.md had no explicit C2 references to change.
- The status change reflects E.1 batched Shamir/RS share-computation relation (`share_computation.rs`) which covers low-degree/RS validity, coefficient bounds, and foldable public instance commitments.

### E.2 — C7 Gap Documentation
- Added §C7 section to `.sisyphus/design/interfold-equivalence.md` with:
  - Current state (Noir toy circuit, N=8, direct Lagrange, no Cyclo/MicroNova)
  - What's needed (full production circuit: Lagrange, CRT, decode, participant selection, C6 binding)
  - Dependency on Batch G
- Updated README.md with C7 status row: "Noir toy circuit (N=8, direct Lagrange, no Cyclo/MicroNova verification) | Missing (stub)"
- Updated SECURITY.md with C7 gap in Known Limitations

### E.3 — C3 Structural Proof Gap
- Added §C3 section to `.sisyphus/design/interfold-equivalence.md`:
  - Algebraic sigma proves hash-preimage (SHA-256 of share), not full Shamir/BFV structure
  - Verifier checks H(share, session) = commitment but cannot check that ciphertext encrypts share
  - D.1 containment fails closed
- Expanded `docs/security-proofs/interfold-equivalent-pvss.md` §4.1 with structural gap details
- Updated README.md with C3 status row: "BFV sigma + Ajtai commitment; verifier lacks BFV encryption relation | Partial (D.1 blocker)"
- Updated SECURITY.md with C3 gap

### E.4 — C5 Gap Documentation
- Added §C5 section to `.sisyphus/design/interfold-equivalence.md`:
  - Aggregate decrypt uses internal ShareManager, no verifiable proof
  - No C5-style proof that pk_agg = Σ pk_i
- Updated SECURITY.md with C5 gap in Known Limitations

### F.1 — External Compressor Verifier
- Added `verify_external` method to `SonobeCompressor` in `crates/pvthfhe-compressor/src/sonobe/mod.rs`
  - Independent deserialization + verification path
  - Fresh verifier params deserialization from key bytes
- Added `external_verify_compressed_proof` function to `crates/pvthfhe-cli/src/compressor_glue.rs`
  - Gated behind `#[cfg(feature = "sonobe-compressor")]`
- Updated `crates/pvthfhe-cli/src/full_pipeline.rs`:
  - Added `compressor_verify_external` phase after primary verify
  - Gated with `#[cfg(feature = "sonobe-compressor")]`
  - Updated test expectations
- Build verified: `cargo build -p pvthfhe-cli --features "sonobe-compressor"` passes
- Gate verified: `cargo build -p pvthfhe-compressor --lib` passes

### F.2 — P2/P3 Gap Documentation
- Updated `.sisyphus/design/spec-real-p2p3.md` §5.1:
  - Added P2/P3 structural gap note: CycloFoldStepCircuit folds 3 hashed field elements, not full Ajtai commitment folding
  - Documented that compressed proof verifies hash-state consistency, not Cyclo accumulator relation
- Added §4.5 to `docs/security-proofs/interfold-equivalent-pvss.md`:
  - P2 gap: Sonobe Nova substitutes for lattice-native folding
  - P3 gap: compressed proof verifies hash-state, not full Ajtai/range-check/sum-check
  - Current flow: Cyclo verify_fold runs off-chain, state digest enters IVC
- Updated README.md P2/P3 status rows to reflect hash-accumulate limitation

### Verification
- `cargo build -p pvthfhe-cli --features "sonobe-compressor"` — clean (pre-existing warnings only)
- `cargo build -p pvthfhe-compressor --lib` — clean
- LSP diagnostics: zero errors across all modified Rust files
- All pre-existing tests pass; pre-existing RED tests (D.1 fail-closed, memory limit) remain
- Docs consistent across all 6 modified markdown files
