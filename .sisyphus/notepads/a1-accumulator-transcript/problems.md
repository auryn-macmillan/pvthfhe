# A1 Open Problems

## 2026-06-04: Plan Creation

### P-A1-1: Real-NIZK Feature Gate Interaction
The accumulator transcript verification must work correctly under both `cfg(feature = "real-nizk")` and the default (surrogate) paths. The default path uses 32-byte proof bytes that pass syntactic checks but don't contain real NIZK data. The accumulator transcript can't be verified against these short proofs; it needs the full Ajtai commitment data. Resolution: the accumulator transcript must only be emitted/verified when real NIZK data is present (i.e., when the sigma proof section is larger than the surrogate's 32-byte minimum).

### P-A1-2: Multi-Track Instance Reconstruction
When multi-track metadata is present in the transcript, the verifier needs to reconstruct `MultiTrackPShareInstance` entries. This requires the full `MultiTrackFoldMetadata` structure, which includes per-track commitment bytes and norm bounds. The codec must encode enough information to reconstruct these entries without including private witness data.

### P-A1-3: Proof Size Regression
Adding an accumulator transcript to every NIZK proof will increase proof sizes. For T=10 sequential folds with 10 instances, each requiring ~128 bytes (hashes + IDs), the transcript adds ~1.3KB. For larger fold depths (future LatticeFold+ targets T=100+), this grows linearly. A batch accumulator Merkle proof approach (proving all instances commit to a single root) would reduce this but is out of scope for A1.

### P-A1-4: Backward Compatibility with Non-folded Path
The empty `acc_len=0` placeholder must remain valid for proofs that use the non-folded path (e.g., single-step per-party verification). The accumulator transcript must be an optional suffix, not a mandatory component. The verifier must gracefully handle both cases.
