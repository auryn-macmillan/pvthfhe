# Round 11 Learnings

## F8: epoch_hash SHA-256 replacement (2026-05-15)

**Pattern**: Replace zero-initialized epoch_hash with deterministic SHA-256 digests.

**Files modified** (6 files):
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` — two occurrences, uses function's `seed: u64` parameter
- `crates/pvthfhe-cli/src/bin/nova_min.rs`
- `crates/pvthfhe-compressor/src/bin/nova_min.rs`
- `crates/pvthfhe-compressor/examples/nova_isolated.rs`
- `crates/pvthfhe-compressor/tests/ivc_steps_match_n.rs`
- `crates/pvthfhe-compressor/tests/nova_isolated_mem.rs`

**Approach**: Files with `seed: u64` parameter use it directly. Files without seed use a deterministic non-zero const (`0x736f6e6f62655f6d` = "nova_m" in hex, `0x6976635f73746570` = "ivc_step" in hex).

**Dependency**: Added `sha2 = "0.10"` to `pvthfhe-compressor/Cargo.toml`. Already present in `pvthfhe-cli/Cargo.toml`.

## F12: LegacyLocalSmudge warning (2026-05-15)

**File**: `crates/pvthfhe-cli/src/full_pipeline.rs` line 697

Added `tracing::warn!` BEFORE the else-branch struct literal. IMPORTANT: The warn must go before `let statement = DecryptNizkStatement { ... }`, NOT inside the struct literal.

## F14: Placeholder removal (2026-05-15)

Removed `#[cfg(test)] mod tests { fn placeholder() {} }` from 4 crates:
- `pvthfhe-core/src/lib.rs`
- `pvthfhe-circuits/src/lib.rs`
- `pvthfhe-cli/src/lib.rs`
- `pvthfhe-enclave-adapter/src/lib.rs`

## Build verification

`cargo build --workspace` succeeds cleanly (only pre-existing deprecated warnings in bench_p4.rs unrelated to these changes).


## Party ID indexing fix (2026-05-15)

### Root cause
The \invalid PVSS share\ error during  was caused by .
The  counter in  was initialized to 0, making the first
party's  = 0.  in  rejects .

### Changes made

1. ** line 603** —  → 
   - This was the actual root cause fix.  must be ≥ 1.

2. ** lines 661/701** —  → 
   - Changed from 0-indexed to 1-indexed to match the prover's convention.

3. ** line 638** —  → 
   - Must match the updated  for commitment computation consistency.

### Verification
- Clean build:  ✅
- *** PVTHFHE end-to-end demo (research prototype) ***
* Supported range: 1 ≤ t ≤ n ≤ 255 (Shamir over GF(256)) *
* Track B (LatticeFold+/MicroNova) — default *
* Pipeline includes keygen, NIZK, RLWE folding, Nova Nova compression (see WARNING.md and SECURITY.md for surrogate disclosures) *
* On-chain Solidity verify is NOT run by this demo (use bench-comparison) *
* DO NOT DEPLOY — research prototype only                                 *
warning: pvthfhe-fhe@0.1.0: MOCK BACKEND ACTIVE — XOR/SHA256 ONLY. Set PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 to use.
warning: unused variable: `p1`
    --> crates/pvthfhe-fhe/src/fhers.rs:1098:13
     |
1098 |         let p1 = bfv_pk.c.get(1).ok_or(FheError::MalformedPublicKey)?;
     |             ^^ help: if this is intentional, prefix it with an underscore: `_p1`
     |
     = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: method `decryption_share_poly_from_full_state` is never used
   --> crates/pvthfhe-fhe/src/fhers.rs:299:8
    |
 75 | impl FhersBackend {
    | ----------------- method in this implementation
...
299 |     fn decryption_share_poly_from_full_state(
    |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: associated function `compute_lagrange_coeffs_integer` is never used
    --> crates/pvthfhe-fhe/src/fhers.rs:1439:8
     |
1218 | impl FhersBackend {
     | ----------------- associated function in this implementation
...
1439 |     fn compute_lagrange_coeffs_integer(party_ids: &[usize]) -> Vec<i64> {
     |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: `pvthfhe-fhe` (lib) generated 3 warnings (run `cargo fix --lib -p pvthfhe-fhe` to apply 1 suggestion)
warning: missing documentation for a function
   --> crates/pvthfhe-pvss/src/encrypt.rs:416:1
    |
416 | pub fn share_proof_dkg_root(ctx: &PvssContext) -> Vec<u8> {
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = note: requested on the command line with `-W missing-docs`

warning: missing documentation for an associated function
    --> crates/pvthfhe-pvss/src/nizk_share.rs:1409:5
     |
1409 |     pub fn from_opened(opened: &ShareNizkOpenedProof) -> Result<Self, PvssError> {
     |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for an associated function
    --> crates/pvthfhe-pvss/src/nizk_share.rs:1421:5
     |
1421 |     pub fn from_bytes(proof_bytes: Vec<u8>) -> Result<Self, PvssError> {
     |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a method
    --> crates/pvthfhe-pvss/src/nizk_share.rs:1429:5
     |
1429 |     pub fn decode(&self) -> Result<ShareNizkOpenedProof, PvssError> {
     |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: pvthfhe-aggregator@0.1.0: SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final are research surrogates — do not deploy
warning: `pvthfhe-pvss` (lib) generated 4 warnings
warning: unused imports: `BigInteger` and `PrimeField`
 --> crates/pvthfhe-compressor/src/merkle.rs:2:14
  |
2 | use ark_ff::{BigInteger, PrimeField};
  |              ^^^^^^^^^^  ^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused import: `ark_r1cs_std::fields::FieldVar`
  --> crates/pvthfhe-compressor/src/nova/mod.rs:33:5
   |
33 | use ark_r1cs_std::fields::FieldVar;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:34:5
   |
34 |     pub leaf_value: F,
   |     ^^^^^^^^^^^^^^^^^
   |
   = note: requested on the command line with `-W missing-docs`

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:35:5
   |
35 |     pub leaf_index: F,
   |     ^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:36:5
   |
36 |     pub siblings: Vec<F>,
   |     ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:50:1
   |
50 | pub struct C7MerkleExternalInputs<F: PrimeField> {
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:51:5
   |
51 |     pub share_eval: F,
   |     ^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:52:5
   |
52 |     pub lagrange_coeff: F,
   |     ^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:53:5
   |
53 |     pub merkle_root: F,
   |     ^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:54:5
   |
54 |     pub merkle_data: MerkleWitnessData<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:71:5
   |
71 |     pub share_eval: FpVar<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:72:5
   |
72 |     pub lagrange_coeff: FpVar<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:73:5
   |
73 |     pub merkle_root: FpVar<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:74:5
   |
74 |     pub merkle_leaf_value: FpVar<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:75:5
   |
75 |     pub merkle_leaf_index: FpVar<F>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
  --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:76:5
   |
76 |     pub merkle_siblings: Vec<FpVar<F>>,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:200:5
    |
200 |     pub merkle_depth: usize,
    |     ^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:201:5
    |
201 |     pub merkle_arity: usize,
    |     ^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for an associated function
   --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:205:5
    |
205 |     pub fn new_with_depth(depth: usize, arity: usize) -> Result<Self, folding_schemes::Error> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a method
   --> crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs:213:5
    |
213 |     pub fn external_inputs_width(&self) -> usize {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a module
 --> crates/pvthfhe-compressor/src/micronova/mod.rs:2:1
  |
2 | pub mod tree;
  | ^^^^^^^^^^^^

warning: missing documentation for an associated function
  --> crates/pvthfhe-compressor/src/micronova/compressor.rs:36:5
   |
36 |     pub fn new(depth: usize, epoch: [u8; 32]) -> Self {
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a method
   --> crates/pvthfhe-compressor/src/micronova/compressor.rs:137:5
    |
137 |     pub fn total_steps(&self) -> usize {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a method
   --> crates/pvthfhe-compressor/src/micronova/compressor.rs:141:5
    |
141 |     pub fn depth(&self) -> usize {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
 --> crates/pvthfhe-compressor/src/micronova/tree.rs:8:5
  |
8 |     pub depth: usize,
  |     ^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
 --> crates/pvthfhe-compressor/src/micronova/tree.rs:9:5
  |
9 |     pub root_proof: CompressedProof,
  |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: `pvthfhe-compressor` (lib) generated 26 warnings (run `cargo fix --lib -p pvthfhe-compressor` to apply 1 suggestion)
warning: use of deprecated struct `hermine::HermineAdapter`: HermineAdapter uses deterministic share derivation (CRITICAL finding F60). Use LatticePvssBfvAdapter instead.
  --> crates/pvthfhe-keygen/src/hermine.rs:62:6
   |
62 | impl HermineAdapter {
   |      ^^^^^^^^^^^^^^
   |
   = note: `#[warn(deprecated)]` on by default

warning: use of deprecated struct `hermine::HermineAdapter`: HermineAdapter uses deterministic share derivation (CRITICAL finding F60). Use LatticePvssBfvAdapter instead.
   --> crates/pvthfhe-keygen/src/hermine.rs:267:24
    |
267 | impl KeygenAdapter for HermineAdapter {
    |                        ^^^^^^^^^^^^^^

warning: `pvthfhe-keygen` (lib) generated 2 warnings
    Finished `release` profile [optimized] target(s) in 0.18s
     Running `target/release/pvthfhe-cli demo --n 10 --threshold 4 --seed 1`
[2m2026-05-15T20:04:57.209911Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m starting demo pipeline [3mn[0m[2m=[0m10 [3mthreshold[0m[2m=[0m4 [3mseed[0m[2m=[0m1
demo: n=10 threshold=4 seed=1
pvss_backend_id=lattice-pvss-bfv-d2
[2m2026-05-15T20:04:57.209936Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m backend_id_p1 [3mbackend_id[0m[2m=[0m"cyclo-ajtai-d2-conditional"
[2m2026-05-15T20:04:57.209939Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m backend_id_p2 [3mbackend_id_p2[0m[2m=[0m"cyclo-rlwe-t10-lemma9-heuristic"
[2m2026-05-15T20:04:57.209940Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m backend_id_p3 [3mbackend_id_p3[0m[2m=[0m"nova-bn254-grumpkin"
backend_id == "cyclo-ajtai-d2-conditional"
backend_id_p2: cyclo-rlwe-t10-lemma9-heuristic
backend_id_p3: nova-bn254-grumpkin
note: on-chain Solidity verify is NOT run by demo (use bench-comparison)
pvss_backend_id=lattice-pvss-bfv-d2
[2m2026-05-15T20:04:57.231854Z[0m [33m WARN[0m [2mpvthfhe_cli::full_pipeline[0m[2m:[0m seed flag ignored in production path; will require --insecure-seed in future R3.6
step 1/10: keygen (n=10 t=4 seed=1)
keygen: complete (30.450 ms)
step 2/10: nizk_prove (dealer=1)
step 3/10: nizk_verify (dealer=1 recipient=1)
step 4/10: pvss_share_encrypt (lattice-pvss-bfv-d2)
pvss_share_encrypt: complete (623.015 ms)
[2m2026-05-15T20:04:58.135260Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m setup_threshold: computing Shamir shares for all parties
setup_threshold: complete (536.350 ms)
[2m2026-05-15T20:04:58.727096Z[0m [32m INFO[0m [2mpvthfhe_cli::full_pipeline[0m[2m:[0m Track B: norm enforcement active (bound B=1024, B_e=16)
step 5/10: cyclo_fold (cyclo-rlwe-t10-lemma9-heuristic)
cyclo_fold: complete (12.560 ms)
[2m2026-05-15T20:04:59.647737Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: params serialized [3mprover_key_bytes_len[0m[2m=[0m2162768 [3mverifier_key_bytes_len[0m[2m=[0m2162768 [3mrss_kb[0m[2m=[0m213376
step 6/10: compressor_prove (nova-bn254-grumpkin)
[2m2026-05-15T20:04:59.656073Z[0m [32m INFO[0m [2mpvthfhe_cli::full_pipeline[0m[2m:[0m Track B: native ring equation verification passed (10/10 parties, challenge=21888242871839275222246405745257275088548364400416034343698204186575808495616)
[2m2026-05-15T20:04:59.656175Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: deserialize_params start [3mrss_kb[0m[2m=[0m213376
[2m2026-05-15T20:04:59.976149Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: pp_deserialize done [3mrss_kb[0m[2m=[0m213376 [3mrss_delta_kb[0m[2m=[0m0
[2m2026-05-15T20:05:00.556654Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: vp_deserialize done [3mrss_kb[0m[2m=[0m266596 [3mrss_delta_kb[0m[2m=[0m53220
[2m2026-05-15T20:05:00.820898Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: Nova::init done [3mrss_kb[0m[2m=[0m322024
[2m2026-05-15T20:05:00.886473Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_step done [3mstep[0m[2m=[0m0 [3mrss_kb[0m[2m=[0m332380
[2m2026-05-15T20:05:00.889209Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: ivc proof serialized [3mivc_bytes_len[0m[2m=[0m7245080 [3mrss_kb[0m[2m=[0m332380
compressor_prove: complete (1248.614 ms)
step 7/10: compressor_verify (nova-bn254-grumpkin)
compressor_verify: complete (579.073 ms)
step 8/10: partial_decrypt (party_id=1)
partial_decrypt: complete (2.617 ms)
partial_decrypt: complete (2.412 ms)
partial_decrypt: complete (2.438 ms)
partial_decrypt: complete (2.429 ms)
step 9/10: aggregate_decrypt
[2m2026-05-15T20:05:02.185197Z[0m [32m INFO[0m [2mpvthfhe_fhe::fhers[0m[2m:[0m aggregate_decrypt: decode shares [3mms[0m[2m=[0m0.896186
[2m2026-05-15T20:05:02.185214Z[0m [32m INFO[0m [2mpvthfhe_fhe::fhers[0m[2m:[0m aggregate_decrypt: Lagrange coeffs [3mms[0m[2m=[0m0.027569999999999997
[2m2026-05-15T20:05:02.212921Z[0m [32m INFO[0m [2mpvthfhe_fhe::fhers[0m[2m:[0m aggregate_decrypt: decrypt_from_shares (NTT) [3mms[0m[2m=[0m27.691228
[2m2026-05-15T20:05:02.213705Z[0m [32m INFO[0m [2mpvthfhe_fhe::fhers[0m[2m:[0m aggregate_decrypt: slot decode [3mms[0m[2m=[0m0.799408
aggregate_decrypt: complete (30.164 ms)
step 10/10: c7_decrypt_aggregation
[2m2026-05-15T20:05:03.086071Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: params serialized [3mprover_key_bytes_len[0m[2m=[0m2162768 [3mverifier_key_bytes_len[0m[2m=[0m2162768 [3mrss_kb[0m[2m=[0m332716
[2m2026-05-15T20:05:03.092072Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: deserialize_params start [3mrss_kb[0m[2m=[0m332716
[2m2026-05-15T20:05:03.407648Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: pp_deserialize done [3mrss_kb[0m[2m=[0m332716 [3mrss_delta_kb[0m[2m=[0m0
[2m2026-05-15T20:05:03.959560Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: vp_deserialize done [3mrss_kb[0m[2m=[0m332716 [3mrss_delta_kb[0m[2m=[0m0
[2m2026-05-15T20:05:04.277041Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_steps done [3mstep[0m[2m=[0m0 [3mrss_kb[0m[2m=[0m355440
[2m2026-05-15T20:05:04.360326Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_steps done [3mstep[0m[2m=[0m1 [3mrss_kb[0m[2m=[0m357436
[2m2026-05-15T20:05:04.472946Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_steps done [3mstep[0m[2m=[0m2 [3mrss_kb[0m[2m=[0m360048
[2m2026-05-15T20:05:04.580862Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_steps done [3mstep[0m[2m=[0m3 [3mrss_kb[0m[2m=[0m368812
[2m2026-05-15T20:05:04.583730Z[0m [32m INFO[0m [2mpvthfhe_compressor::nova[0m[2m:[0m nova: prove_steps proof serialized [3mivc_bytes_len[0m[2m=[0m7245080 [3mrss_kb[0m[2m=[0m368812
c7_decrypt_aggregation: complete (2966.222 ms)
plaintext_roundtrip: OK
aggregate_pk_hash: d84d6c9dc1c57a82a6101d8ba9cbcfe4e849e78229d5288549352ede1c59a116
ciphertext_hash: 5b448cb87878c3bf5ce78cac1d1f506afe1759722b2ab436207738793656268b
compressed_proof_digest: d0b344582a1eff81e1aa89409562f350ce392aac7252ae1a99f939d74387cb22
keygen_ms=30.450385
aggregate_keygen_ms=5.140121
encrypt_ms=2.852394
share_encryption_proof_ms=338
partial_decrypt_ms=9.896157
aggregate_decrypt_ms=30.164313
decrypt_ms=40.06047
threshold=4
n=10
verify: ACCEPT
[2m2026-05-15T20:05:05.189863Z[0m [32m INFO[0m [2mpvthfhe_cli[0m[2m:[0m demo complete: ACCEPT
pvss_backend_id=lattice-pvss-bfv-d2:  ✅

## Party ID indexing fix: slot_id=0 rejection (2026-05-15)

**Root cause**: The "invalid PVSS share" error during partial_decrypt was caused by
slot_id=0. decrypt_round was initialized to 0, making the first party's slot_id=0.
validate_mode in nizk_decrypt.rs rejects slot_id==0.

**Changes**:
1. `full_pipeline.rs:603` - decrypt_round init from 0 to 1 (actual fix)
2. `full_pipeline.rs:661,701` - party_index from zero_based to usize::try_from(party_id)
3. `full_pipeline.rs:638` - recipient_id from zero_based to party_id

**Verification**: demo-e2e ACCEPT

