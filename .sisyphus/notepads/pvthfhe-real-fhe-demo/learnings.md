# Learnings

## [2026-05-05] Session start

- `pvthfhe-fhe` Cargo.toml currently has NO fhe/fhe-traits/e3-trbfv deps — all 5 crypto methods in fhers.rs are stubs
- `pvthfhe-cyclo/Cargo.toml` pins fhe-math at rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- Canonical params: `qis = [288230376173076481, 288230376167047169, 288230376161280001]`, `error_stddev = 3.19`, variance = 10
- Party IDs in ShareManager::decrypt_from_shares are 1-based
- fhe::mbfv exports: CommonRandomPoly, PublicKeyShare, PublicKey::from_shares, DecryptionShare, Aggregate, AggregateIter
- fhe::trbfv exports: ShareManager, TRBFV, ShamirSecretSharing
- Plan A3: first-pass uses direct composition of fhe::mbfv + fhe::trbfv (NOT e3-trbfv wrapper) to avoid Cipher dep
- Stage 0 tripwires must survive; build.rs warning stays

## [2026-05-05] F1 dependency pinning

- Verified `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b` contains `fhe::trbfv` and `ShareManager`; no rev bump was needed for Risk R2.
- `pvthfhe-fhe` now pins `fhe`, `fhe-traits`, and direct `fhe-math` to the same locked `fhe.rs` rev already used by `pvthfhe-cyclo`.
- F1 keeps `e3-trbfv` out of `pvthfhe-fhe` for now because the direct `fhe::mbfv` + `fhe::trbfv` path remains viable and avoids the wrapper's heavier transitive surface.

- Hardened `dep_lock.rs` to invoke `cargo metadata --locked` directly, parse JSON in Rust, and fail if any locked fhe.rs crate resolves from multiple distinct sources.

## [2026-05-05] F2 params schema extension

- `Params` now carries explicit `moduli: Vec<u64>` and `variance: usize`; parser still accepts legacy TOML without `moduli` via a warning-backed shim.
- `parse_params` now also accepts `plaintext_modulus` as a transitional alias for `t_plain`, which keeps `.sisyphus/design/parameters.toml` consumable while fixtures migrate.
- `pvthfhe-fhe` conformance tests had to keep the current `FhersBackend` sentinel behavior explicit until later F/A tasks wire real crypto primitives; primary tests now assert `FheError::Backend` instead of a mock round-trip.

## [2026-05-05] F3 wire format

- Added `pvthfhe_fhe::wire` with hand-rolled V1 encodings: leading 0x01 version byte plus 4-byte big-endian length prefixes per field for keygen shares, public keys, and decrypt shares.
- Added `FheError::DecodeError { reason }` so malformed or unsupported wire payloads fail explicitly at the trait boundary instead of panicking.
- `cargo test -p pvthfhe-fhe wire` only runs tests whose names contain `wire`; our new file keeps that substring in each test name so the targeted command exercises the round-trips.

## [2026-05-05] A1 BFV parameter loading

- `FhersBackend::load_params` now maps parsed `Params` into a real `Arc<BfvParameters>` using `BfvParametersBuilder::new().set_degree(...).set_moduli(...).set_plaintext_modulus(...).build_arc()` and converts builder failures into `FheError::Backend { reason }`.
- A focused integration test now loads the canonical RLWE TOML and asserts the constructed BFV parameter degree (`8192`) and modulus-count (`3`) through a test-only accessor-style method on `FhersBackend`.
- Clarified \ docs that versioned payload structs back the crate's opaque byte wrappers, and renamed wire tests with a \ prefix so \
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s actually executes the targeted round-trip cases.
- Clarified wire.rs docs that versioned payload structs back the crate opaque byte wrappers, and renamed wire tests with a wire_ prefix so cargo test -p pvthfhe-fhe wire executes the targeted round-trip cases.

## [2026-05-05] A2 session-scoped CRP plumbing

- Verified in the locked `gnosisguild/fhe.rs` source that `CommonRandomPoly::new_deterministic` takes `(&Arc<BfvParameters>, [u8; 32])` and returns `Result<CommonRandomPoly>`; no RNG is involved once the 32-byte session seed is fixed.
- `FheBackend::keygen_share` now default-generates a fresh 32-byte session ID with the caller-provided RNG and delegates to the new `keygen_share_with_session`; backend implementations that do not override the session-aware entry point will panic by default.
- `FhersBackend` now derives deterministic CRPs from session IDs and exposes a test-only byte accessor so RED/GREEN coverage can assert same-session equality and cross-session inequality without leaking the CRP helper into the public API.

## [2026-05-05] A3 real keygen-share bytes and retained party state

- In the pinned `fhe.rs` rev, `SecretKey::random(&Arc<BfvParameters>, rng)` returns a concrete `SecretKey`, while `PublicKeyShare::new_extended(&sk, crp, rng)` returns `Result<(pk_0, pk_1, s, e)>`; for the wire payload we only need `pk_0`, because `PublicKeyShare` serializes to the `p0_share` polynomial bytes.
- `FhersBackend::keygen_share_with_session` now derives a deterministic session CRP, samples a real BFV secret key, serializes `crp` plus `pk_0` into `wire::encode_keygen_share`, and stores per-party state behind `Arc<Mutex<HashMap<u32, PartyState>>>` so the backend stays `Send + Sync`.
- `PartyState` currently retains the local secret-key coefficients as `sk_poly_sum: Vec<i64>` and leaves `esi_poly_sum` empty until the later C-series Shamir/smudging work lands; retrieval now goes through `take_party_state`, which returns `FheError::UnknownParty { party_id }` on missing entries.

## [2026-05-05] Conformance expectations after A3

- Primary-backend conformance tests can no longer treat `keygen_share` as a sentinel `FheError::Backend`; after A3 it should succeed and return a non-empty `KeygenShare` with the requested `party_id`.
- The remaining primary-backend surface in `conformance.rs` still legitimately expects `aggregate_keygen`, `encrypt`, `partial_decrypt`, and `aggregate_decrypt` to return `FheError::Backend` until their later tasks are implemented.

## [2026-05-05] A4 real aggregate_keygen

- In the pinned `fhe.rs` rev, A4 is wired via `CommonRandomPoly::deserialize(&crp_bytes, &Arc<BfvParameters>)`, `PublicKeyShare::deserialize(&p0_share_bytes, &Arc<BfvParameters>, crp.clone())`, and `fhe::mbfv::Aggregate`'s `PublicKey::from_shares(...)`; the aggregated BFV key components are then read from `public_key.c.get(0/1)` and wrapped with `wire::encode_public_key`.
- `aggregate_keygen` now decodes every `KeygenShare` through `wire::decode_keygen_share`, rejects mismatched CRP payloads with the new `FheError::InconsistentCrp`, and maps share/aggregation backend failures to `FheError::Backend { reason }`.
- The focused RED/GREEN test for A4 only asserts successful V1 public-key decoding and non-empty `(p0, p1)` bytes; full encrypt/decrypt validation remains for later plan tasks once `encrypt` and decryption are real.

## [2026-05-05] A5 generic keygen simulator with real backend

- `KeygenSimulator` now stores `Arc<dyn FheBackend>` so the same simulator type can drive both `MockBackend` and `FhersBackend` without feature-gating the module itself.
- To keep `FhersBackend::aggregate_keygen` happy, the simulator derives one deterministic 32-byte session ID per run from the simulator parameters and threads it through `keygen_share_with_session` for every party, ensuring all shares embed the same CRP.
- The simulator-level mock env-var panic is now conditional on the concrete backend type name ending in `::MockBackend`; real-backend tests can construct and run the simulator without `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1`, while mock call sites still fail fast.

## [2026-05-05] A5 review follow-up hardening

- Replaced panic-driven capability probing with explicit `FheBackend` capability methods: `supports_session_scoped_keygen()` and `requires_mock_acknowledgement()`, avoiding `catch_unwind` and brittle `type_name()` checks in the simulator.
- Tightened the simulator's deterministic session ID derivation to include a hash of the participant set plus threshold, which better matches the protocol intent than hashing only simulator shape.
- `keygen_real` now asserts successful completion of all three simulator rounds (`participant_set`, `round1_messages`, and `round2_messages` lengths all equal `n=8`) before checking the aggregated public-key wire version.

## [2026-05-05] B1 real encrypt

- `wire::decode_public_key` returns raw `p0`/`p1` polynomial bytes; at the pinned `fhe.rs` rev the simplest reconstruction path is `Poly::from_bytes(..., ctx_at_level(0))` plus `bfv::Ciphertext::new(vec![p0, p1], &par)` wrapped into `bfv::PublicKey`, rather than relying on a flat `PublicKey::from_bytes` payload.
- `bytes_to_slots` packs plaintext bytes into little-endian `u64` chunks, zero-pads the final chunk, and then pads the slot vector to `par.degree()`; `slots_to_bytes` performs the inverse by concatenating little-endian slot bytes and truncating to the original length.
- `FhersBackend::encrypt` should reject inputs longer than `degree * 8` bytes up front, then `Plaintext::try_encode(..., Encoding::poly(), &par)` and `pk.try_encrypt(...)` produce a fresh 2-polynomial BFV ciphertext whose serialized bytes round-trip with `bfv::Ciphertext::from_bytes`.

## [2026-05-05] B2 encoding golden vectors

- `bytes_per_plaintext` is `par.degree() * 8` bytes with the current B1 little-endian `u64` slot packing, so canonical `degree = 8192` yields a 65536-byte single-plaintext capacity.
- `bytes_to_slots` and `slots_to_bytes` were exposed for integration testing as documented `pub` helpers in `pvthfhe_fhe::fhers`.
- `FheError::PlaintextTooLong` now has shape `PlaintextTooLong { max: usize, got: usize }` and `FhersBackend::encrypt` returns it before attempting BFV encoding.

## [2026-05-05] C1 per-party state plumbing

- At the pinned `fhe.rs` rev, the practical API for C1 is `ShareManager::new(n, threshold_index, params)` plus `coeffs_to_poly_level0`, `generate_secret_shares_from_poly`, and `aggregate_collected_shares`; `ShamirSecretSharing` itself is lower-level and uses 1-based party indices with `recover` expecting exactly `threshold + 1` shares.
- `setup_threshold(&self, n, t)` was added as a new default `FheBackend` trait method and implemented in `FhersBackend` by constructing a `ShareManager` with threshold index `t - 1`, generating per-sender Shamir share matrices, distributing each sender's row for receiver `j` in-process, and aggregating the collected matrices for each receiver.
- After `setup_threshold`, each party state's `sk_poly_sum` is overwritten with the sum of received Shamir SK shares from all parties, `esi_poly_sum` remains empty for deferred smudging work, and `take_party_state(unknown)` still returns `FheError::UnknownParty`.

## [2026-05-05] C2 partial_decrypt real implementation

- Ciphertext deserialization uses `fhe::bfv::Ciphertext::from_bytes(&ciphertext.bytes, &Arc<BfvParameters>)`, with `fhe_traits::DeserializeParametrized` imported so the trait method is in scope.
- The deferred zero smudging polynomial is constructed as `Poly::zero(bfv_params.ctx_at_level(0)?, Representation::PowerBasis)`.
- Partial decrypt now uses `ShareManager::new(n, t - 1, params).decryption_share(Arc::new(ct), sk_poly_sum_poly, esi_poly)` and serializes the resulting polynomial with `Poly::to_bytes()` before wrapping it in `wire::encode_decrypt_share`.

## [2026-05-05] C3 aggregate_decrypt
- ShareManager::decrypt_from_shares signature at locked fhe.rs rev: `(Vec<Poly>, Vec<usize>, Arc<Ciphertext>) -> Result<Plaintext, Error>`; threshold passed to ShareManager::new is `t - 1`, while reconstructing party IDs are 1-based.
- Plaintext decode API is `Vec::<u64>::try_decode(&pt, Encoding::poly())` with `fhe_traits::FheDecoder` in scope.
- aggregate_decrypt now deserializes ciphertext via `BfvCiphertext::from_bytes`, decodes `DecryptShareV1` payloads, reconstructs with `decrypt_from_shares`, converts slots with `slots_to_bytes(degree * 8)`, then trims trailing zero bytes.
- Gotcha: current wrong-ciphertext backend test needs a structurally valid but mixed-share set; corrupting raw poly bytes can fail earlier at deserialization instead of yielding garbage.

## [2026-05-05] C4 aggregator integration smoke test
- Exercised aggregator keygen simulator + decrypt wrapper path end-to-end: `KeygenSimulator::run`, aggregator `decrypt::partial_decrypt`, aggregator `decrypt::aggregate_decrypt`, and the real `FhersBackend` keygen/setup/encrypt/partial-decrypt/aggregate-decrypt flow.
- Gotcha: the simulator had drifted to 0-based party IDs, but the real `FhersBackend` threshold/share plumbing and `fhe.rs` Shamir reconstruction expect 1-based IDs; aligning the simulator/tests back to 1-based fixed `setup_threshold` and preserved aggregator validation semantics.
- Gotcha: aggregator `nizk: vec![1]` placeholder and `ciphertext_hash` binding already pass for this smoke test as long as the test hashes the exact serialized ciphertext bytes once and threads that same hash through every share payload and final aggregate call.
- `setup_threshold` remains a required explicit post-keygen step for this unit-level integration: `KeygenSimulator` builds the aggregate public key/transcript, then the test must call `backend.setup_threshold(8, 5)` before real partial decrypts.
- Real BFV decrypt of all-zero plaintext exposed an encoding boundary bug: trimming trailing zero bytes erased legitimate zero plaintexts, so the backend now prefixes plaintext length into slot 0 and decodes exact-length bytes instead of trimming.

## [2026-05-05] D1 CLI threshold flag
- Demo command structure is now `cargo run -p pvthfhe-cli -- demo --n <n> --threshold <threshold> --seed <seed>`; the CLI accepts `--threshold` explicitly and still defaults to `n / 2 + 1` when omitted.
- Timing output format is line-oriented key/value text: `keygen_ms=<N>`, `aggregate_keygen_ms=<N>`, `encrypt_ms=<N>`, `partial_decrypt_ms=<N>`, `aggregate_decrypt_ms=<N>`, `decrypt_ms=<N>`, `threshold=<T>`, `n=<N>`.
- `Justfile` recipe syntax is now parameterised as `demo-e2e n="32" threshold="17": cargo run --release -p pvthfhe-cli -- demo --n {{n}} --threshold {{threshold}} --seed 1`.

## [2026-05-05] D2 banner update
- `crates/pvthfhe-fhe/build.rs` now switches on `CARGO_FEATURE_MOCK`: default builds warn that the folding accumulator is still surrogate while FHE crypto is real (honest-but-curious), and mock builds warn `MOCK BACKEND ACTIVE — XOR/SHA256 ONLY` with the existing env-var acknowledgement requirement.
- Added `crates/pvthfhe-fhe/tests/banner.rs` as a RED-then-GREEN integration test that reads `build.rs` source and asserts both required warning strings are present.
- Updated `SECURITY.md` and `README.md` so the docs no longer claim the FHE backend is itself a surrogate; they now call out the real-but-unproven FHE path and the remaining folding/on-chain surrogate boundaries.

## [2026-05-05] D4 followon doc
- Added a deferred-items section to `.sisyphus/plans/pvthfhe-followon.md` covering `Greco well-formedness ZK proofs` (E1), `Eval-key/relinearization DKG` (E2 / `EVAL_KEY_MPC_DESIGN.md`), `Multi-ciphertext encrypt` (B2/E-series), `Cross-process share distribution` (E3), and `Smudging-noise tuning at n≥1024` (Phase E).
- Added `crates/pvthfhe-fhe/tests/followon.rs` as a RED-then-GREEN content check that asserts those deferred follow-on entries remain present.

## [2026-05-05] D3 bench-fhe-baseline
- `crates/pvthfhe-bench/src/bin/fhe_baseline.rs`
- `bench/results/fhe-baseline.csv`
- `Justfile` recipe: `bench-fhe-baseline n_max="64"`
- CI smoke exercised `n ∈ {4, 8, 16}` via `FHE_BENCH_N_MAX=16`

## [2026-05-05] Review follow-up hardening
- Strengthened `crates/pvthfhe-fhe/tests/banner.rs` so it now verifies observable build-script behavior by compiling tiny probe crates against `pvthfhe-fhe` in both default and `mock` configurations, and added a negative assertion that the old `SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final` wording is gone.
- Updated the Stage 0 gate cargo tripwire in `Justfile` to check for the new default warning text and to `cargo clean -p pvthfhe-fhe` before the build, since the warning only appears when the crate is actually rebuilt.
- Re-verified `cargo test -p pvthfhe-fhe banner`, `cargo test -p pvthfhe-fhe --features mock banner`, `cargo test -p pvthfhe-fhe followon`, and `just stage0-gate` all pass after the review-driven fixes.

## [2026-05-05] F4 remove mock moduli shim
- `mock_impl::parse_params` now rejects TOML that omits `moduli` with `FheError::InvalidParams { reason: "moduli required in [rlwe] section" }` before the generic missing-field path.
- Removing the transitional shim also removed the local `CANONICAL_MODULI` constant; tests that still need the canonical values now inline `[288230376173076481u64, 288230376167047169, 288230376161280001]`.
- A focused RED→GREEN integration test lives in `crates/pvthfhe-fhe/tests/params_no_moduli.rs`; the targeted `cargo test -p pvthfhe-fhe params_no_moduli` now passes and the full crate test suite stays green.

## [2026-05-06] FHE encoding correctness fix
- With `t_plain = 65536 = 2^16`, each BFV slot can carry only 16 bits; packing 8 plaintext bytes into one `u64` slot silently truncates six bytes modulo `65536` during real encrypt/decrypt.
- `fhers.rs` plaintext framing still reserves slot 0 for original byte length, so payload capacity is `(degree - 1) * 2` bytes, not `(degree - 1) * 8`.
- Added a real-backend RED→GREEN integration test in `encoding_golden.rs` that round-trips a non-trivial ASCII string through `encrypt` + threshold `aggregate_decrypt`; pure slot-function tests alone did not expose the modulus-truncation bug.
