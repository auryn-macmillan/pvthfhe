# `pvthfhe-real-fhe-demo` — Real BFV in the End-to-End Demo

> **Status**: ACTIVE — Phase F ready to start
> **Predecessor context**: `.sisyphus/plans/pvthfhe-real-p2p3.md` (P1/P2/P3 cryptographic core; ACTIVE) — orthogonal: that plan replaces folding/on-chain surrogates; THIS plan replaces the FHE surrogate.
> **Backend lock**: F1, AGENTS.md — `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`.
> **Strategic framing**: the wrapper crate `e3-trbfv` (gnosisguild/enclave) is the **status-quo baseline that PVTHFHE aims to surpass at n≫100**. We integrate it now to (a) make the demo's keygen/encrypt/decrypt timings real, (b) provide an honest, line-up-able baseline against PVTHFHE's folding contribution, and (c) empirically reproduce the n≈50–100 scaling cliff that motivates the whole project.

---

## 0. Mission

Replace the XOR/SHA-256 surrogate in `MockBackend`/`FhersBackend` with real threshold BFV cryptography end-to-end through the demo (`just demo-e2e`), retaining all Stage 0 tripwires. After this plan, every *cryptographic primitive* on the demo's hot path (keygen share, PK aggregation, encryption, partial decryption, threshold reconstruction) executes real lattice arithmetic via `gnosisguild/fhe.rs` + `gnosisguild/enclave/crates/trbfv`. The folding accumulator (P2) and on-chain verifier (P3) **remain surrogate** — that is the explicit territory of `pvthfhe-real-p2p3`.

**Success vignette**: `just demo-e2e --n 64 --threshold 33` runs in seconds-to-minutes (not microseconds), prints a non-zero `keygen_ms`, `encrypt_ms`, `decrypt_ms`, and the recovered plaintext bytes equal the input. `just demo-e2e --n 256 --threshold 129` reproduces the e3-trbfv scaling cliff (DKG dominates wall-time). Setting `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` + `--features mock` still routes to `MockBackend`. Default-feature builds with `FhersBackend` no longer return the T33 sentinel error.

---

## 1. Out of Scope

- **Folding/aggregation accumulator** stays SHA-256 surrogate (`pvthfhe-aggregator/src/folding/mod.rs`). Replaced by `pvthfhe-real-p2p3` Phase 2 (Cyclo).
- **On-chain verifier** stays killswitch. Replaced by `pvthfhe-real-p2p3` Phase 3.
- **NIZK well-formedness proofs** (Greco) — share validity is **NOT** enforced; honest-but-curious threat model only. Tracked as residual surrogate; banner stays in `SECURITY.md`.
- **Eval-key / relinearization / Galois DKG** — only PK + decryption are wired. Homomorphic multiplication and rotations are not on the demo path. (Auryn's `EVAL_KEY_MPC_DESIGN.md` is referenced for future eval-key work.)
- **PVSS Noir circuits** (`gnosisguild/enclave/circuits/`) — not wired; folding plan owns Noir integration.
- **Noise budget tuning at large `n`** — we adopt e3-trbfv's smudging defaults (λ, z) verbatim; tuning is a Phase F4 follow-on.
- **Wire-format stability across PVTHFHE versions** — internal-only; bumping the `fhe.rs` rev may break serialised artefacts.

---

## 2. Non-negotiable Policies

- **TDD strict**: RED test committed before every implementation change; CI must observe the RED state.
- **ZERO** new `#[allow(...)]` attributes anywhere in modified code.
- **Cargo**: `cargo ... -p <crate>` from repo root; never `--workspace` for tests.
- **Stage 0 tripwires SURVIVE**: `pvthfhe-fhe/build.rs` warning + `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` env-var guard for `MockBackend` remain active; renamed only to "MOCK BACKEND ACTIVE" once `FhersBackend` is real (no longer "ANY backend is a surrogate").
- **No silent fallback**: `FhersBackend::backend_id()` must report the linked `fhe`/`e3-trbfv` git rev; any escape-hatch surfaces in API and `SECURITY.md` in the same PR.
- **Stub protocol**: replace the body of `crates/pvthfhe-fhe/src/fhers.rs` in place; do NOT delete and recreate the file.
- **Backend lock**: `fhe`/`fhe-traits`/`fhe-math`/`e3-trbfv` revs are pinned in Cargo.toml; bumps require a F-task with rationale.
- **Orchestrator boundary**: implementation is delegated to subagents; orchestrator only edits `.sisyphus/` and merges.
- **Forbidden commands**: `nargo prove`, `nargo verify` (canonical BB flow only). Not directly relevant to this plan but the policy applies.

---

## 3. Phase F — Foundations (dependency wiring & param schema)

Gate: `cargo build -p pvthfhe-fhe` succeeds with new deps; `cargo test -p pvthfhe-fhe` green; param fixture migration tests pass.

### Task F1 — Pin `e3-trbfv` + `fhe`/`fhe-traits` in `pvthfhe-fhe/Cargo.toml`

| Field | Value |
|---|---|
| **ID** | F1 |
| **Owner** | `crates/pvthfhe-fhe/Cargo.toml` |
| **Depends on** | — |
| **Gate** | F-gate |

**RED test** (`crates/pvthfhe-fhe/tests/dep_lock.rs`): assert that `cargo metadata --format-version=1 -p pvthfhe-fhe` includes packages `fhe`, `fhe-traits`, `fhe-math`, `e3-trbfv`, all resolving to the locked git rev recorded in `REPRODUCING.md`. Initially fails (deps absent).

**GREEN criteria**:
- `pvthfhe-fhe/Cargo.toml` adds:
  - `fhe = { git = "https://github.com/gnosisguild/fhe.rs", rev = "5f24d0b62a7329b789db07a065b68accd614a47b" }`
  - `fhe-traits = { git = "...", rev = "..." }`
  - `e3-trbfv = { git = "https://github.com/gnosisguild/enclave", rev = "<lock-pinned>" }`
  - any minimal transitive (`anyhow`, `tracing` already in workspace? — to confirm during F1).
- `fhe-math` rev in `pvthfhe-cyclo/Cargo.toml` matches.
- `REPRODUCING.md` updated with the four pinned revs.
- `cargo build -p pvthfhe-fhe` succeeds.

**Checkboxes**:
- [x] F1

### Task F2 — Extend `Params` to carry an explicit moduli list + variance

| Field | Value |
|---|---|
| **ID** | F2 |
| **Owner** | `crates/pvthfhe-fhe/src/types.rs`, `crates/pvthfhe-fhe/src/mock_impl.rs` (parser), all `parameters.toml` fixtures |
| **Depends on** | — |
| **Gate** | F-gate |

**RED test** (`crates/pvthfhe-fhe/tests/params_moduli.rs`): parse a TOML containing `moduli = [0x..., 0x..., 0x...]` and `variance = 10`; assert `Params { moduli, variance, ... }` round-trips. Initially fails (fields absent).

**GREEN criteria**:
- `Params` gains `moduli: Vec<u64>`, `variance: usize`. Parser accepts both forms with a transitional shim: if `moduli` absent, derive a canonical 3×62-bit moduli set from `log2_q` (matching `BfvParameters::default_arc(3, log2(N))` for L=3) and emit a `tracing::warn!`. Shim removed in F4.
- All `parameters.toml` fixtures across the workspace add explicit `moduli` and `variance` fields (canonical: N=8192, log₂q≈174 → 3 NTT-friendly 58-bit primes consistent with current `pvthfhe-cyclo` choices; exact values to be verified via `fhe-math::zq::supports_ntt`).
- Existing tests pass; param fixtures unchanged in semantics.

**Checkboxes**:
- [x] F2

### Task F3 — Versioned wire format for `KeygenShare` and `PublicKey`

| Field | Value |
|---|---|
| **ID** | F3 |
| **Owner** | `crates/pvthfhe-fhe/src/types.rs`, new `crates/pvthfhe-fhe/src/wire.rs` |
| **Depends on** | F2 |
| **Gate** | F-gate |

**RED test** (`crates/pvthfhe-fhe/tests/wire_roundtrip.rs`): synthesise a `KeygenShare { bytes }` via the new `wire::encode_keygen_share(version, crp_bytes, p0_share_bytes)`, decode it, assert all three fields round-trip; assert `version_byte == 0x01`. Initially fails (module absent).

**GREEN criteria**:
- `wire.rs` defines `KeygenShareV1 { crp: Vec<u8>, p0_share: Vec<u8> }`, `PublicKeyV1 { p0: Vec<u8>, p1: Vec<u8> }`, `DecryptShareV1 { d_share_poly: Vec<u8> }`, all with a leading `0x01` version byte and length-prefixed sub-fields (CBOR or hand-rolled — implementer's choice; CBOR preferred to match P3 boundary).
- `cargo test -p pvthfhe-fhe wire` exits 0.
- The opaque `bytes: Vec<u8>` fields of `KeygenShare`/`PublicKey`/`DecryptShare` are unchanged at the trait boundary; only the *contents* are now structured.

**Checkboxes**:
- [x] F3

### Task F4 — Remove transitional moduli shim; enforce explicit moduli

| Field | Value |
|---|---|
| **ID** | F4 |
| **Owner** | `crates/pvthfhe-fhe/src/mock_impl.rs` |
| **Depends on** | F2, plus all consumers updated |
| **Gate** | F-gate |

**RED test**: parse a TOML with `log2_q = 174` and *no* `moduli` field; assert `Err(FheError::Backend{..})` with message containing `"moduli required"`. Initially fails (shim still active, returns Ok).

**GREEN criteria**: shim deleted; all fixtures supply `moduli`; CI-grep ensures no `parameters.toml` without `moduli =`.

**Checkboxes**:
- [x] F4

---

## 4. Phase A — Real distributed key generation

Gate: `cargo test -p pvthfhe-fhe fhers_keygen` green; `cargo test -p pvthfhe-aggregator keygen_real` green; demo CLI keygen path no longer returns `not_implemented`.

### Task A1 — `FhersBackend::load_params` constructs `Arc<BfvParameters>`

| Field | Value |
|---|---|
| **ID** | A1 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | F2 |
| **Gate** | A-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_load_params.rs`): load canonical PVTHFHE TOML; assert backend internal `BfvParameters.degree() == 8192` and `moduli().len() == 3`. Initially fails (`FhersBackend` doesn't store BFV params).

**GREEN criteria**: `FhersBackend` gains a private `bfv_params: Arc<BfvParameters>` built via `BfvParametersBuilder::new().set_degree(p.n).set_moduli(&p.moduli).set_plaintext_modulus(p.t_plain).build_arc()?`. `Params` view retained.

**Checkboxes**:
- [x] A1

### Task A2 — CRP commitment in `FhersBackend` (deterministic per session)

| Field | Value |
|---|---|
| **ID** | A2 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | A1, F3 |
| **Gate** | A-gate |

**RED test**: assert two `FhersBackend` instances seeded with the same `session_id` produce byte-identical CRPs; with different `session_ids`, CRPs differ. Initially fails (no CRP API).

**GREEN criteria**: backend gains `fn crp_for_session(&self, session_id: &[u8; 32]) -> CommonRandomPoly` using `CommonRandomPoly::new_deterministic(&bfv_params, session_id_as_chacha_seed)`. Session ID plumbed through the trait via a new method `keygen_share_with_session(&self, session_id, party_id, rng)` (default impl panics; default `keygen_share` calls it with a per-instance random session). The aggregator's `KeygenSimulator` is updated in A4 to thread session through.

**Checkboxes**:
- [x] A2

### Task A3 — `keygen_share` produces real `PublicKeyShare` bytes

| Field | Value |
|---|---|
| **ID** | A3 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | A1, A2, F3 |
| **Gate** | A-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_keygen_share.rs`): generate 3 keygen shares with distinct `party_id`, encode each via `wire::KeygenShareV1`, decode and call `PublicKeyShare::deserialize(p0_bytes, &par, crp)`; `Aggregate::<PublicKeyShare>::from_shares(...)` produces a valid `PublicKey` (assert encryption of zero plaintext + decryption with the *summed secret* recovers zero — done with a test-only `SecretKey::new(sk_sum_coeffs, &par)`). Initially fails (`not_implemented`).

**GREEN criteria**:
- `keygen_share` directly composes: `SecretKey::random` + `PublicKeyShare::new_extended` + `TRBFV::generate_smudging_error` + `ShareManager::generate_secret_shares_from_poly`. First-pass avoids `e3-trbfv` wrapper to minimise transitive dep surface; fallback: use the wrapper if composition proves brittle.
- `KeygenShare.bytes` carries `KeygenShareV1 { crp_bytes, p0_share_bytes }`; smudging-noise share and Shamir SK shares are *withheld inside backend session state* indexed by `party_id` (see Task C-series for retrieval).
- Backend exposes a `take_party_state(&self, party_id) -> PartyState` for handoff to decryption (used in C-series).

**Checkboxes**:
- [x] A3

### Task A4 — `aggregate_keygen` produces real BFV `PublicKey`

| Field | Value |
|---|---|
| **ID** | A4 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | A3 |
| **Gate** | A-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_aggregate.rs`): take 5 real `KeygenShare`s, aggregate, encrypt a known plaintext under the resulting PK, attempt decryption with the **sum of the 5 secret keys** (test-only access via `take_party_state`); assert plaintext recovers. Initially fails (`not_implemented`).

**GREEN criteria**: `aggregate_keygen` decodes each `KeygenShareV1`, asserts all CRPs are byte-identical (else `FheError::InconsistentCrp`), constructs `PublicKeyShare::deserialize(...)` for each, calls `PublicKey::from_shares(iter)`, encodes resulting `(p0, p1)` into `wire::PublicKeyV1` and returns. Errors map to `FheError::Backend{reason}`.

**Checkboxes**:
- [x] A4

### Task A5 — Aggregator `KeygenSimulator` integration

| Field | Value |
|---|---|
| **ID** | A5 |
| **Owner** | `crates/pvthfhe-aggregator/src/keygen/simulator.rs` |
| **Depends on** | A4 |
| **Gate** | A-gate |

**RED test** (`crates/pvthfhe-aggregator/tests/keygen_real.rs`): drive `KeygenSimulator` with `FhersBackend`, n=8 parties, run all 3 rounds, assert resulting `PublicKey.bytes` decodes to `PublicKeyV1` (version byte `0x01`). Initially fails (simulator currently passes through XOR'd 4-byte ID via mock).

**GREEN criteria**: simulator threads `session_id` (sourced from epoch + ciphertext_hash placeholder) through to `keygen_share_with_session`; R1/R2 (commitments + complaints) remain — they bind to `KeygenShareV1.crp_bytes ∥ p0_share_bytes`; R3 calls `aggregate_keygen` unchanged. Simulator's existing duplicate-party and missing-share checks survive.

**Checkboxes**:
- [x] A5

---

## 5. Phase B — Real public-key encryption

Gate: `cargo test -p pvthfhe-fhe fhers_encrypt` green; encryption time is non-zero and scales with `N`.

### Task B1 — `encrypt` calls real `PublicKey::try_encrypt`

| Field | Value |
|---|---|
| **ID** | B1 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | A4, F3 |
| **Gate** | B-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_encrypt.rs`): build a real PK via Phase A; encrypt the plaintext bytes `b"hello world"` (encoded as `Vec<u64>` chunks fitting `t_plain`); assert `Ciphertext.bytes` decodes via `Ciphertext::from_bytes(&par, &raw)` to a 2-poly ciphertext. Initially fails.

**GREEN criteria**:
- Plaintext-byte → `fhe::bfv::Plaintext` encoding pipeline defined: chunk input bytes into `u64` slots (LSB-packed), pad with zeros to `par.degree()`, encode via `Plaintext::try_encode(&slots, Encoding::poly(), &par)`. Reverse pipeline lives in `aggregate_decrypt`.
- `encrypt` calls `pk.try_encrypt(&pt, rng)`, serialises the resulting `Ciphertext` via `fhe_traits::Serialize::to_bytes`, wraps in `Ciphertext { bytes }`. (No wire-version wrapper needed for ciphertexts in v1; `fhe.rs` ciphertext serialisation already self-describes.)
- Encryption of an n=8192 plaintext takes >1ms on commodity hardware (sanity check).

**Checkboxes**:
- [x] B1

### Task B2 — Encoding boundary tests (golden vectors)

| Field | Value |
|---|---|
| **ID** | B2 |
| **Owner** | `crates/pvthfhe-fhe/tests/encoding_golden.rs` |
| **Depends on** | B1 |
| **Gate** | B-gate |

**RED test**: golden inputs `[0x00..0xff]` (256 bytes) and `[0x00; par.degree() / 8]` round-trip through `bytes_to_slots` → `slots_to_bytes`; assert exact equality. Initially fails (functions don't exist).

**GREEN criteria**: byte↔slot helpers documented and tested; chunk size pinned (`bytes_per_plaintext = par.degree() * log2(t_plain).floor() / 8`); inputs longer than one plaintext slice are rejected with `FheError::PlaintextTooLong` (multi-ciphertext support is a Phase E follow-on).

**Checkboxes**:
- [x] B2

---

## 6. Phase C — Real threshold decryption (Shamir-on-additive, `t`-of-`n`)

Gate: `cargo test -p pvthfhe-fhe fhers_decrypt` green; `t-1` shares fail to decrypt; `t` shares succeed; `n` shares also succeed.

### Task C1 — Per-party state plumbing for decryption

| Field | Value |
|---|---|
| **ID** | C1 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | A3 |
| **Gate** | C-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_party_state.rs`): after Phase A keygen of 5 parties, assert each party can retrieve its own secret-key Shamir shares + smudging-noise shares; assert party `i` cannot retrieve party `j != i`'s state (returns `FheError::UnknownParty`). Initially fails (no API).

**GREEN criteria**:
- Backend internal `HashMap<u32, PartyState>` keyed by `party_id` carrying `{ sk_shamir_shares: Vec<Poly>, esi_shamir_shares: Vec<Poly>, sk_poly_sum: Poly, esi_poly_sum: Vec<Poly> }`.
- After R3 keygen each party's `sk_poly_sum` (sum of received SK Shamir shares from all parties) and `esi_poly_sum` (likewise for smudging) is computed. **Matches e3-trbfv's two-phase pattern**: gen → distribute → sum → ready-to-decrypt.
- Distribution is in-process for the demo (single-process simulator); cross-process distribution is out of scope.

**Checkboxes**:
- [x] C1

### Task C2 — `partial_decrypt` produces real decryption-share polynomial

| Field | Value |
|---|---|
| **ID** | C2 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | B1, C1 |
| **Gate** | C-gate |

**RED test** (`crates/pvthfhe-fhe/tests/fhers_partial_decrypt.rs`): with n=5, t=3, encrypt `b"42"`; produce 5 partial decryption shares; assert each `DecryptShare.bytes` decodes via `wire::DecryptShareV1` and the inner poly matches `ShareManager::decryption_share(ct, sk_poly_sum, esi_poly_sum[0])`. Initially fails.

**GREEN criteria**: `partial_decrypt` invokes `ShareManager::new(n, t, par).decryption_share(Arc::new(ct), party.sk_poly_sum.clone(), party.esi_poly_sum[0].clone())`, wraps in `DecryptShareV1 { d_share_poly: poly_bytes }`. `n` and `t` are sourced from a backend-stored `(n, t)` set during keygen.

**Checkboxes**:
- [x] C2

### Task C3 — `aggregate_decrypt` Lagrange-reconstructs and decodes plaintext

| Field | Value |
|---|---|
| **ID** | C3 |
| **Owner** | `crates/pvthfhe-fhe/src/fhers.rs` |
| **Depends on** | C2 |
| **Gate** | C-gate |

**RED test 1 — happy path** (`crates/pvthfhe-fhe/tests/fhers_aggregate_decrypt.rs`): n=5, t=3, encrypt `b"42"`; pick any 3 of 5 shares; assert `aggregate_decrypt` returns `b"42"`. Initially fails.
**RED test 2 — t-1 shares fail**: pick 2 of 5; assert `Err(FheError::InsufficientShares { have: 2, need: 3 })`.
**RED test 3 — n shares succeed**: pass all 5; assert recovery (Lagrange handles any subset of size ≥ t).
**RED test 4 — wrong-ciphertext binding**: shares from ct_A cannot decrypt ct_B; assert recovery fails or returns garbage. (The aggregator already validates `ciphertext_hash` binding upstream — this test asserts backend-level robustness too.)

**GREEN criteria**:
- `aggregate_decrypt` decodes each `DecryptShareV1` to a `Poly`, gathers the corresponding 1-based `party_id`s, calls `ShareManager::decrypt_from_shares(threshold_shares, party_ids, Arc::new(ct))` to obtain a `Plaintext`, decodes via `decode_plaintext_to_vec_u64` (or local equivalent if not depending on `e3-bfv-client`), runs `slots_to_bytes` from B2, returns `Vec<u8>`.
- Insufficient-shares branch returns `FheError::InsufficientShares` *before* calling `decrypt_from_shares`.
- Aggregator's existing checks (`allowed_parties`, dedup, `ciphertext_hash`, `nizk` marker) remain untouched; backend just becomes real.

**Checkboxes**:
- [x] C3

### Task C4 — Aggregator integration smoke test

| Field | Value |
|---|---|
| **ID** | C4 |
| **Owner** | `crates/pvthfhe-aggregator/tests/decrypt_real.rs` |
| **Depends on** | C3, A5 |
| **Gate** | C-gate |

**RED test**: full simulator run with `FhersBackend`, n=8, t=5; encrypt `[0u8; 64]`; t parties partial-decrypt; aggregator validates and returns plaintext; assert `== [0u8; 64]`. Initially fails.

**GREEN criteria**: passes.

**Checkboxes**:
- [x] C4

---

## 7. Phase D — Demo + benchmark integration

Gate: `just demo-e2e --n 32 --threshold 17` runs end-to-end with real timings; `just bench-fhe-baseline` reproduces a scaling cliff at n≈64–128.

### Task D1 — CLI `--threshold` flag + threading through demo

| Field | Value |
|---|---|
| **ID** | D1 |
| **Owner** | `crates/pvthfhe-cli/src/main.rs`, `Justfile` |
| **Depends on** | C4 |
| **Gate** | D-gate |

**RED test** (`crates/pvthfhe-cli/tests/demo_threshold.rs`): invoke `pvthfhe demo --n 4 --threshold 3 --seed 1`; assert exit 0, stdout includes `threshold=3`, `keygen_ms > 0`, `decrypt_ms > 0`. Initially fails (no `--threshold` flag; demo path errors with `not_implemented`).

**GREEN criteria**: clap arg `--threshold <usize>` (default `n/2 + 1`) wired into the demo subcommand; `Justfile` `demo-e2e` recipe parameterised: `just demo-e2e n=32 threshold=17`. Demo prints structured timings (`keygen_ms`, `aggregate_keygen_ms`, `encrypt_ms`, `partial_decrypt_ms`, `aggregate_decrypt_ms`).

**Checkboxes**:
- [x] D1

### Task D2 — Stage-0 banner update

| Field | Value |
|---|---|
| **ID** | D2 |
| **Owner** | `crates/pvthfhe-fhe/build.rs`, `crates/pvthfhe-fhe/src/mock.rs`, `SECURITY.md`, `README.md` |
| **Depends on** | C4 |
| **Gate** | D-gate |

**RED test** (`crates/pvthfhe-fhe/tests/banner.rs`): with `mock` feature OFF, build emits `cargo:warning=` containing `"FOLDING ACCUMULATOR IS A SURROGATE"` (NOT the prior FHE-surrogate warning); with `mock` feature ON, build still warns `"MOCK BACKEND ACTIVE — XOR/SHA256 ONLY"`. Initially fails (current banner says all backends are surrogates).

**GREEN criteria**:
- `build.rs` distinguishes the two cases; warning text updated to localise the surrogate to **folding/on-chain** only.
- `MockBackend::load_params` retains `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` env-var guard; error message unchanged.
- `SECURITY.md` updated: FHE backend now real (subject to honest-but-curious threat model — no Greco proofs); folding + on-chain still surrogate.
- `README.md` "Status: Research Prototype" section: bullet for FHE moves from ❌ surrogate to ⚠️ real but unproven (no Greco).

**Checkboxes**:
- [x] D2

### Task D3 — Baseline scaling benchmark `bench-fhe-baseline`

| Field | Value |
|---|---|
| **ID** | D3 |
| **Owner** | `bench/scripts/fhe_baseline.rs`, `Justfile` |
| **Depends on** | D1 |
| **Gate** | D-gate |

**RED test** (`bench/tests/baseline_smoke.rs`): run benchmark with `n ∈ {4, 8, 16}`; assert each completes; assert wall-time monotonically increases with `n`. Initially fails (script absent).

**GREEN criteria**:
- Criterion-or-bespoke Rust binary that runs full keygen + 1 encrypt + threshold decrypt for `n ∈ {4, 8, 16, 32, 64, 128, 256}` (subject to hardware budget — auto-skip if a single iteration exceeds 5 min wall-time), `t = ⌈2n/3⌉`.
- Output: CSV `bench/results/fhe-baseline.csv` with columns `n, t, keygen_total_s, keygen_per_party_s, encrypt_s, partial_decrypt_per_party_s, aggregate_decrypt_s, peak_rss_mb`.
- `bench/results/fhe-baseline.md` (auto-generated) renders a table + ASCII chart highlighting where DKG wall-time crosses 60 s — empirically reproducing the n≈50–100 cliff cited as motivation for PVTHFHE.
- This benchmark becomes the **before** picture; `pvthfhe-real-p2p3` Phase 2 produces the **after** (folded) picture.

**Checkboxes**:
- [x] D3

### Task D4 — Update `pvthfhe-followon.md` with deferred items

| Field | Value |
|---|---|
| **ID** | D4 |
| **Owner** | `.sisyphus/plans/pvthfhe-followon.md` |
| **Depends on** | D3 |
| **Gate** | D-gate |

**RED test**: grep for new follow-on entries — `Greco well-formedness ZK proofs`, `Eval-key/relinearization DKG` (cite Auryn's `EVAL_KEY_MPC_DESIGN.md`), `Multi-ciphertext encrypt` (lift B2 length cap), `Cross-process share distribution`, `Smudging-noise tuning at n≥1024`. Initially fails (entries absent).

**GREEN criteria**: entries added with cross-references to this plan's task IDs.

**Checkboxes**:
- [x] D4

---

## 8. Phase E — Deferred (banner-only, not implemented in this plan)

Listed for traceability:

- **E1** Greco well-formedness ZK proofs for share + ciphertext validity (replaces `nizk: vec![1]` placeholder). Belongs to a future `pvthfhe-greco` plan; uses `gnosisguild/enclave/circuits/`.
- **E2** Eval-key + relinearization + Galois DKG (homomorphic multiplication path). Reference: `EVAL_KEY_MPC_DESIGN.md`.
- **E3** Cross-process share distribution (network layer) — currently in-process simulator only.
- **E4** Folding accumulator integration with real ciphertexts (boundary with `pvthfhe-real-p2p3` Phase 2).
- **E5** Real on-chain decrypt verification using real `D = Σ dᵢ` (boundary with `pvthfhe-real-p2p3` Phase 3).

---

## 9. Acceptance Gates

- **F-gate**: `cargo test -p pvthfhe-fhe` green; `cargo build -p pvthfhe-fhe --all-features` green; `REPRODUCING.md` lists 4 pinned revs.
- **A-gate**: `cargo test -p pvthfhe-fhe fhers_keygen` green; `cargo test -p pvthfhe-aggregator keygen_real` green.
- **B-gate**: `cargo test -p pvthfhe-fhe fhers_encrypt` green; encoding round-trip golden vectors pass.
- **C-gate**: `cargo test -p pvthfhe-fhe fhers_aggregate_decrypt` green (4 subtests); `cargo test -p pvthfhe-aggregator decrypt_real` green.
- **D-gate**: `just demo-e2e n=32 threshold=17` exit 0 with non-zero timings; `just bench-fhe-baseline n_max=64` produces `bench/results/fhe-baseline.csv` ≥ 4 rows; `cargo test -p pvthfhe-fhe banner` green; `SECURITY.md` and `README.md` updated.
- **PLAN-GATE (final)**: orchestrator runs `just phase1-gate` (must remain green; this plan does not touch P1 NIZK) AND `just demo-e2e` AND `just bench-fhe-baseline` — all green; `cargo clippy --workspace -- -D warnings` clean (modulo existing baseline); zero new `#[allow]`.

---

## 10. Risks & Escape Hatches

| # | Risk | Mitigation | Escape hatch |
|---|------|------------|--------------|
| R1 | `e3-trbfv` pulls heavy `e3-*` transitive deps (encrypted state, tracing, anyhow) bloating PVTHFHE | A3 spec allows direct composition of `fhe::mbfv` + `fhe::trbfv::ShareManager` instead of the wrapper | Choice deferred to A3 implementer; if `e3-trbfv` deps exceed +30 transitive crates, fall back to direct composition (no plan rev needed) |
| R2 | `fhe-math` rev pinned in `pvthfhe-cyclo` (`5f24d0b6`) is older than `fhe.rs` head — symbol drift | F1 forces all four crates onto same locked rev | If `fhe::trbfv` doesn't exist at `5f24d0b6`, F1 RFC for rev bump (separate F-task; affects `pvthfhe-cyclo`) |
| R3 | `e3-trbfv::gen_pk_share_and_sk_sss` requires `e3_crypto::Cipher` (encrypted state at rest) — not needed in PVTHFHE | Bypass by direct composition | (See R1) |
| R4 | Real keygen at n=128 may exceed CI wall-time budget | D3 auto-skips configurations > 5 min; CI uses n≤16 only | `just bench-fhe-baseline-large` runs locally, not in CI |
| R5 | Param fixture migration (F2) breaks downstream tests in `pvthfhe-keygen`, `pvthfhe-aggregator`, `pvthfhe-cyclo` | F2 GREEN includes "all consumers updated"; subagent task fans out edits | Transitional shim (auto-derive moduli) deferred-deletion to F4 |
| R6 | Encoding pipeline (B1/B2) limits ciphertext to one plaintext-slot's worth of bytes (≈8 KB at N=8192) | B2 explicitly out-of-scope multi-ct; demo uses ≤1 KB plaintext | Multi-ct encrypt is E2-adjacent follow-on |
| R7 | `e3-trbfv` license/governance change (gnosisguild → "The Interfold" rebrand mid-flight) | Pinned git rev | If repo is renamed/moved, vendor source under `vendor/e3-trbfv/` (separate F-task) |
| R8 | Aggregator's `nizk: vec![1]` placeholder + binding checks may interact with real shares unexpectedly | C4 smoke test catches integration issues; existing aggregator validation tests must remain green | If breakage is structural, raise to user — do NOT relax aggregator checks unilaterally |

---

## 11. Sequencing Summary

```
F1 ──► F2 ──► F3 ──► F4
              │
              ▼
       A1 ──► A2 ──► A3 ──► A4 ──► A5
                            │
                            ▼
                     B1 ──► B2
                            │
                            ▼
                     C1 ──► C2 ──► C3 ──► C4
                                          │
                                          ▼
                                   D1 ──► D2 ──► D3 ──► D4 ──► PLAN-GATE
```

Critical path: F1 → F2 → A1 → A3 → A4 → A5 → B1 → C1 → C2 → C3 → C4 → D1 → D3 → PLAN-GATE.
Parallelizable: F3↔A2, B2↔C1, D2↔D3, D4↔D3.

---

**End of plan.**
