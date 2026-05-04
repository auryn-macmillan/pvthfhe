# pvthfhe-real-p2p3 — Real P2 (Cyclo) + Real P3 (UltraHonk-wrapped MicroNova)

> **Status**: ACTIVE — Phase 0 complete, Phase 1 ready to start
> **Predecessor**: `.sisyphus/plans/pvt-fhe-scaling.md` (CLOSED, 49/49 ✅)
> **Spec freeze**: `.sisyphus/design/spec-real-p2p3.md`
> **Assumptions ledger**: `.sisyphus/design/assumptions-ledger.md`
> **P3 architecture decision**: **Option B** — MicroNova proof wrapped in UltraHonk Noir circuit; preserve `IPvthfheVerifier.sol` ABI

---

## 0. Mission

Replace the two cryptographic surrogates carried over from the prior plan: the `SurrogateAdapter` (P2, folding) and the `ecrecover`/`TRUSTED_SIGNER` construction (P3, on-chain verification). P2 is replaced by **Cyclo**, a LatticeFold+-style folding scheme over RLWE using partial range checks, delivering O(n) per-party work. P3 is replaced by **MicroNova** proof compression wrapped inside a Noir/UltraHonk circuit, yielding a BB-generated Solidity verifier that preserves the existing `IPvthfheVerifier.sol` ABI. P1 lattice NIZK conditional-soundness is disclosed and tabled; the work here covers the practical system path only.

---

## 1. Out of Scope

- P1 formal soundness theorem (joint extractor T2 — still tabled)
- Production audits or CVE-class security reviews
- QROM proofs (stretch goal, not gated)
- PQ-secure on-chain verifier (BN254 is non-PQ; documented as A-DLOG-1..4 in assumptions ledger)

---

## 2. Non-negotiable Policies

- **TDD strict**: RED test committed before every implementation change; CI must see the RED state.
- **ZERO** `#[allow(clippy::...)]` attributes in new or modified code.
- Foundry: `forge ... --root contracts` from repo root.
- Noir: `(cd circuits && nargo ...)` from repo root.
- Cargo: `cargo ... -p <crate>` from repo root.
- **Forbidden**: `nargo prove`, `nargo verify`. Use canonical BB flow from AGENTS.md.
- **No silent fallback**: any backend swap or escape-hatch activation surfaces in `backend_id` field + SECURITY.md banner within the same PR.
- **Stub protocol**: replace stubs in place; never delete-and-recreate.
- **User-approved policy 2**: no-silent-fallback escape — every backend swap surfaces in API + SECURITY.md.
- **User-approved policy 3**: parameter renegotiation allowed if Phase-3 gate fails (priority order: §10).

---

## 3. Phase 0 — Literature & Spec Freeze (DONE)

- [x] **L1** — Cyclo digest (`.sisyphus/research/cyclo-digest.md`, 421 L) — LatticeFold+ via partial range checks; ring parameters and norm budget extracted.
- [x] **L2** — MicroNova digest (`.sisyphus/research/micronova-digest.md`, 286 L) — BN254/Grumpkin half-cycle, HAC RoK, Construction 1 Poseidon↔Keccak bridge. **Side-find**: `paper/bib.bib` line 46 has wrong eprint ID (`2024/1826` → `2024/2099`); tracked as A1.
- [x] **L3** — NIZK candidate selection (`.sisyphus/research/nizk-selection.md`, 482 L) — selected candidate **(D)** Cyclo-companion Ajtai NIZK; fallback **(C)**.
- [x] **L4** — Joint spec freeze (`.sisyphus/design/spec-real-p2p3.md`, 740 L) — **Option B** chosen for P3; statement/witness shapes, trait surfaces, proof-byte layout, and FS domain separator all frozen.
- [x] **L5** — Assumptions ledger (`.sisyphus/design/assumptions-ledger.md`, 232 L) — A-MLWE-1..3, A-SIS-1..2, A-DLOG-1..4, A-FS-1, A-ROM-1, A-KZG-1..2.
- [x] **Phase-0 gate**: parameter compat table present in spec §8; all 5 docs non-trivial; no open blockers.

---

## 4. Phase 1 — Per-Share NIZK (Candidate D, Cyclo-companion Ajtai)

Gate: `just phase1-gate`

---

### Task N1 — New crate scaffold `crates/pvthfhe-nizk` + `NizkAdapter` trait

| Field | Value |
|---|---|
| **ID** | N1 |
| **Owner** | `crates/pvthfhe-nizk/src/lib.rs` |
| **Depends on** | — |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/trait_object.rs`): `NizkAdapter` object-safety test — compile-fail if trait is not object-safe.

**GREEN criteria**: `cargo test -p pvthfhe-nizk` exits 0; `NizkAdapter` defines `prove`, `verify`, `backend_id` methods mirroring the surface in spec §3.6; crate appears in `cargo metadata`.

---

### Task N2 — Ajtai commitment over R_{q_commit}

| Field | Value |
|---|---|
| **ID** | N2 |
| **Owner** | `crates/pvthfhe-nizk/src/ajtai.rs` |
| **Depends on** | N1 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/ajtai_binding.rs`): open the same commitment to two distinct witnesses — test asserts this returns `Err`; initially fails because the function is a stub returning `Ok`.

**GREEN criteria**: Ajtai commitment `commit(A, s) → C` with φ=256, q_commit≈2^50 (spec §4.1) implemented; binding-check test passes; `cargo clippy -p pvthfhe-nizk -- -D warnings` clean.

---

### Task N3 — D2 hash-bridge SHA-256 commitment binding

| Field | Value |
|---|---|
| **ID** | N3 |
| **Owner** | `crates/pvthfhe-nizk/src/hash_bridge.rs` |
| **Depends on** | N2 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/hash_bridge.rs`): given a synthesised share `(session_id, i, s_i)`, assert `hash_bridge::commit(session_id, i, s_i) == sha256(session_id ∥ i_le ∥ s_i_be)` — initially fails because impl is a stub.

**GREEN criteria**: D2 variant `C_i = SHA256(session_id ∥ i_le ∥ s_i_be)` (spec §3.1) implemented and golden-vector tested; cross-check against Python reference in `bench/scripts/hash_bridge_ref.py`.

---

### Task N4 — Sigma protocol: prove (s_i, e_i) satisfies RLWE relation

| Field | Value |
|---|---|
| **ID** | N4 |
| **Owner** | `crates/pvthfhe-nizk/src/sigma.rs` |
| **Depends on** | N2, N3 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/sigma_completeness.rs`): generate valid `(s_i, e_i)` pair; run `sigma::prove` then `sigma::verify` — fails initially (stubs return `false`).

**GREEN criteria**: completeness holds for 1000 random honest instances; rejection holds for 100 random cheating witnesses; norm bound `‖e_i‖_∞ ≤ B_e=16` enforced; N=8192, log₂q≈174 (parameters from `parameters.toml [rlwe]`).

---

### Task N5 — Fiat-Shamir transcript with domain separator

| Field | Value |
|---|---|
| **ID** | N5 |
| **Owner** | `crates/pvthfhe-nizk/src/fiat_shamir.rs` |
| **Depends on** | N4 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/fs_domain.rs`): two transcripts with different domain separators must produce distinct challenges — test asserts inequality; fails initially.

**GREEN criteria**: domain separator locked to spec §3.6 constant; transcript is deterministic given `(statement, randomness)`; `cargo test -p pvthfhe-nizk` clean.

---

### Task N6 — Wire new backend into `crates/pvthfhe-fhe`; preserve trait

| Field | Value |
|---|---|
| **ID** | N6 |
| **Owner** | `crates/pvthfhe-fhe/src/nizk_backend.rs` |
| **Depends on** | N5 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-fhe/tests/nizk_roundtrip.rs`): end-to-end prove+verify through `RealNizkAdapter` using new backend — fails while impl still delegates to old stub.

**GREEN criteria**: `RealNizkAdapter` in `crates/pvthfhe-fhe` now calls `pvthfhe-nizk`; old stub removed; `backend_id()` returns `"cyclo-ajtai-d2-conditional"`; full workspace `cargo test` green.

---

### Task N7 — Conditional-soundness disclosure surfaces

| Field | Value |
|---|---|
| **ID** | N7 |
| **Owner** | `crates/pvthfhe-nizk/src/lib.rs`, `SECURITY.md` |
| **Depends on** | N6 |
| **Gate** | phase1-gate |

**RED test** (`crates/pvthfhe-nizk/tests/error_variant.rs`): match on `NizkError::ConditionalSoundness` — compile-fails until variant is added.

**GREEN criteria**: `NizkError::ConditionalSoundness` variant exists; rustdoc on `prove`/`verify` cites spec §3.5; `SECURITY.md` has P1 banner; README badge reads "P1 NIZK: conditional soundness"; CI `cargo doc --no-deps` exits 0.

---

### Task N8 — Adversarial test parity with `tests/lattice_nizk_adversarial.rs`

| Field | Value |
|---|---|
| **ID** | N8 |
| **Owner** | `crates/pvthfhe-nizk/tests/lattice_nizk_adversarial.rs` |
| **Depends on** | N7 |
| **Gate** | phase1-gate |

**RED test**: the adversarial test file itself is the RED artifact — it is committed with stubs that return `Ok(true)` unconditionally; all forged-proof checks then fail.

**GREEN criteria**: at minimum 6 adversarial scenarios pass: wrong `e_i` norm, wrong ciphertext `c`, spoofed `d_i`, replayed proof, mismatched session_id, null witness; `just phase1-gate` exits 0.

---

## 5. Phase 2 — Cyclo Folding over RLWE

Gate: `just phase2-gate`

---

### Task F1 — New crate `crates/pvthfhe-cyclo`; lock ring backend

| Field | Value |
|---|---|
| **ID** | F1 |
| **Owner** | `crates/pvthfhe-cyclo/src/lib.rs` |
| **Depends on** | N1 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/placeholder.rs`): trivial object-safety test on `CycloAdapter` trait — fails until trait is defined.

**GREEN criteria**: crate scaffolded; FHE ring backend chosen per AGENTS.md policy (Poulpy **or** `gnosisguild/fhe.rs`); decision recorded in spec §4.1 addendum and `AGENTS.md` "Backend lock" section; `cargo test -p pvthfhe-cyclo` green.

---

### Task F2 — R_{q_commit} arithmetic: vector ops, NTT, norms

| Field | Value |
|---|---|
| **ID** | F2 |
| **Owner** | `crates/pvthfhe-cyclo/src/ring.rs` |
| **Depends on** | F1 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/ring_ntt.rs`): NTT forward-then-inverse round-trip on random degree-256 polynomial — fails until NTT implemented.

**GREEN criteria**: NTT, point-wise multiplication, `‖·‖_∞` and `‖·‖_2` over R_{q_commit} (φ=256, q_commit from spec §4.1) all correct on 500 random inputs; no unsafe blocks; clippy clean.

---

### Task F3 — CCS instance encoding for one P1 NIZK output

| Field | Value |
|---|---|
| **ID** | F3 |
| **Owner** | `crates/pvthfhe-cyclo/src/ccs_encode.rs` |
| **Depends on** | F2, N6 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/ccs_encode.rs`): encode a single valid NIZK witness into a CCS instance, then check the CCS satisfiability relation — fails while encode is a stub.

**GREEN criteria**: CCS instance for one share passes satisfiability check; constraint count matches spec §4.2 table; encode is deterministic.

---

### Task F4 — Range-check sub-protocol (Cyclo §4, T1)

| Field | Value |
|---|---|
| **ID** | F4 |
| **Owner** | `crates/pvthfhe-cyclo/src/range_check.rs` |
| **Depends on** | F3 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/range_check.rs`): verify that a witness with `‖e_i‖_∞ = B_e + 1` is rejected — fails while stub returns `Ok`.

**GREEN criteria**: T1 range-check sub-protocol (partial range checks per Cyclo §4) implemented; accepts all valid witnesses, rejects all out-of-bound witnesses in 200-sample fuzz.

---

### Task F5 — Extension sub-protocol (Cyclo §5, T2)

| Field | Value |
|---|---|
| **ID** | F5 |
| **Owner** | `crates/pvthfhe-cyclo/src/extension.rs` |
| **Depends on** | F4 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/extension.rs`): run one fold step with T2 extension — fails while stub panics.

**GREEN criteria**: T2 extension sub-protocol produces correct output on 100 random CCS instances; norm growth within spec §4.3 budget.

---

### Task F6 — Folding sub-protocol (Cyclo §6, T3)

| Field | Value |
|---|---|
| **ID** | F6 |
| **Owner** | `crates/pvthfhe-cyclo/src/fold.rs` |
| **Depends on** | F5 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/fold_one.rs`): fold two valid CCS instances into one accumulator — fails while stub returns empty accumulator.

**GREEN criteria**: T3 fold sub-protocol produces accumulator with correct norm; `verify_fold` accepts the output and rejects a tampered accumulator; clippy clean.

---

### Task F7 — Sequential T=10 fold driver; norm budget β_T ≤ B=2^10

| Field | Value |
|---|---|
| **ID** | F7 |
| **Owner** | `crates/pvthfhe-cyclo/src/driver.rs` |
| **Depends on** | F6 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/fold_driver_t10.rs`): fold exactly 10 CCS instances sequentially and check `acc.norm_bound ≤ 2^10` — fails while driver is unimplemented.

**GREEN criteria**: driver folds T=10 steps without norm explosion; final accumulator passes `verify_fold`; benchmark `bench/cyclo_fold_t10` records per-step wall time.

---

### Task F8 — Replace `SurrogateAdapter` with `CycloAdapter`

| Field | Value |
|---|---|
| **ID** | F8 |
| **Owner** | `crates/pvthfhe-aggregator/src/folding/mod.rs` |
| **Depends on** | F7 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-aggregator/tests/cyclo_wire.rs`): call `aggregate` with `CycloAdapter` backend and confirm result is a valid Cyclo accumulator (not surrogate signature) — fails while impl still uses surrogate.

**GREEN criteria**: `SurrogateAdapter` import removed from `pvthfhe-aggregator`; `backend_id()` returns `"cyclo-rlwe-t10"`; full workspace `cargo test` green; SECURITY.md P2 banner updated.

---

### Task F9 — Aggregate N=1024 per-share NIZKs end-to-end; perf bench

| Field | Value |
|---|---|
| **ID** | F9 |
| **Owner** | `crates/pvthfhe-aggregator/benches/aggregate_1024.rs` |
| **Depends on** | F8 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-aggregator/tests/aggregate_1024_smoke.rs`): aggregate 1024 NIZKs — fails (timeout/OOM) while sequential O(n²) stub is active.

**GREEN criteria**: aggregation of n=1024 shares completes within wall-time cap (spec §7.1); per-party work is O(n); bench result written to `bench/results/aggregate_1024.json`.

---

### Task F10 — Conditional-soundness banner for Cyclo Lemma 9

| Field | Value |
|---|---|
| **ID** | F10 |
| **Owner** | `crates/pvthfhe-cyclo/src/lib.rs`, `SECURITY.md` |
| **Depends on** | F8 |
| **Gate** | phase2-gate |

**RED test** (`crates/pvthfhe-cyclo/tests/backend_id_banner.rs`): assert `CycloAdapter::backend_id()` contains substring `"lemma9-heuristic"` — fails until banner added.

**GREEN criteria**: `backend_id()` encodes heuristic flag; rustdoc on `CycloAdapter::fold` cites Cyclo Lemma 9 invertibility heuristic; SECURITY.md P2 banner updated; `cargo doc` clean.

---

### Task F11 — Adversarial: norm-explosion fuzz (β grows beyond B)

| Field | Value |
|---|---|
| **ID** | F11 |
| **Owner** | `crates/pvthfhe-cyclo/tests/adversarial_norm.rs` |
| **Depends on** | F10 |
| **Gate** | phase2-gate |

**RED test**: adversarial test file committed with stubs that accept everything — all norm-explosion checks fail.

**GREEN criteria**: 500-round fuzz with adversarially chosen witnesses confirms that any fold with β_step > B/T is rejected before accumulator update; no panics or UB (run under `cargo test` with address-sanitizer in CI).

---

### Task F12 — `just phase2-gate` recipe implementation

| Field | Value |
|---|---|
| **ID** | F12 |
| **Owner** | `Justfile`, `.sisyphus/scripts/phase2-gate.py` |
| **Depends on** | F11 |
| **Gate** | phase2-gate |

**RED test**: `just phase2-gate` currently exits 2 (stub) — this is the RED state.

**GREEN criteria**: `just phase2-gate` runs full Cyclo test suite + adversarial tests + aggregates 1024 shares; produces `bench/results/phase2-gate.json` with `status: pass`; exits 0.

---

## 6. Phase 3 — MicroNova Compression

Gate: `just phase3-gate`

---

### Task M1 — Locate/implement minimal MicroNova prover (OI-1)

| Field | Value |
|---|---|
| **ID** | M1 |
| **Owner** | `crates/pvthfhe-micronova/src/lib.rs` |
| **Depends on** | F12 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/prover_smoke.rs`): call `MicroNovaProver::prove(r1cs, witness)` — compile-fails until struct defined.

**GREEN criteria**: new crate `pvthfhe-micronova` scaffolded; OI-1 resolution documented in `.sisyphus/research/micronova-oi1-resolution.md` (upstream repo found **or** minimal impl plan with milestone); `cargo check -p pvthfhe-micronova` exits 0.

---

### Task M2 — BN254/Grumpkin half-pairing cycle wired

| Field | Value |
|---|---|
| **ID** | M2 |
| **Owner** | `crates/pvthfhe-micronova/src/cycle.rs` |
| **Depends on** | M1 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/cycle_check.rs`): round-trip scalar through BN254→Grumpkin→BN254 — fails until cycle wired.

**GREEN criteria**: both BN254 and Grumpkin curve backends are wired; coordinate types match; field element round-trip test passes; `cargo test -p pvthfhe-micronova` green.

---

### Task M3 — KZG SRS (universal, BN254) bound to repo

| Field | Value |
|---|---|
| **ID** | M3 |
| **Owner** | `REPRODUCING.md`, `bench/srs/` |
| **Depends on** | M2 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/srs_load.rs`): load SRS from `bench/srs/bn254.srs` — fails until file is present.

**GREEN criteria**: SRS file at `bench/srs/bn254.srs` (or fetch script in `bench/scripts/fetch_srs.sh`); `REPRODUCING.md` documents provenance, size, and hash; `cargo test -p pvthfhe-micronova -- srs_load` exits 0.

---

### Task M4 — HAC RoK / Construction 1 Poseidon↔Keccak bridge

| Field | Value |
|---|---|
| **ID** | M4 |
| **Owner** | `crates/pvthfhe-micronova/src/hash_bridge.rs` |
| **Depends on** | M3 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/hash_bridge.rs`): assert `poseidon_keccak_bridge(x) == expected_keccak` — fails until bridge implemented.

**GREEN criteria**: Construction 1 (MicroNova digest §4.3) implemented; 10 golden-vector tests pass; no `unsafe`; clippy clean.

---

### Task M5 — R1CS encoding of Cyclo accumulator verification (≤ 2^21 constraints)

| Field | Value |
|---|---|
| **ID** | M5 |
| **Owner** | `crates/pvthfhe-micronova/src/r1cs_encode.rs` |
| **Depends on** | M4, F7 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/r1cs_size.rs`): encode Cyclo accumulator verifier into R1CS and assert `num_constraints <= 2^21` — fails while constraint count is a stub returning `usize::MAX`.

**GREEN criteria**: R1CS encoding of the Cyclo `verify_fold` circuit has ≤ 2^21 constraints; actual count recorded in `bench/results/r1cs_size.json`; satisfiability test passes on one honest accumulator.

---

### Task M6 — End-to-end: Cyclo accumulator → R1CS → MicroNova proof; verify in Rust

| Field | Value |
|---|---|
| **ID** | M6 |
| **Owner** | `crates/pvthfhe-micronova/tests/e2e_micronova.rs` |
| **Depends on** | M5 |
| **Gate** | phase3-gate |

**RED test** (`crates/pvthfhe-micronova/tests/e2e_micronova.rs`): produce a MicroNova proof for a 10-fold Cyclo accumulator and verify it in Rust — fails while `prove` returns `Err(Unimplemented)`.

**GREEN criteria**: `prove` + `verify` round-trip passes on 5 random honest inputs; forged accumulator is rejected; wall-time for `prove` recorded in `bench/results/micronova_prove.json`.

---

### Task M7 — `just phase3-gate`

| Field | Value |
|---|---|
| **ID** | M7 |
| **Owner** | `Justfile`, `.sisyphus/scripts/phase3-gate.py` |
| **Depends on** | M6 |
| **Gate** | phase3-gate |

**RED test**: `just phase3-gate` currently exits 2 (stub).

**GREEN criteria**: `just phase3-gate` runs M1..M6 tests, prints `status: pass`, exits 0; if gate **fails** due to constraint count or proving time, invoke escape-hatch procedure from §10; no silent fallback.

---

## 7. Phase 4 — UltraHonk Wrap (Option B) + On-chain

Gate: `just phase4-gate`

---

### Task O1 — Noir circuit `circuits/micronova_wrap`; bind 7 frozen public inputs

| Field | Value |
|---|---|
| **ID** | O1 |
| **Owner** | `circuits/micronova_wrap/src/main.nr` |
| **Depends on** | M7 |
| **Gate** | phase4-gate |

**RED test** (`circuits/micronova_wrap/tests/bind_inputs.nr`): assert all 7 public inputs from proof-boundary are constrained — `nargo test` fails until circuit implemented.

**GREEN criteria**: `(cd circuits && nargo test --package micronova_wrap)` passes; circuit constrains `ciphertext_hash`, `plaintext_hash`, `aggregate_pk_hash`, `dkg_root`, `epoch`, `participant_set_hash`, `D_commitment` exactly as specified in spec §2 and `proof-boundary.md`.

---

### Task O2 — `nargo execute` flow per AGENTS.md

| Field | Value |
|---|---|
| **ID** | O2 |
| **Owner** | `circuits/micronova_wrap/Prover.toml` |
| **Depends on** | O1 |
| **Gate** | phase4-gate |

**RED test**: `(cd circuits && nargo execute --package micronova_wrap --prover-name Prover)` — fails until `Prover.toml` is populated with valid inputs.

**GREEN criteria**: command exits 0; `circuits/micronova_wrap/target/micronova_wrap.json` and `target/micronova_wrap.gz` generated; no `nargo prove` invocation anywhere in scripts.

---

### Task O3 — `bb write_vk --scheme ultra_honk`

| Field | Value |
|---|---|
| **ID** | O3 |
| **Owner** | `circuits/micronova_wrap/target/vk` |
| **Depends on** | O2 |
| **Gate** | phase4-gate |

**RED test**: `bb write_vk --scheme ultra_honk -b circuits/micronova_wrap/target/micronova_wrap.json -o circuits/micronova_wrap/target` — fails until circuit bytecode exists.

**GREEN criteria**: verification key written to `circuits/micronova_wrap/target/vk`; file non-empty; `wc -c vk` matches expected size band from BB docs.

---

### Task O4 — `bb prove --scheme ultra_honk`

| Field | Value |
|---|---|
| **ID** | O4 |
| **Owner** | `circuits/micronova_wrap/target/proof` |
| **Depends on** | O3 |
| **Gate** | phase4-gate |

**RED test**: `bb prove --scheme ultra_honk -b ... -w ... -o circuits/micronova_wrap/target` — fails until valid witness file exists.

**GREEN criteria**: proof file written; `wc -c proof` non-zero; command exits 0.

---

### Task O5 — `bb verify --scheme ultra_honk`

| Field | Value |
|---|---|
| **ID** | O5 |
| **Owner** | CI step / `Justfile` recipe `verify-onchain` |
| **Depends on** | O4 |
| **Gate** | phase4-gate |

**RED test**: `bb verify --scheme ultra_honk -k ... -p ... -i ...` on a tampered proof — must exit non-zero; fails while verifier accepts all inputs.

**GREEN criteria**: honest proof accepted (exit 0); tampered proof rejected (exit non-zero); both outcomes automated in `just verify-onchain`.

---

### Task O6 — Strip `ecrecover`/`TRUSTED_SIGNER` from `P3RealVerifier.sol`

| Field | Value |
|---|---|
| **ID** | O6 |
| **Owner** | `contracts/src/P3RealVerifier.sol` |
| **Depends on** | O5 |
| **Gate** | phase4-gate |

**RED test** (`contracts/test/P3RealVerifier_no_ecrecover.t.sol`): assert that `P3RealVerifier` contains no reference to `ecrecover` or `TRUSTED_SIGNER` — `forge test --root contracts` fails until lines removed.

**GREEN criteria**: all surrogate lines listed in spec §6.6 removed; `grep -r TRUSTED_SIGNER contracts/src` returns empty; SECURITY.md P3 surrogate banner removed or updated to "RESOLVED".

---

### Task O7 — Wire BB UltraHonk Solidity verifier; preserve `IPvthfheVerifier.sol` ABI

| Field | Value |
|---|---|
| **ID** | O7 |
| **Owner** | `contracts/src/UltraHonkVerifier.sol`, `contracts/src/P3RealVerifier.sol` |
| **Depends on** | O6 |
| **Gate** | phase4-gate |

**RED test** (`contracts/test/abi_preservation.t.sol`): call every function in `IPvthfheVerifier` on the new verifier — fails while ABI is broken.

**GREEN criteria**: BB-generated `UltraHonkVerifier.sol` imported; `IPvthfheVerifier.sol` function selectors unchanged (verified by `.sisyphus/scripts/check-abi.py`); `forge build --root contracts` exits 0.

---

### Task O8 — Foundry happy-path tests

| Field | Value |
|---|---|
| **ID** | O8 |
| **Owner** | `contracts/test/P3RealVerifier.t.sol` |
| **Depends on** | O7 |
| **Gate** | phase4-gate |

**RED test**: `forge test --root contracts --match-test test_happy` — fails while verifier rejects all proofs.

**GREEN criteria**: at minimum 3 happy-path scenarios pass: valid proof+inputs accepted; wrong epoch rejected; wrong `ciphertext_hash` rejected; `forge test --root contracts` exits 0.

---

### Task O9 — Foundry adversarial tests

| Field | Value |
|---|---|
| **ID** | O9 |
| **Owner** | `contracts/test/P3RealVerifier_adversarial.t.sol` |
| **Depends on** | O8 |
| **Gate** | phase4-gate |

**RED test**: adversarial test file committed with `assertTrue(false)` stubs — all fail.

**GREEN criteria**: at minimum 4 adversarial scenarios: wrong public inputs (each of the 7); mangled proof bytes; replay with old epoch; all return `false` from `verify`; no reverts on adversarial input.

---

### Task O10 — Gas measurement under cap; record in `bench/`

| Field | Value |
|---|---|
| **ID** | O10 |
| **Owner** | `bench/results/gas_measurement.json`, `contracts/test/GasMeasure.t.sol` |
| **Depends on** | O9 |
| **Gate** | phase4-gate |

**RED test** (`contracts/test/GasMeasure.t.sol`): assert `gasleft() delta < GAS_CAP` — fails while verifier is unoptimized.

**GREEN criteria**: gas consumed by `P3RealVerifier.verify(proof, inputs)` is within the cap defined in spec §6.7; measurement written to `bench/results/gas_measurement.json`; `forge test --root contracts --match-test test_gas` exits 0.

---

## 8. Phase 5 — E2E + F1–F4 Review Wave

Gate: phase5-gate (manual user "okay" required for E3..E6)

---

### Task E1 — `just demo-e2e --seed 1` with all real backends

| Field | Value |
|---|---|
| **ID** | E1 |
| **Owner** | `Justfile` (`demo-e2e` recipe), `crates/pvthfhe-cli/src/main.rs` |
| **Depends on** | O10 |
| **Gate** | phase5-gate |

**RED test** (`crates/pvthfhe-cli/tests/e2e_real.rs`): `just demo-e2e --seed 1` with real backends at n=128 — fails while CLI still selects surrogate.

**GREEN criteria**: end-to-end run at n=128 completes; banner in stdout explicitly states "P1 NIZK: conditional soundness only"; `backend_id` logged for P2 (`cyclo-rlwe-t10`) and P3 (`ultra-honk-micronova`); all real backends active; exits 0.

---

### Task E2 — `just bench-scaling` for n=128..1024

| Field | Value |
|---|---|
| **ID** | E2 |
| **Owner** | `bench/results/scaling_*.json`, `Justfile` (`bench-scaling` recipe) |
| **Depends on** | E1 |
| **Gate** | phase5-gate |

**RED test**: `just bench-scaling` exits 2 (stub).

**GREEN criteria**: `just bench-scaling` produces JSON results for n ∈ {128, 256, 512, 1024}; per-party work growth is sub-quadratic (verified by `bench/scripts/fit-loglog.py`); results written to `bench/results/`; exits 0.

---

### Task E3 — F1: Goal & Constraint Verification (oracle-deep)

| Field | Value |
|---|---|
| **ID** | E3 |
| **Owner** | `.sisyphus/evidence/final-qa/f1-oracle-deep.md` |
| **Depends on** | E2 |
| **Gate** | phase5-gate (user "okay" required) |

**RED test**: review report file does not exist — `[ -f .sisyphus/evidence/final-qa/f1-oracle-deep.md ]` fails.

**GREEN criteria**: oracle-deep agent produces ACCEPT/REJECT verdict with rationale; every plan goal has a mapping to a concrete deliverable; report file present; **user must explicitly "okay" before marking `[x]`**.

> ⚠️ Do NOT resume sessions `ses_21081dbb8ffedyBw8xnJLNTozt` or `ses_2107c5809ffeTj9qni39Ko20iF` — use a fresh agent invocation.

---

### Task E4 — F2: Code Quality review (sisyphus-junior unspecified-high)

| Field | Value |
|---|---|
| **ID** | E4 |
| **Owner** | `.sisyphus/evidence/final-qa/f2-code-quality.md` |
| **Depends on** | E2 |
| **Gate** | phase5-gate (user "okay" required) |

**RED test**: report file absent.

**GREEN criteria**: code quality agent reviews all new crates (`pvthfhe-nizk`, `pvthfhe-cyclo`, `pvthfhe-micronova`) and modified files; no unresolved `TODO`/`FIXME` in hot paths; no `unwrap()` in lib code; report present; user "okay" required.

---

### Task E5 — F3: Manual QA (sisyphus-junior unspecified-high; ACCEPT/REJECT)

| Field | Value |
|---|---|
| **ID** | E5 |
| **Owner** | `.sisyphus/evidence/final-qa/f3-manual-qa.md` |
| **Depends on** | E3, E4 |
| **Gate** | phase5-gate (user "okay" required) |

**RED test**: QA report absent.

**GREEN criteria**: QA agent runs every QA scenario from N1..O10 (at minimum one per task); captures evidence; reports ACCEPT or REJECT with specific failures listed; user "okay" required before `[x]`.

---

### Task E6 — F4: Scope Fidelity check (oracle-deep)

| Field | Value |
|---|---|
| **ID** | E6 |
| **Owner** | `.sisyphus/evidence/final-qa/f4-scope-fidelity.md` |
| **Depends on** | E5 |
| **Gate** | phase5-gate (user "okay" required) |

**RED test**: scope report absent.

**GREEN criteria**: oracle-deep agent verifies every diff in git log since plan activation maps to a task in this plan; no scope creep; no missing deliverable; report present; user "okay" required.

> ⚠️ Prior pvt-fhe-scaling F4 oracle (gpt-5.4) was unreliable — use a different model or direct verification. Do NOT resume prior sessions listed under E3.

---

## 9. Administrative Tasks

---

### Task A1 — Fix `paper/bib.bib` line 46 eprint ID

| Field | Value |
|---|---|
| **ID** | A1 |
| **Owner** | `paper/bib.bib` |
| **Depends on** | — |
| **Gate** | phase5-gate |

**RED test**: `grep '2024/1826' paper/bib.bib` returns a match — line is wrong.

**GREEN criteria**: `grep '2024/2099' paper/bib.bib` returns a match; `grep '2024/1826' paper/bib.bib` returns nothing; commit message references L2 discovery.

---

### Task A2 — Pin exact toolchain versions in `REPRODUCING.md`

| Field | Value |
|---|---|
| **ID** | A2 |
| **Owner** | `REPRODUCING.md` |
| **Depends on** | M3 |
| **Gate** | phase5-gate |

**RED test**: `grep 'BB CLI' REPRODUCING.md` returns nothing — section absent (T44 carryover from pvt-fhe-scaling).

**GREEN criteria**: `REPRODUCING.md` pins exact versions for Rust (channel from `rust-toolchain.toml`), Foundry, Noir, and Barretenberg `bb` CLI; SRS hash documented; `Dockerfile.quickstart` installs identical versions.

---

### Task A3 — Update `SECURITY.md` P2/P3 status

| Field | Value |
|---|---|
| **ID** | A3 |
| **Owner** | `SECURITY.md` |
| **Depends on** | F8, O7 |
| **Gate** | phase5-gate |

**RED test**: `grep 'SurrogateAdapter' SECURITY.md` or `grep 'TRUSTED_SIGNER' SECURITY.md` — at least one match (old surrogates still documented as active).

**GREEN criteria**: SECURITY.md reflects real P2 (`CycloAdapter`) and real P3 (`UltraHonkVerifier`); P1 tabled status preserved with conditional-soundness note; P2/P3 "surrogate" warnings removed or marked RESOLVED; no new `#[allow]` markers in doc.

---

## 10. Escape Hatches (spec §9, user-approved policy 3)

If `just phase3-gate` fails, invoke in priority order:

| Priority | Escape | Trigger |
|---|---|---|
| i | RLWE log₂q reduction | R1CS constraint count > 2^21 |
| ii | Cyclo q_commit re-pick | Norm budget overshoot at T=10 |
| iii | Sequential T reduction (T=10 → T=5) | Proving time exceeds wall-time cap |
| iv | Drop QROM stretch goal | Soundness proof too costly |
| v | Fall back to direct MicroNova Solidity verifier (Option A) | Last resort only |

**No silent fallback**: every escape surfaces `backend_id` change + SECURITY.md banner in the same PR.

---

## 11. Gates

| Gate | Command | Passing criteria |
|---|---|---|
| **phase1-gate** | `just phase1-gate` | N1..N8 all GREEN; conditional-soundness banners in API + SECURITY.md |
| **phase2-gate** | `just phase2-gate` | F1..F12 all GREEN; n=1024 aggregation demo complete |
| **phase3-gate** | `just phase3-gate` | M1..M7 GREEN; MicroNova proof verified in Rust |
| **phase4-gate** | `just phase4-gate` | O1..O10 GREEN; gas under cap; `IPvthfheVerifier` ABI preserved |
| **phase5-gate** | user "okay" | E3..E6 ACCEPT verdicts; E1, E2 green; user explicitly approves |

---

## 12. Dependency Summary

```
N1 → N2 → N3 → N4 → N5 → N6 → N7 → N8   (phase1-gate)
         ↘              ↗
          F1 → F2 → F3 → F4 → F5 → F6 → F7 → F8 → F9 → F10 → F11 → F12  (phase2-gate)
                              ↗
                         M1 → M2 → M3 → M4 → M5 → M6 → M7  (phase3-gate)
                                                       ↗
                              O1 → O2 → O3 → O4 → O5 → O6 → O7 → O8 → O9 → O10  (phase4-gate)
                                                                              ↗
                              E1 → E2 → E3/E4 → E5 → E6  (phase5-gate, user okay)
A1, A2 (after M3), A3 (after F8+O7) — parallel admin tasks
```

---

## 13. Acceptance Checklist

- [x] N1: `crates/pvthfhe-nizk` scaffolded; `NizkAdapter` trait defined and object-safe
- [x] N2: Ajtai commitment over R_{q_commit} (φ=256, q_commit≈2^50); binding holds
- [x] N3: D2 SHA-256 hash-bridge golden-vector tested
- [x] N4: Sigma protocol complete/sound for RLWE relation; norm bound enforced
- [x] N5: Fiat-Shamir transcript with locked domain separator (spec §3.6)
- [x] N6: `RealNizkAdapter` in `pvthfhe-fhe` wired to new backend; `backend_id` = `"cyclo-ajtai-d2-conditional"`
- [ ] N7: `NizkError::ConditionalSoundness` variant; rustdoc + README badge + SECURITY.md banner
- [ ] N8: 6+ adversarial NIZK scenarios pass; `just phase1-gate` exits 0
- [ ] F1: `pvthfhe-cyclo` crate created; ring backend locked and documented
- [ ] F2: NTT + norm arithmetic over R_{q_commit} correct on 500 random inputs
- [ ] F3: CCS instance encoding for one share passes satisfiability check
- [ ] F4: T1 range-check sub-protocol rejects all out-of-bound witnesses
- [ ] F5: T2 extension sub-protocol correct on 100 random CCS instances
- [ ] F6: T3 fold sub-protocol produces valid accumulator; tampered accumulator rejected
- [ ] F7: T=10 sequential driver; β_T ≤ 2^10 enforced
- [ ] F8: `SurrogateAdapter` removed; `backend_id` = `"cyclo-rlwe-t10"`; full workspace green
- [ ] F9: n=1024 aggregation within wall-time cap; bench recorded
- [ ] F10: Cyclo Lemma 9 heuristic banner in API + SECURITY.md
- [ ] F11: 500-round norm-explosion fuzz; all explosions rejected
- [ ] F12: `just phase2-gate` exits 0; `phase2-gate.json` present
- [ ] M1: `pvthfhe-micronova` scaffolded; OI-1 resolution documented
- [ ] M2: BN254/Grumpkin cycle wired; round-trip test passes
- [ ] M3: SRS at `bench/srs/bn254.srs`; hash in `REPRODUCING.md`
- [ ] M4: Construction 1 Poseidon↔Keccak bridge; 10 golden-vector tests pass
- [ ] M5: Cyclo accumulator verifier R1CS ≤ 2^21 constraints; satisfiability passes
- [ ] M6: Prove+verify round-trip on 5 honest inputs; forged accumulator rejected
- [ ] M7: `just phase3-gate` exits 0; escape-hatch procedure documented if needed
- [ ] O1: `circuits/micronova_wrap` circuit constrains all 7 public inputs; `nargo test` green
- [ ] O2: `nargo execute` flow produces bytecode + witness; no `nargo prove`
- [ ] O3: `bb write_vk --scheme ultra_honk` produces non-empty VK
- [ ] O4: `bb prove --scheme ultra_honk` produces non-empty proof
- [ ] O5: `bb verify` accepts honest proof; rejects tampered proof; automated in `just verify-onchain`
- [ ] O6: `ecrecover`/`TRUSTED_SIGNER` stripped from `P3RealVerifier.sol`; forge test passes
- [ ] O7: `IPvthfheVerifier.sol` ABI preserved; `check-abi.py` exits 0
- [ ] O8: 3+ happy-path Foundry tests pass
- [ ] O9: 4+ adversarial Foundry tests pass; no reverts on adversarial input
- [ ] O10: Gas under cap; `bench/results/gas_measurement.json` written
- [ ] E1: `just demo-e2e --seed 1` exits 0 at n=128; real backends active; banner displayed
- [ ] E2: `just bench-scaling` produces JSON for n=128..1024; sub-quadratic growth confirmed
- [ ] E3: F1 oracle-deep ACCEPT verdict; user "okay" received *(do not pre-mark)*
- [ ] E4: F2 code-quality ACCEPT verdict; user "okay" received *(do not pre-mark)*
- [ ] E5: F3 manual QA ACCEPT verdict; user "okay" received *(do not pre-mark)*
- [ ] E6: F4 scope-fidelity ACCEPT verdict; user "okay" received *(do not pre-mark)*
- [ ] A1: `paper/bib.bib` line 46 corrected (`2024/1826 → 2024/2099`)
- [ ] A2: `REPRODUCING.md` pins Rust / Foundry / Noir / BB versions + SRS hash
- [ ] A3: `SECURITY.md` P2/P3 status updated; P1 tabled status preserved

---

*Total tasks: 5 (L, Phase 0 ✅) + 8 (N) + 12 (F) + 7 (M) + 10 (O) + 6 (E) + 3 (A) = **51***
