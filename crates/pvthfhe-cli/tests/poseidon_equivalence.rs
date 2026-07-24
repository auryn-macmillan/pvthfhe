//! Behavior-pinning golden tests for the FIVE native Poseidon implementations
//! in this repo (Phase 1.1 of `.omo/plans/repo-refactor-2026-07-24.md`).
//!
//! The five implementations ("A"–"E"):
//!
//! - **A** `pvthfhe-cli/src/noir_poseidon.rs` — Noir-compatible sponge
//!   (`sponge`, a.k.a. `poseidon_sponge_native_noir` / `hash_n`), x5_5
//!   permutation (t=5, RF=8, RP=60), rate=4, capacity=1, absorb at
//!   `state[1+i]`, squeeze `state[1]`, empty input → 0 (no permutation).
//!   Constants parsed from Noir's `poseidon` v0.3.0 `bn254/consts.nr`.
//! - **B1** `pvthfhe-cli/src/full_pipeline.rs::poseidon_sponge_native_noir`
//!   (~line 3291) — a duplicate symbol that *delegates* to
//!   `noir_poseidon::hash_n`, hence identical to A by construction.
//! - **B2** `pvthfhe-cli/src/full_pipeline.rs::poseidon_hash_native`
//!   (~line 3257) — `light_poseidon::Poseidon::<Fr>::new_circom(len).hash(..)`;
//!   single permutation over `[0, inputs..]` with width = len+1 (max 12
//!   inputs, width ≤ 13 = MAX_X5_LEN), output `state[0]`. **Private**; its
//!   only caller sits deep inside the private FHE pipeline, so it is pinned
//!   here through an exact replica of its two-call body against the same
//!   `light-poseidon` 0.4.0 (single version in `Cargo.lock`), and that
//!   replica is in turn proven byte-identical to E through E's public API.
//! - **C** `pvthfhe-compressor/src/witness.rs::poseidon_sponge_hash_native`
//!   (~line 135) — **documented degenerate stub** ("Track A: Nova removed,
//!   local stub"): t=5, rate=4, capacity=1, RF=8, RP=56 (≠ Noir's 60),
//!   all-zero round constants, identity MDS. Its own docs state hash
//!   outputs are NOT compatible with real Poseidon. Same absorb schedule
//!   as A but always applies a final permutation (vacuous given the stub
//!   constants: 0 and identity lanes are fixed points).
//! - **D** `pvthfhe-foundations/src/types/verification_statement.rs` — public sponge
//!   `noir_bn254_sponge` over the private `poseidon_permute` (~line 425),
//!   using `light_poseidon::parameters::bn254_x5::get_poseidon_parameters(5)`
//!   (width 5, RF=8, RP=60 — Grain-LFSR constants), same Noir sponge
//!   schedule as A, squeeze `state[1]`.
//! - **E** `pvthfhe-nizk/src/sigma.rs::poseidon_hash` (~line 775) —
//!   `light_poseidon::Poseidon::<Fr>::new_circom(len).hash(..)`, byte-for-byte
//!   the same construction as B2. **Private**; reached only through the
//!   public `derive_challenge_from_commitment`, which fixes arity 2 and
//!   reduces the Fr output to a ternary challenge. Pinned via that public
//!   API (8 transcript vectors) and cross-checked against the B2 replica.
//!
//! ## How the goldens were produced
//!
//! Expected outputs were generated on 2026-07-24 by running the CURRENT,
//! UNMODIFIED code on branch `refactor/repo-simplify-2026-07-24` via a
//! temporary print harness in this file (since removed) invoked as:
//!
//! ```text
//! cargo test -p pvthfhe-cli --test poseidon_equivalence -- --nocapture
//! ```
//!
//! Two independent pre-existing pins cross-validate the generated values:
//! `noir_poseidon.rs`'s own `#[cfg(test)]` cross-language vectors (verified
//! against Noir's `poseidon::bn254::sponge`, e.g. sponge([1,2]) = 0x2ddd…2c37)
//! and `GOLDEN_STATEMENT_HASH_{DECIMAL,HEX}` in `pvthfhe-foundations::types` (verified
//! against the Noir statement-hash circuit). A and D reproduce both.
//!
//! ## Known-divergence provenance
//!
//! `crates/pvthfhe-compressor/tests/s1_native_noir_hash_divergence.rs`
//! documents the native-vs-Noir commitment divergence; its two cases are
//! reused here as goldens V6 (input `[1,2,3,4]`, with the s1-pinned native
//! Keccak256 digest `0x3927…2d`) and V7 (the golden `VerificationStatementV1`
//! 92-element preimage, pinned against `GOLDEN_STATEMENT_HASH_*`).

// Test-only ergonomics: workspace lints warn on these; tests assert exact
// values and must abort on the first mismatch.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

// ── Golden-vector inputs ────────────────────────────────────────────────────

/// V0: empty input (sponge implementations only; the circom construction
/// rejects arity 0 — see `circom_arity_bounds`).
fn v0_empty() -> Vec<Fr> {
    Vec::new()
}

/// V1: single zero.
fn v1_zero() -> Vec<Fr> {
    vec![Fr::from(0u64)]
}

/// V2: single one.
fn v2_one() -> Vec<Fr> {
    vec![Fr::from(1u64)]
}

/// V3: [1, 2].
fn v3_one_two() -> Vec<Fr> {
    vec![Fr::from(1u64), Fr::from(2u64)]
}

/// V4: typical 5-element vector [1, 2, 3, 4, 5] (crosses the rate=4 block
/// boundary: one full block + one partial block).
fn v4_one_to_five() -> Vec<Fr> {
    (1..=5u64).map(Fr::from).collect()
}

/// V5: max-arity vector [1..=12]. 12 inputs is the maximum the circom
/// construction supports (width 13 = MAX_X5_LEN); also exercises three full
/// rate-4 sponge blocks.
fn v5_max_arity() -> Vec<Fr> {
    (1..=12u64).map(Fr::from).collect()
}

/// V6: known-divergence case #1 from `s1_native_noir_hash_divergence.rs`:
/// the 4-element IVC-state input [1, 2, 3, 4] (exactly one rate-4 block).
fn v6_s1_state() -> Vec<Fr> {
    (1..=4u64).map(Fr::from).collect()
}

/// V7: known-divergence case #2 from `s1_native_noir_hash_divergence.rs`:
/// the 92-element Poseidon preimage of the golden `VerificationStatementV1`
/// (sponge implementations only; far beyond circom max arity 12).
fn v7_golden_statement_preimage() -> Vec<Fr> {
    let fixture = pvthfhe_foundations::types::verification_statement::VerificationStatementV1::golden_fixture()
        .expect("golden fixture must build");
    fixture
        .poseidon_preimage_decimal
        .iter()
        .map(|s| s.parse::<Fr>().expect("golden preimage elements are decimal Fr"))
        .collect()
}

/// All sponge-applicable vectors with their names: (name, input).
fn sponge_vectors() -> Vec<(&'static str, Vec<Fr>)> {
    vec![
        ("V0_empty", v0_empty()),
        ("V1_zero", v1_zero()),
        ("V2_one", v2_one()),
        ("V3_1_2", v3_one_two()),
        ("V4_1_to_5", v4_one_to_five()),
        ("V5_max_arity_12", v5_max_arity()),
        ("V6_s1_1_to_4", v6_s1_state()),
        ("V7_golden_statement_92", v7_golden_statement_preimage()),
    ]
}

/// Circom-applicable vectors (arity 1..=12): V1–V6.
fn circom_vectors() -> Vec<(&'static str, Vec<Fr>)> {
    vec![
        ("V1_zero", v1_zero()),
        ("V2_one", v2_one()),
        ("V3_1_2", v3_one_two()),
        ("V4_1_to_5", v4_one_to_five()),
        ("V5_max_arity_12", v5_max_arity()),
        ("V6_s1_1_to_4", v6_s1_state()),
    ]
}

// ── Pinned expected outputs (32-byte big-endian hex of the Fr digest) ───────

/// Golden outputs of the Noir-compatible sponge (implementations A, B1, D —
/// proven byte-identical by `cross_impl_noir_sponges_byte_identical`).
const GOLDEN_NOIR_SPONGE: [(&str, &str); 8] = [
    ("V0_empty", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("V1_zero", "2875620e99eb8e792ddd736e15a21a653ddc6724a8e6133eea0fa9adfeb75e02"),
    ("V2_one", "0fe896c25d7e32889bdff98e915a5fc35fca904c90d392d10226bc3839ba5e90"),
    ("V3_1_2", "2dddd542213b9228162ff1b438c3709c057a9550103c9173c6204fb29b802c37"),
    ("V4_1_to_5", "046f72048d371ab8c2793248aee7aa80a56a4f990d4d21ca5424509a0d5c85c3"),
    ("V5_max_arity_12", "08cb8d4fda5f3b3746ca195666b96a3f0679cfff549d3091c793a62b59a26e24"),
    ("V6_s1_1_to_4", "1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d"),
    ("V7_golden_statement_92", "00046b39c51423acca3390ca18deddf1a5c98c3b391b53a70fe5d17b205b8abf"),
];

/// Golden outputs of implementation C (compressor witness stub: zero round
/// constants, identity MDS, RP=56 — documented as Poseidon-incompatible).
const GOLDEN_COMPRESSOR_STUB: [(&str, &str); 8] = [
    ("V0_empty", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("V1_zero", "0000000000000000000000000000000000000000000000000000000000000000"),
    ("V2_one", "0000000000000000000000000000000000000000000000000000000000000001"),
    ("V3_1_2", "0000000000000000000000000000000000000000000000000000000000000001"),
    ("V4_1_to_5", "15acd5439cfc7496ac2aee4cac8be4c55ea963fd5b103036fcc4638c1fbadc6d"),
    ("V5_max_arity_12", "0e8d3b2c1f2a776912ead4104f3e7d707db664610f80d21bb69eedf99efefbb5"),
    ("V6_s1_1_to_4", "0000000000000000000000000000000000000000000000000000000000000001"),
    ("V7_golden_statement_92", "1cce017bed7a5f012ae8d4f9d5aac1201c2b39219909de1ea37ae6e3b2dd72a0"),
];

/// Golden outputs of the circom construction shared by B2 and E
/// (`light_poseidon::Poseidon::new_circom(len).hash(..)`, single permutation,
/// output `state[0]`).
const GOLDEN_CIRCOM: [(&str, &str); 6] = [
    ("V1_zero", "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c"),
    ("V2_one", "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133"),
    ("V3_1_2", "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"),
    ("V4_1_to_5", "0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0"),
    ("V5_max_arity_12", "058814945232937db248a01e7cc55b3d681cc08702c8168494e856c1ef7693b5"),
    ("V6_s1_1_to_4", "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"),
];

/// Golden transcript vectors for implementation E (nizk `sigma.rs`
/// `poseidon_hash`), reached through the public
/// `pvthfhe_nizk::derive_challenge_from_commitment`. Each entry pins the
/// SHA-256-derived Poseidon input pair `[lo, hi]`, the circom hash `ch_fr`
/// of that pair (an additional B2-construction golden), and the final
/// ternary challenge returned by the public API.
const GOLDEN_NIZK_TRANSCRIPTS: [(&str, &str, &str, i64); 8] = [
    (
        "0000000000000000000000000000000073054746e673015c7cf6121bd7601e99",
        "00000000000000000000000000000000f12bafc7251a264615e854a24902b7fa",
        "1fed1d5cc8a4190f2a1ef560379fe07c0179a07f0ca7546b5f0f262d059979fa",
        1,
    ),
    (
        "000000000000000000000000000000003e2ce82c5e7a1829590d9ff8dd944058",
        "0000000000000000000000000000000065b4948f48a4298be0c189c4003efca4",
        "29fdb5d0401a7859047cdade30cedf9ea54ea04667311b3587547535ccc8de9e",
        0,
    ),
    (
        "00000000000000000000000000000000b3049fb7eeb95761f2fa4a98fa8384e9",
        "000000000000000000000000000000002824e1b8e69601d10c8c742ec26650f2",
        "2b086f3763e9dbc12e47492e9492050c2180972df06fc0b3a009517a13ab8a39",
        -1,
    ),
    (
        "0000000000000000000000000000000012b1b4c11d6bd7c193a614b935571787",
        "00000000000000000000000000000000ce2a2b75f95096026ab78c1e042af30d",
        "1dd766ba967986fee0b4a5538a12219003db666e6c1ef32568e5177ee205da0a",
        -1,
    ),
    (
        "00000000000000000000000000000000fcce93c2b03e40a868b54bb20800c4f4",
        "00000000000000000000000000000000c49942d516576b61ef1df1717fff56f8",
        "1527b141ed2b2a14a050b87ee1359f2f6bcbb8fa853071ee36e068648f06fa8d",
        0,
    ),
    (
        "00000000000000000000000000000000969d0ea8096bf34cd689162836775d1d",
        "00000000000000000000000000000000219fe68c92f89839dab606c8ec504171",
        "0aacba7e71d405a8cc882160d294f9b1948ceadc38e8f7b8d5d8644ab9aa7f3c",
        -1,
    ),
    (
        "00000000000000000000000000000000ea1d158b2c7af8d6267921f9a172997e",
        "000000000000000000000000000000006738806e510a085559d832932b418028",
        "0c2e488579ee3bee5fd2166307f0800a7145ef19663344365633e1f10f61118a",
        0,
    ),
    (
        "00000000000000000000000000000000e4a7934733f59497d721d9c82d5d0819",
        "00000000000000000000000000000000c5aa09f1d41017a9d27ac576225f2eb8",
        "2ce21509df67d23b69914ca79ba7fba7c7b7cf0cc31d06afbf4ca1ca6f585f8e",
        0,
    ),
];

/// s1-pinned native IVC state hash: Keccak256 over the big-endian bytes of
/// [1, 2, 3, 4], copied from `s1_native_noir_hash_divergence.rs`
/// (`s1_native_hash_regression`). Every Poseidon implementation here must
/// NOT reproduce it — that is the documented native-vs-Noir divergence.
const S1_NATIVE_KECCAK_OF_1_2_3_4: [u8; 32] = [
    0x39, 0x27, 0x91, 0xdf, 0x62, 0x64, 0x08, 0x01, 0x7a, 0x26, 0x4f, 0x53, 0xfd, 0xe6, 0x10, 0x65,
    0xd5, 0xa9, 0x3a, 0x32, 0xb6, 0x01, 0x71, 0xdf, 0x9d, 0x8a, 0x46, 0xaf, 0xdf, 0x82, 0x99, 0x2d,
];

// ── Helpers ─────────────────────────────────────────────────────────────────

fn fr_from_hex(s: &str) -> Fr {
    let bytes = hex::decode(s).expect("golden constants are valid hex");
    assert_eq!(bytes.len(), 32, "golden constants are 32-byte digests");
    Fr::from_be_bytes_mod_order(&bytes)
}

fn fr_hex(value: &Fr) -> String {
    hex::encode(value.into_bigint().to_bytes_be())
}

/// Exact replica of `full_pipeline.rs::poseidon_hash_native` (B2) — the
/// function is private and its sole caller is buried in the private FHE
/// pipeline, so it cannot be invoked from an integration test. The body is
/// verbatim the same two `light-poseidon` calls; the replica is proven to
/// match implementation E's public behavior in
/// `golden_nizk_sigma_derive_challenge_from_commitment`.
fn circom_hash_b2_replica(inputs: &[Fr]) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .expect("Noir aggregator_final Poseidon arity is within Circom parameter range");
    hasher
        .hash(inputs)
        .expect("Noir aggregator_final Poseidon input arity matches construction")
}

/// (commitment, session_id, participant_id, round_index, d_commitment).
type TranscriptTuple = ([u8; 32], String, u32, usize, [u8; 32]);

/// The 8 fixed transcript tuples fed to `derive_challenge_from_commitment`.
fn nizk_transcript_tuples() -> Vec<TranscriptTuple> {
    (0..8u8)
        .map(|i| {
            let mut commitment = [0u8; 32];
            let mut d_commitment = [0u8; 32];
            for (j, (c, d)) in commitment.iter_mut().zip(d_commitment.iter_mut()).enumerate() {
                *c = i.wrapping_mul(17).wrapping_add(j as u8);
                *d = i.wrapping_mul(31).wrapping_add(j as u8).wrapping_add(7);
            }
            (
                commitment,
                format!("poseidon-equivalence-session-{i}"),
                u32::from(i) + 1,
                usize::from(i),
                d_commitment,
            )
        })
        .collect()
}

/// Replica of the transcript pre-processing inside
/// `pvthfhe-nizk/src/sigma.rs::derive_challenge_from_commitment`
/// (domain tag || "t2-commit-ch" || session || participant || round ||
/// d_commitment, then labeled "commitment" digest split into two 16-byte
/// little-endian Fr limbs). Returns `(lo, hi, ch_fr, ternary)` where
/// `ch_fr = poseidon_hash([lo, hi])` and `ternary` applies the crate's
/// `uniform_ternary` byte rejection over the LE encoding of `ch_fr`.
fn nizk_challenge_replica(
    commitment: &[u8; 32],
    session_id: &[u8],
    participant_id: u32,
    round_index: usize,
    d_commitment: &[u8; 32],
) -> (Fr, Fr, Fr, i64) {
    let domain = pvthfhe_foundations::domain_tags::Tag::SigmaScalarChallenge.as_bytes();
    let mut prefix = Sha256::new();
    prefix.update(domain);
    prefix.update(b"t2-commit-ch");
    prefix.update(session_id);
    prefix.update(participant_id.to_le_bytes());
    prefix.update((round_index as u64).to_le_bytes());
    prefix.update(d_commitment);

    // labeled_sha256(&prefix, b"commitment", commitment)
    let mut h = prefix;
    h.update(b"commitment");
    h.update(commitment);
    let digest: [u8; 32] = h.finalize().into();

    // bytes16_to_fr: 16 digest bytes placed in the low half of a zeroed
    // 32-byte LE buffer (always < 2^128 << |Fr|, so no reduction).
    let mut lo_buf = [0u8; 32];
    lo_buf[..16].copy_from_slice(&digest[..16]);
    let mut hi_buf = [0u8; 32];
    hi_buf[..16].copy_from_slice(&digest[16..]);
    let lo = Fr::from_le_bytes_mod_order(&lo_buf);
    let hi = Fr::from_le_bytes_mod_order(&hi_buf);

    let ch_fr = circom_hash_b2_replica(&[lo, hi]);

    // fr_to_bytes + uniform_ternary rejection loop from sigma.rs.
    let le = ch_fr.into_bigint().to_bytes_le();
    let mut bytes = [0u8; 32];
    let n = le.len().min(32);
    bytes[..n].copy_from_slice(&le[..n]);
    let mut challenge = 0i64; // fallback: all bytes ≥ 252
    for &byte in &bytes {
        if byte < 252 {
            challenge = match byte / 84 {
                0 => -1,
                1 => 0,
                _ => 1,
            };
            break;
        }
    }
    (lo, hi, ch_fr, challenge)
}

// ── Golden tests: one per implementation ────────────────────────────────────

/// A: `pvthfhe-cli/src/noir_poseidon.rs` sponge (8 vectors).
#[test]
fn golden_noir_sponge_cli_noir_poseidon() {
    for (name, input) in sponge_vectors() {
        let expected = GOLDEN_NOIR_SPONGE
            .iter()
            .find(|(n, _)| *n == name)
            .expect("every vector has a golden entry")
            .1;
        let actual = pvthfhe_cli::noir_poseidon::sponge(&input);
        assert_eq!(
            actual,
            fr_from_hex(expected),
            "A (cli/noir_poseidon::sponge) diverged on {name}: got 0x{}",
            fr_hex(&actual),
        );
    }
}

/// B1: `pvthfhe-cli/src/full_pipeline.rs::poseidon_sponge_native_noir`
/// duplicate (8 vectors, same table as A).
#[test]
fn golden_noir_sponge_cli_full_pipeline_duplicate() {
    for (name, input) in sponge_vectors() {
        let expected = GOLDEN_NOIR_SPONGE
            .iter()
            .find(|(n, _)| *n == name)
            .expect("every vector has a golden entry")
            .1;
        let actual = pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir(&input);
        assert_eq!(
            actual,
            fr_from_hex(expected),
            "B1 (full_pipeline::poseidon_sponge_native_noir) diverged on {name}: got 0x{}",
            fr_hex(&actual),
        );
    }
}

/// C: `pvthfhe-compressor/src/witness.rs::poseidon_sponge_hash_native`
/// stub (8 vectors, its own table — documented Poseidon-incompatible).
#[test]
fn golden_compressor_witness_stub_vectors() {
    for (name, input) in sponge_vectors() {
        let expected = GOLDEN_COMPRESSOR_STUB
            .iter()
            .find(|(n, _)| *n == name)
            .expect("every vector has a golden entry")
            .1;
        let actual = pvthfhe_compressor::witness::poseidon_sponge_hash_native(&input);
        assert_eq!(
            actual,
            fr_from_hex(expected),
            "C (compressor witness stub) diverged on {name}: got 0x{}",
            fr_hex(&actual),
        );
    }
}

/// D: `pvthfhe-foundations/src/types/verification_statement.rs` private `poseidon_permute`
/// via the public `noir_bn254_sponge` (8 vectors, same table as A).
#[test]
fn golden_noir_sponge_types_verification_statement() {
    for (name, input) in sponge_vectors() {
        let expected = GOLDEN_NOIR_SPONGE
            .iter()
            .find(|(n, _)| *n == name)
            .expect("every vector has a golden entry")
            .1;
        let actual = pvthfhe_foundations::types::verification_statement::noir_bn254_sponge(&input)
            .expect("D sponge never fails for valid Fr slices");
        assert_eq!(
            actual,
            fr_from_hex(expected),
            "D (types noir_bn254_sponge) diverged on {name}: got 0x{}",
            fr_hex(&actual),
        );
    }
}

/// B2: `pvthfhe-cli/src/full_pipeline.rs::poseidon_hash_native` via the
/// exact replica (6 direct vectors) plus the 8 transcript-derived input
/// pairs from the nizk table (14 circom-construction goldens total).
#[test]
fn golden_circom_full_pipeline_poseidon_hash_native() {
    for (name, input) in circom_vectors() {
        let expected = GOLDEN_CIRCOM
            .iter()
            .find(|(n, _)| *n == name)
            .expect("every vector has a golden entry")
            .1;
        let actual = circom_hash_b2_replica(&input);
        assert_eq!(
            actual,
            fr_from_hex(expected),
            "B2 (full_pipeline poseidon_hash_native replica) diverged on {name}: got 0x{}",
            fr_hex(&actual),
        );
    }
    for (i, (lo_hex, hi_hex, chfr_hex, _)) in GOLDEN_NIZK_TRANSCRIPTS.iter().enumerate() {
        let lo = fr_from_hex(lo_hex);
        let hi = fr_from_hex(hi_hex);
        let actual = circom_hash_b2_replica(&[lo, hi]);
        assert_eq!(
            actual,
            fr_from_hex(chfr_hex),
            "B2 circom construction diverged on nizk transcript pair {i}: got 0x{}",
            fr_hex(&actual),
        );
    }
}

/// E: `pvthfhe-nizk/src/sigma.rs::poseidon_hash` through the public
/// `derive_challenge_from_commitment` (8 transcript vectors), cross-checked
/// limb-by-limb against the B2 replica.
#[test]
fn golden_nizk_sigma_derive_challenge_from_commitment() {
    for (i, (commitment, session_id, participant_id, round_index, d_commitment)) in
        nizk_transcript_tuples().into_iter().enumerate()
    {
        let (lo_hex, hi_hex, chfr_hex, ternary) = GOLDEN_NIZK_TRANSCRIPTS[i];

        // Pin the full public behavior of E.
        let real = pvthfhe_nizk::derive_challenge_from_commitment(
            &commitment,
            session_id.as_bytes(),
            participant_id,
            round_index,
            &d_commitment,
        )
        .expect("E public challenge derivation must succeed");
        assert_eq!(
            real, ternary,
            "E (nizk poseidon_hash via derive_challenge_from_commitment) \
             changed on transcript {i}"
        );

        // Pin the derived Poseidon input pair and cross-check E against the
        // B2 construction: the replica's ternary reduction of the B2 circom
        // hash must equal the real API output.
        let (lo, hi, ch_fr, replica_ternary) = nizk_challenge_replica(
            &commitment,
            session_id.as_bytes(),
            participant_id,
            round_index,
            &d_commitment,
        );
        assert_eq!(lo, fr_from_hex(lo_hex), "E transcript {i} lo limb changed");
        assert_eq!(hi, fr_from_hex(hi_hex), "E transcript {i} hi limb changed");
        assert_eq!(
            ch_fr,
            fr_from_hex(chfr_hex),
            "E transcript {i} circom hash changed"
        );
        assert_eq!(
            real, replica_ternary,
            "E and the B2 circom construction disagree on transcript {i}"
        );
    }
}

// ── Cross-implementation equality ───────────────────────────────────────────

/// A ≡ B1 ≡ D: the three Noir-compatible sponges are byte-identical on all
/// 8 vectors. This is the equivalence Phase 3 relies on to consolidate them.
#[test]
fn cross_impl_noir_sponges_byte_identical() {
    for (name, input) in sponge_vectors() {
        let a = pvthfhe_cli::noir_poseidon::sponge(&input);
        let b1 = pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir(&input);
        let d = pvthfhe_foundations::types::verification_statement::noir_bn254_sponge(&input)
            .expect("D sponge never fails");
        assert_eq!(a, b1, "A != B1 on {name}");
        assert_eq!(a, d, "A != D on {name}");
    }
}

/// B2 ≡ E: both are `light_poseidon::Poseidon::new_circom(len).hash(..)`
/// over the same crate version (single light-poseidon 0.4.0 in Cargo.lock).
/// Proven behaviorally: for every circom-legal input the replica matches
/// the pinned table, and for all 8 nizk transcripts the replica's hash,
/// reduced through sigma.rs's own ternary rule, equals E's public output
/// (asserted in `golden_nizk_sigma_derive_challenge_from_commitment`).
#[test]
fn cross_impl_circom_construction_identical_between_full_pipeline_and_nizk() {
    for (commitment, session_id, participant_id, round_index, d_commitment) in
        nizk_transcript_tuples()
    {
        let (_, _, ch_fr, replica_ternary) = nizk_challenge_replica(
            &commitment,
            session_id.as_bytes(),
            participant_id,
            round_index,
            &d_commitment,
        );
        let real = pvthfhe_nizk::derive_challenge_from_commitment(
            &commitment,
            session_id.as_bytes(),
            participant_id,
            round_index,
            &d_commitment,
        )
        .expect("E public challenge derivation must succeed");
        assert_eq!(
            real, replica_ternary,
            "B2 circom construction (via ch_fr 0x{}) != E public output",
            fr_hex(&ch_fr),
        );
    }
}

// ── Documented divergences (report outcomes — NOT bugs to fix) ──────────────

/// s1 known divergence, case #1: the native IVC state commitment is
/// Keccak256 over BE bytes; no native Poseidon implementation may reproduce
/// it for the same logical input [1,2,3,4].
#[test]
fn divergence_s1_native_keccak_vs_all_poseidon() {
    let input = v6_s1_state();
    let keccak_fr = Fr::from_be_bytes_mod_order(&S1_NATIVE_KECCAK_OF_1_2_3_4);

    let a = pvthfhe_cli::noir_poseidon::sponge(&input);
    let b1 = pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir(&input);
    let c = pvthfhe_compressor::witness::poseidon_sponge_hash_native(&input);
    let d = pvthfhe_foundations::types::verification_statement::noir_bn254_sponge(&input).expect("D sponge");
    let b2 = circom_hash_b2_replica(&input);

    for (label, value) in [("A", a), ("B1", b1), ("C", c), ("D", d), ("B2", b2)] {
        assert_ne!(
            value, keccak_fr,
            "{label} must not equal the s1 native Keccak commitment (documented divergence)"
        );
    }
    // The Noir side of the s1 divergence: A and D agree with each other…
    assert_eq!(a, d, "Noir-side implementations must agree on the s1 vector");
    // …and D on the s1 statement preimage reproduces the cross-language
    // golden pinned in pvthfhe-foundations::types (s1 case #2).
    let d_stmt = pvthfhe_foundations::types::verification_statement::noir_bn254_sponge(
        &v7_golden_statement_preimage(),
    )
    .expect("D sponge");
    assert_eq!(
        d_stmt.into_bigint().to_string(),
        pvthfhe_foundations::types::verification_statement::GOLDEN_STATEMENT_HASH_DECIMAL,
        "D must reproduce GOLDEN_STATEMENT_HASH_DECIMAL on the s1 golden statement"
    );
}

/// C is a documented stub (zero ARK, identity MDS, RP=56): it diverges from
/// the real Noir sponge on every non-trivial vector. (On the empty input
/// both return 0 — A because it never permutes, C because its degenerate
/// permutation fixes the zero state. The agreement is accidental, not
/// compatibility.)
#[test]
fn divergence_compressor_stub_vs_noir_sponge() {
    for (name, input) in sponge_vectors() {
        let a = pvthfhe_cli::noir_poseidon::sponge(&input);
        let c = pvthfhe_compressor::witness::poseidon_sponge_hash_native(&input);
        if name == "V0_empty" {
            assert_eq!(a, c, "empty input is 0 in both (accidental agreement)");
        } else {
            assert_ne!(
                a, c,
                "C (stub) must differ from A (Noir sponge) on {name} — documented divergence"
            );
        }
    }
}

/// B2/E use the circom single-permutation construction (width = len+1,
/// output `state[0]`), which differs from the Noir rate-4 sponge (width 5,
/// output `state[1]`) on every vector.
#[test]
fn divergence_circom_vs_noir_sponge() {
    for (name, input) in circom_vectors() {
        let a = pvthfhe_cli::noir_poseidon::sponge(&input);
        let b2 = circom_hash_b2_replica(&input);
        assert_ne!(
            a, b2,
            "B2 (circom) must differ from A (Noir sponge) on {name} — different constructions"
        );
    }
    // Related-but-distinct: the circom construction equals Noir's
    // *fixed-arity* `bn254::hash_2` (x5_3, state=[0, l, r], output state[0]),
    // which `noir_poseidon::hash_2` also implements — sanity-check that the
    // two libraries' width-3 Grain constants agree.
    let l = Fr::from(1u64);
    let r = Fr::from(2u64);
    assert_eq!(
        pvthfhe_cli::noir_poseidon::hash_2(l, r),
        circom_hash_b2_replica(&[l, r]),
        "circom arity-2 hash and Noir bn254::hash_2 share the x5_3 construction"
    );
}

/// The circom construction's arity bounds: 1..=12 inputs (width 2..=13).
/// Empty input and the 92-element statement preimage are outside its domain
/// — an API-surface difference from the sponges, pinned here.
#[test]
fn circom_arity_bounds() {
    assert!(
        Poseidon::<Fr>::new_circom(0).is_err(),
        "circom construction rejects empty input (width 1)"
    );
    assert!(
        Poseidon::<Fr>::new_circom(12).is_ok(),
        "circom construction accepts 12 inputs (width 13 = MAX_X5_LEN)"
    );
    assert!(
        Poseidon::<Fr>::new_circom(13).is_err(),
        "circom construction rejects 13 inputs (width 14 > MAX_X5_LEN)"
    );
    assert!(
        Poseidon::<Fr>::new_circom(92).is_err(),
        "circom construction rejects the 92-element statement preimage"
    );
}
