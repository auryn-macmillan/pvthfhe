//! Behavior-pinning equivalence tests for the duplicated lattice primitives.
//!
//! Phase 1 of `.omo/plans/repo-refactor-2026-07-24.md`: pin the CURRENT
//! behavior of
//!   (a) the three Ajtai commitment implementations
//!       (`pvthfhe-nizk::ajtai`, `pvthfhe-cyclo::ajtai`,
//!        `pvthfhe-aggregator::folding::ajtai`),
//!   (b) the two Fiat-Shamir transcript modules
//!       (`pvthfhe-nizk::fiat_shamir`, `pvthfhe-cyclo::fiat_shamir`),
//!   (c) the norm/range-check and ring helpers duplicated between the
//!       aggregator (`folding::norm`, `folding::ring_element`) and cyclo
//!       (`range_check`, `ring`),
//! so that a later consolidation can be proven behavior-preserving.
//!
//! # Vector provenance
//!
//! Every frozen constant below was produced by running the CURRENT,
//! UNMODIFIED implementations once (branch `refactor/repo-simplify-2026-07-24`)
//! via a temporary dump test and pasting the printed output here. No
//! implementation file was modified. Constants are labelled `PINNED_*`.
//!
//! # Visibility notes
//!
//! - `pvthfhe_nizk::ajtai::Rq.coeffs` and `AjtaiCommitment.elems` are
//!   `pub(crate)`: nizk commitments are pinned through the public
//!   `to_d2_digest()` and cross-checked against cyclo by recomputing the same
//!   documented digest from cyclo's public coefficients.
//! - `pvthfhe_cyclo::fiat_shamir::uniform_ternary` is `pub(crate)`: its
//!   semantics are pinned through `CycloTernaryTranscript::sample_challenge`
//!   plus an independent replay of the documented rejection-sampling rule.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use ark_bn254::Fr;
use ark_ff::fields::{Fp64, MontBackend};
use ark_ff::PrimeField;
use pvthfhe_aggregator::folding::ajtai::AjtaiMatrix as FieldAjtaiMatrix;
use pvthfhe_aggregator::folding::norm::{enforce_norm_inf, validate_folding_witness};
use pvthfhe_aggregator::folding::ring_element::RingElement;
use pvthfhe_cyclo::ajtai::{
    commit as cyclo_ajtai_commit, decode_commitment, encode_commitment,
    verify as cyclo_ajtai_verify, AjtaiParams as CycloAjtaiParams,
};
use pvthfhe_cyclo::fiat_shamir as cyclo_fs;
use pvthfhe_cyclo::range_check::check_range;
use pvthfhe_cyclo::ring::{
    bytes_to_rqpoly, centred, norm_inf as cyclo_norm_inf, norm_sq, ntt_mul, ring_add_poly,
    rqpoly_to_bytes, scalar_mul, ternary_mul, RqPoly, PHI_COMMIT, Q_COMMIT as CYCLO_Q,
};
use pvthfhe_cyclo::CycloError;
use pvthfhe_nizk::ajtai::{
    AjtaiCommitment as NizkAjtaiCommitment, AjtaiMatrix as NizkAjtaiMatrix,
    AjtaiParams as NizkAjtaiParams, Rq, AJTAI_RANK, PHI as NIZK_PHI, Q_COMMIT as NIZK_Q,
    WITNESS_BOUND,
};
use pvthfhe_nizk::fiat_shamir::{Transcript as NizkTranscript, DOMAIN_SEP_PREFIX};
use pvthfhe_nizk::NizkError;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

// ────────────────────────────────────────────────────────────────────────────
// Shared domain: F_q_commit as an ark-ff prime field.
//
// The aggregator's `RingElement<F>` is generic over any `ark_ff::PrimeField`,
// while cyclo's `RqPoly` is fixed to `Z_{q_commit}[X]/(X^256+1)`. Instantiating
// `RingElement` over this field puts both on their shared domain so add / mul /
// norm can be compared coefficient-by-coefficient. The generator value is
// unused by every operation exercised here (no FFT/root-of-unity calls).
// ────────────────────────────────────────────────────────────────────────────

#[derive(ark_ff::fields::ark_ff_macros::MontConfig)]
#[modulus = "562949953438721"]
#[generator = "5"]
pub struct FqCommitConfig;
pub type FqCommit = Fp64<MontBackend<FqCommitConfig, 1>>;

fn fq(v: u64) -> FqCommit {
    FqCommit::from(v)
}

fn fq_to_u64(v: &FqCommit) -> u64 {
    v.into_bigint().0[0]
}

fn ring_elem_from_residues(res: &[u64]) -> RingElement<FqCommit> {
    RingElement {
        coeffs: res.iter().map(|&v| fq(v)).collect(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fixed inputs (deterministic; no RNG at assertion time).
// ────────────────────────────────────────────────────────────────────────────

/// Seed shared by the nizk and cyclo Ajtai matrix derivations (both use
/// `ChaCha20Rng::from_seed(seed)` and consume `next_u64() % q` per
/// coefficient, row-major, 256 coefficients per entry).
const SEED_A: [u8; 32] = [0x42; 32];
/// Witness width for the nizk/cyclo Ajtai cross-check (`nizk m` == `cyclo n`).
const WITNESS_M: usize = 3;
/// Commitment rank (`nizk rank` == `cyclo m`).
const RANK: usize = 13;

/// Three centred witness polynomials with ‖·‖∞ ≤ 1024 (the nizk bound).
fn fixed_witness_centred() -> Vec<[i64; NIZK_PHI]> {
    let mut w0 = [0i64; NIZK_PHI];
    let mut w1 = [0i64; NIZK_PHI];
    let mut w2 = [0i64; NIZK_PHI];
    for i in 0..NIZK_PHI {
        w0[i] = ((i * 7 + 1) % 5) as i64 - 2;
        w1[i] = ((i * 11 + 3) % 3) as i64 - 1;
        w2[i] = if i % 64 == 0 { 1024 } else { -1024 };
    }
    vec![w0, w1, w2]
}

/// Deterministic full-range residue polynomials (span both halves of
/// `[0, q_commit)` to exercise centred representations).
fn poly_a_residues() -> Vec<u64> {
    (0..PHI_COMMIT)
        .map(|i| ((i as u64 + 1).wrapping_mul(2_179_869_774_371)) % CYCLO_Q)
        .collect()
}

fn poly_b_residues() -> Vec<u64> {
    (0..PHI_COMMIT)
        .map(|i| ((i as u64 + 3).wrapping_mul(1_234_567_890_123)) % CYCLO_Q)
        .collect()
}

/// Mixed-value polynomial for norm checks: exercises 0, ±1, ±1024, the exact
/// `(q±1)/2` centredness boundary, and a dominating boundary coefficient.
fn norm_poly_residues() -> Vec<u64> {
    let mut v = vec![0u64; PHI_COMMIT];
    v[0] = 0;
    v[1] = 1;
    v[2] = CYCLO_Q - 1; // centred −1
    v[3] = (CYCLO_Q - 1) / 2; // boundary: centred == (q−1)/2
    v[4] = CYCLO_Q.div_ceil(2); // boundary: centred == (q−1)/2
    v[5] = CYCLO_Q - 1024; // centred −1024
    v[6] = 2048;
    v
}

// ────────────────────────────────────────────────────────────────────────────
// Representation bridges between nizk (centred i64) and cyclo (residue u64).
// ────────────────────────────────────────────────────────────────────────────

/// cyclo residue `c ∈ [0, q)` → nizk centred representative `(-q/2, q/2]`.
fn residue_to_centred(c: u64) -> i64 {
    if c > CYCLO_Q / 2 {
        (c as i128 - CYCLO_Q as i128) as i64
    } else {
        c as i64
    }
}

/// nizk centred representative → cyclo residue `c ∈ [0, q)`.
fn centred_to_residue(c: i64) -> u64 {
    if c < 0 {
        (CYCLO_Q as i128 + c as i128) as u64
    } else {
        c as u64
    }
}

/// Re-implementation of `NizkAjtaiCommitment::to_d2_digest` from cyclo-side
/// residues: SHA-256 over the label followed by centred i64 LE coefficients.
fn d2_digest_of_residues(elems: &[Vec<u64>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-ajtai-d2-commitment-v1");
    for e in elems {
        for &c in e {
            h.update(residue_to_centred(c).to_le_bytes());
        }
    }
    h.finalize().into()
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

// ────────────────────────────────────────────────────────────────────────────
// Independent re-derivations of the transcript constructions. These pin the
// *construction* (not only frozen outputs) by replaying the documented wire
// formats directly on `sha2`.
// ────────────────────────────────────────────────────────────────────────────

/// Replays the nizk transcript: domain separator, length-prefixed absorbs,
/// then one challenge squeeze.
fn nizk_challenge_rederived(
    session_id: &[u8],
    participant_id: u32,
    absorbs: &[(&[u8], &[u8])],
    challenge_label: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut h = nizk_raw_hasher(session_id, participant_id);
    for (label, data) in absorbs {
        nizk_raw_absorb(&mut h, label, data);
    }
    nizk_raw_challenge(&mut h, challenge_label, out_len)
}

fn nizk_raw_hasher(session_id: &[u8], participant_id: u32) -> Sha256 {
    let domain = format!(
        "pvthfhe/cyclo-ajtai-d2/v1/{}/{}",
        hex::encode(session_id),
        participant_id
    );
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h
}

fn nizk_raw_absorb(h: &mut Sha256, label: &[u8], data: &[u8]) {
    h.update((label.len() as u64).to_be_bytes());
    h.update(label);
    h.update((data.len() as u64).to_be_bytes());
    h.update(data);
}

/// Mirrors `Transcript::challenge_bytes`: absorbs the challenge label into the
/// running state, then squeezes `SHA256(label ‖ u64_be(counter) ‖ state)`.
fn nizk_raw_challenge(h: &mut Sha256, challenge_label: &[u8], out_len: usize) -> Vec<u8> {
    h.update((challenge_label.len() as u64).to_be_bytes());
    h.update(challenge_label);
    let state: [u8; 32] = h.clone().finalize().into();
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0u64;
    while out.len() < out_len {
        let mut b = Sha256::new();
        b.update(challenge_label);
        b.update(counter.to_be_bytes());
        b.update(state);
        let block: [u8; 32] = b.finalize().into();
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }
    out
}

/// Independent replay of the cyclo ternary rejection-sampling rule
/// (`uniform_ternary` is `pub(crate)`; this pins its documented semantics).
fn ternary_rederived(byte: u8) -> Option<i8> {
    if byte >= 252 {
        return None;
    }
    Some(match byte / 84 {
        0 => -1,
        1 => 0,
        _ => 1,
    })
}

fn cyclo_raw_absorb(h: &mut Sha256, label: &[u8], data: &[u8]) {
    h.update((label.len() as u64).to_be_bytes());
    h.update(label);
    h.update((data.len() as u64).to_be_bytes());
    h.update(data);
}

fn cyclo_raw_sample(state: &mut Sha256) -> i8 {
    let hash: [u8; 32] = state.clone().finalize().into();
    state.update(hash);
    for &byte in &hash {
        if let Some(ch) = ternary_rederived(byte) {
            return ch;
        }
    }
    0
}

/// Replays `CycloTernaryTranscript::new("session-alpha", 5)` with the same
/// absorb script used in the pinned test.
fn cyclo_ternary_sequence_rederived() -> (Vec<i8>, Vec<i8>) {
    let mut state = Sha256::new();
    state.update(b"pvthfhe-cyclo-fs-v2");
    state.update(b"session-alpha");
    state.update(5u16.to_le_bytes());
    cyclo_raw_absorb(&mut state, b"commit", &[1, 2, 3]);
    cyclo_raw_absorb(&mut state, b"empty", &[]);
    let seq1: Vec<i8> = (0..8).map(|_| cyclo_raw_sample(&mut state)).collect();
    cyclo_raw_absorb(&mut state, b"more", &[9, 9]);
    let seq2: Vec<i8> = (0..4).map(|_| cyclo_raw_sample(&mut state)).collect();
    (seq1, seq2)
}

// ────────────────────────────────────────────────────────────────────────────
// Shared Ajtai fixtures.
// ────────────────────────────────────────────────────────────────────────────

fn nizk_rq(centred: &[i64; NIZK_PHI]) -> Rq {
    Rq::new(*centred, NIZK_Q)
}

fn cyclo_rq_from_centred(centred: &[i64; NIZK_PHI]) -> RqPoly {
    RqPoly(centred.iter().map(|&c| centred_to_residue(c)).collect())
}

fn nizk_params_and_matrix() -> (NizkAjtaiParams, NizkAjtaiMatrix) {
    let params = NizkAjtaiParams::default();
    let matrix = NizkAjtaiMatrix::from_seed(SEED_A, &params, WITNESS_M)
        .expect("nizk matrix from seed");
    (params, matrix)
}

fn nizk_commit_fixed_witness() -> NizkAjtaiCommitment {
    let (_params, matrix) = nizk_params_and_matrix();
    let witness: Vec<Rq> = fixed_witness_centred().iter().map(nizk_rq).collect();
    NizkAjtaiCommitment::commit(&matrix, &witness).expect("nizk commit")
}

fn cyclo_params() -> CycloAjtaiParams {
    CycloAjtaiParams {
        m: RANK,
        n: WITNESS_M,
        q_commit: CYCLO_Q,
        seed: SEED_A,
    }
}

fn cyclo_commit_witness(witness: Vec<RqPoly>) -> pvthfhe_cyclo::ajtai::AjtaiCommitment {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]); // ignored by the impl
    cyclo_ajtai_commit(&cyclo_params(), &witness, &mut rng).expect("cyclo commit")
}

fn cyclo_commit_fixed_witness() -> pvthfhe_cyclo::ajtai::AjtaiCommitment {
    let witness: Vec<RqPoly> = fixed_witness_centred()
        .iter()
        .map(cyclo_rq_from_centred)
        .collect();
    cyclo_commit_witness(witness)
}

/// Unit-vector witness probing matrix column `j` (ring element 1 at slot j,
/// zero elsewhere). Recovers `A[·][j]` on both implementations.
fn column_probe_nizk(j: usize) -> [u8; 32] {
    let (_params, matrix) = nizk_params_and_matrix();
    let mut witness = vec![[0i64; NIZK_PHI]; WITNESS_M];
    witness[j][0] = 1;
    let witness: Vec<Rq> = witness.iter().map(nizk_rq).collect();
    NizkAjtaiCommitment::commit(&matrix, &witness)
        .expect("nizk probe commit")
        .to_d2_digest()
}

fn column_probe_cyclo(j: usize) -> Vec<Vec<u64>> {
    let mut witness = vec![RqPoly::zero(); WITNESS_M];
    let mut one = vec![0u64; PHI_COMMIT];
    one[0] = 1;
    witness[j] = RqPoly(one);
    cyclo_commit_witness(witness)
        .commitment
        .iter()
        .map(|p| p.0.clone())
        .collect()
}

// ════════════════════════════════════════════════════════════════════════════
// PINNED VECTORS — frozen from the unmodified implementations. Changing any
// implementation detail (parameters, domains, encodings, hash usage) MUST
// break these tests.
// ════════════════════════════════════════════════════════════════════════════

/// nizk `AjtaiCommitment::to_d2_digest` for the fixed witness under `SEED_A`.
const PINNED_NIZK_D2_W: &str =
    "629db2eb750e823d1c42385bf6158749d3866c61edb07edf167903ad484b76b4";
/// SHA-256 of cyclo `encode_commitment` wire bytes (26624 B) for the same
/// seed/witness.
const PINNED_CYCLO_COMMIT_SHA256: &str =
    "0dae02eb745b67661f69656feac80c1b1b836862e7e3650b2f8201e2e4178f31";
/// Column-probe D2 digests (recover matrix columns 0..2).
const PINNED_NIZK_D2_E: [&str; 3] = [
    "b9e75c2f08b6b6e0cb58de75d3de77e623366f517c182bee2c81d73c5b397855",
    "d3ebece955138f3652be3646cc75c25832afb8a99915a077c52b07b2775a49ef",
    "28c4841f1191814c26c90b1f1881cc57a54518e078f25e25821d61d93561665f",
];

/// Aggregator `FieldAjtaiMatrix::<Fr>::from_epoch([0xAA;32], 2, 3)` entries,
/// canonical 32-byte LE hex.
const PINNED_AGG_ENTRIES: [[&str; 3]; 2] = [
    [
        "7d3f6b6dc6f3ae55bdaeaf22dca6d915c479a111bf298eaa8e7911fe99600f2c",
        "005fa5bdc428432b9625bf8586022ca9221ab58d1a334c47acde8b9f0721f504",
        "feef2665dc5c780d0c86b4f705a7932b3264a9c308ace0491d088cb3ab7a6a05",
    ],
    [
        "f1baf10c4bfabbffd46094daf006e065bcb1290e89b2d49602069eba70a40318",
        "2e762f6d7196121adbea0f7f939e5b2240d99aadbadbffaf9c737e10d71c031e",
        "fd5e68f6903cb3b684ab6be196efab56bbdff3a4dec1b49629b9eab80017da25",
    ],
];
/// `commit([5, 7, 11])` under that matrix.
const PINNED_AGG_COMMIT: [&str; 2] = [
    "55264a0b421c21d8ea8f1120890f95fbbf535a978ef8a122c70e05c3e6383a18",
    "c7f680c32037a4945716184cf9273a4c06d9f285a7bd366fadd9b8d86164a614",
];

/// nizk transcript challenges (see test bodies for the exact scripts).
const PINNED_NIZK_FS_T1: &str =
    "6577e14af2d43ba7562ff698c4bbda76a82539505fe3497a22d29a012e023b5d";
const PINNED_NIZK_FS_T2: &str =
    "c5f746ac500bbea2a47e90135d6e3709416cb9eef76d1380c70155b132d35d5a";
const PINNED_NIZK_FS_T3: &str =
    "76b509341367f51594ae8187dcf5784d75944d6c9f2e955e4b0b4f15e406c7da";
const PINNED_NIZK_FS_T4: &str = "76b509341367f51594ae8187dcf5784d75944d6c9f2e955e4b0b4f15e406c7daeba32334e97925cee1457cbbbc3b6cd89d81cdbcf8764e62ae6380d67faf766a1397809b06ed852a8afa91fa682290fa1a65aaba5ebb06829dafd9581b567b1e";
const PINNED_NIZK_FS_T5: &str = "11cd1ecbf71109a82314dc27bcab138d";
const PINNED_NIZK_FS_T6: &str =
    "60ec0f7a27980e77f1a7b391a3de14363395b3e70f5e19742ad6bc50ee70015e";

/// cyclo Fiat-Shamir one-shot digests.
const PINNED_CYCLO_FS_C1: &str =
    "2b53423dd61a8e68e434a9fb23d2bff08b830b03a7e4ca19171163ef66f055ca";
const PINNED_CYCLO_FS_C2: &str =
    "dcceb84b300fd84fa3f466eb11615e1d8ec9a96be13bf03ddceb32d3b67b17ab";
const PINNED_CYCLO_FS_C3: &str =
    "382d7f33b7863315224766aece1ab9fe7377bb5cec38241d840732e914fe3945";
const PINNED_CYCLO_FS_C4: &str =
    "f24dc389d7ad8f9b23da82499bcf8e844d7492eaadcf050997520265a12341e0";
const PINNED_CYCLO_FS_C5: &str =
    "a28f08cf662523fb2e53871a80b0d8a32654a3483d198de89d9419d6a7e2ba0d";
const PINNED_CYCLO_FS_C6: &str =
    "8937d8a80860ea76a8fb2b14d4708d3efe26cbf3e90936dbeabd76eddf310ded";
const PINNED_CYCLO_FS_C7: &str =
    "685af19dfcab015157bb4371e8751771d98c0c2e06114ecbdaf668bd57b5b508";
/// `CycloTernaryTranscript` sampled sequences.
const PINNED_TERNARY_SEQ: [i8; 8] = [-1, 1, 0, -1, 0, 1, 1, 1];
const PINNED_TERNARY_SEQ2: [i8; 4] = [1, 1, -1, -1];

/// Ring-operation result digests (SHA-256 over `rqpoly_to_bytes`).
const PINNED_RING_ADD_SHA256: &str =
    "e1804a683a35bb999bedffc62995d6c830ffdf97e1fbcb9a836d8a4de127d4de";
const PINNED_RING_MUL_SHA256: &str =
    "52350fd0069dbaffa06f03240eb649bb7bc4b9a7e63a5c5267a1c8e2627e6112";
const PINNED_RING_SCALE7_SHA256: &str =
    "62d74dea82b780397b837e40861ab758203d83a712cb9241a310659fe2b33336";
const PINNED_RING_NEG_SHA256: &str =
    "22c0913b72e5548ee73b64841f9df238d563fcb0ce43ad78bf99a06e91c043aa";

/// Norm pins.
const PINNED_NORM_POLY_NORM: u64 = 281_474_976_719_360; // (q_commit − 1)/2
const PINNED_NORM_POLY_NORM_SQ: u128 = 158_456_325_038_328_507_976_402_862_082;
const PINNED_POLY_A_NORM: u64 = 281_203_200_893_859;
const PINNED_BYTES_REDUCED_FIRST: u64 = 562_949_382_980_608; // (2^64−1) mod q

fn pinned_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("pinned hex decodes")
}

fn pinned_fr(s: &str) -> Fr {
    Fr::from_le_bytes_mod_order(&pinned_bytes(s))
}

// ════════════════════════════════════════════════════════════════════════════
// (a) Ajtai commitments
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ajtai_shared_parameters_match() {
    // The nizk and cyclo Ajtai implementations claim the same ring.
    assert_eq!(NIZK_Q, CYCLO_Q, "q_commit mismatch");
    assert_eq!(NIZK_Q, 562_949_953_438_721);
    assert_eq!(NIZK_PHI, PHI_COMMIT);
    assert_eq!(NIZK_PHI, 256);
    assert_eq!(AJTAI_RANK, RANK);
    assert_eq!(WITNESS_BOUND, 1024);
    let p = NizkAjtaiParams::default();
    assert_eq!((p.phi, p.q, p.rank, p.witness_bound), (256, NIZK_Q, 13, 1024));
}

#[test]
fn nizk_ajtai_commit_open_verify_roundtrip() {
    let (_params, matrix) = nizk_params_and_matrix();
    let witness: Vec<Rq> = fixed_witness_centred().iter().map(nizk_rq).collect();

    let commitment = NizkAjtaiCommitment::commit(&matrix, &witness).expect("commit");
    commitment
        .verify_open(&matrix, &witness)
        .expect("valid opening must verify");

    // Determinism: committing twice yields the same digest.
    let again = NizkAjtaiCommitment::commit(&matrix, &witness).expect("commit");
    assert_eq!(commitment.to_d2_digest(), again.to_d2_digest());

    // Frozen digest (pins coefficients byte-for-byte).
    assert_eq!(
        hex::encode(commitment.to_d2_digest()),
        PINNED_NIZK_D2_W,
        "nizk Ajtai commitment digest drifted"
    );

    // Tampered witness must fail verification.
    let mut tampered = fixed_witness_centred();
    tampered[0][0] = if tampered[0][0] == 5 { 6 } else { 5 };
    let bad: Vec<Rq> = tampered.iter().map(nizk_rq).collect();
    let err = commitment
        .verify_open(&matrix, &bad)
        .expect_err("tampered witness must fail");
    assert!(
        matches!(err, NizkError::VerificationFailed { .. }),
        "expected VerificationFailed, got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "NIZK verification failed (party None): ajtai opening mismatch"
    );

    // Wrong witness length is rejected at commit time.
    let short = &witness[..WITNESS_M - 1];
    let err = NizkAjtaiCommitment::commit(&matrix, short)
        .err()
        .expect("length mismatch must fail");
    assert!(matches!(err, NizkError::InvalidInput { .. }));

    // Over-bound witness (∞-norm > 1024) is rejected at commit time.
    let mut over = [0i64; NIZK_PHI];
    over[0] = 1025;
    let mut bad_witness = witness.clone();
    bad_witness[0] = Rq::new(over, NIZK_Q);
    let err = NizkAjtaiCommitment::commit(&matrix, &bad_witness)
        .err()
        .expect("over-bound witness must fail");
    assert!(matches!(err, NizkError::InvalidInput { .. }));
}

#[test]
fn cyclo_ajtai_commit_verify_wire_roundtrip() {
    let params = cyclo_params();
    let witness: Vec<RqPoly> = fixed_witness_centred()
        .iter()
        .map(cyclo_rq_from_centred)
        .collect();

    let commitment = cyclo_commit_witness(witness.clone());
    assert!(
        cyclo_ajtai_verify(&params, &commitment, &witness),
        "valid witness must verify"
    );

    // Tampered witness must not verify.
    let mut bad = witness.clone();
    let mut coeffs = bad[0].0.clone();
    coeffs[0] = (coeffs[0] + 1) % CYCLO_Q;
    bad[0] = RqPoly(coeffs);
    assert!(
        !cyclo_ajtai_verify(&params, &commitment, &bad),
        "tampered witness must not verify"
    );

    // Wire format: exactly m × 256 × 8 bytes, deterministic, decode-invertible.
    let encoded = encode_commitment(&commitment);
    assert_eq!(encoded.len(), RANK * PHI_COMMIT * 8);
    assert_eq!(encoded.len(), 26_624);
    assert_eq!(
        sha256_hex(&[&encoded]),
        PINNED_CYCLO_COMMIT_SHA256,
        "cyclo Ajtai commitment wire bytes drifted"
    );
    let decoded = decode_commitment(&encoded, RANK).expect("decode");
    assert_eq!(decoded, commitment, "encode→decode round trip broke");

    // Wrong wire length is rejected.
    assert!(decode_commitment(&encoded[..encoded.len() - 8], RANK).is_err());
}

/// THE cross-implementation equivalence check for the two ring-based Ajtai
/// implementations: same seed ⇒ same matrix residues; same witness ⇒ same
/// commitment coefficients (verified through the D2 digest, which commits to
/// every coefficient byte).
#[test]
fn nizk_cyclo_ajtai_commitment_byte_equivalence() {
    // Whole-witness equivalence.
    let nizk_commitment = nizk_commit_fixed_witness();
    let cyclo_commitment = cyclo_commit_fixed_witness();
    let cyclo_elems: Vec<Vec<u64>> = cyclo_commitment
        .commitment
        .iter()
        .map(|p| p.0.clone())
        .collect();
    assert_eq!(
        hex::encode(nizk_commitment.to_d2_digest()),
        PINNED_NIZK_D2_W
    );
    assert_eq!(
        hex::encode(d2_digest_of_residues(&cyclo_elems)),
        PINNED_NIZK_D2_W,
        "nizk and cyclo Ajtai commitments diverge for the same seed/witness"
    );

    // Per-column matrix equivalence (unit-vector probes recover A[·][j]).
    for (j, pinned) in PINNED_NIZK_D2_E.iter().enumerate() {
        let nizk_probe = column_probe_nizk(j);
        let cyclo_probe = column_probe_cyclo(j);
        assert_eq!(
            hex::encode(nizk_probe),
            *pinned,
            "nizk matrix column {j} drifted"
        );
        assert_eq!(
            hex::encode(d2_digest_of_residues(&cyclo_probe)),
            *pinned,
            "nizk/cyclo matrix column {j} diverges"
        );
    }
}

/// The ring arithmetic underneath both Ajtai implementations is identical on
/// the shared domain: nizk schoolbook (i128 accumulators, centred i64) agrees
/// with cyclo NTT (u64 residues) coefficient-by-coefficient.
#[test]
fn nizk_cyclo_ring_arithmetic_equivalence() {
    let a_res = poly_a_residues();
    let b_res = poly_b_residues();
    let a_c: Vec<i64> = a_res.iter().map(|&c| residue_to_centred(c)).collect();
    let b_c: Vec<i64> = b_res.iter().map(|&c| residue_to_centred(c)).collect();

    let a_nizk = Rq::new(a_c.clone().try_into().expect("256 coeffs"), NIZK_Q);
    let b_nizk = Rq::new(b_c.clone().try_into().expect("256 coeffs"), NIZK_Q);
    let a_cyclo = RqPoly(a_res.clone());
    let b_cyclo = RqPoly(b_res.clone());

    // Multiplication: schoolbook vs NTT.
    let prod_nizk = a_nizk.mul(&b_nizk).expect("nizk mul");
    let prod_cyclo = ntt_mul(&a_cyclo, &b_cyclo).expect("cyclo ntt_mul");
    let expected_prod: Vec<i64> = prod_cyclo.0.iter().map(|&c| residue_to_centred(c)).collect();
    let expected_prod = Rq::new(expected_prod.try_into().expect("256 coeffs"), NIZK_Q);
    assert_eq!(
        prod_nizk, expected_prod,
        "nizk schoolbook mul != cyclo NTT mul"
    );

    // Addition (both reduce mod q and centre identically).
    let sum_nizk = a_nizk.add(&b_nizk).expect("nizk add");
    let sum_cyclo = ring_add_poly(&a_cyclo, &b_cyclo);
    let expected_sum: Vec<i64> = sum_cyclo.0.iter().map(|&c| residue_to_centred(c)).collect();
    let expected_sum = Rq::new(expected_sum.try_into().expect("256 coeffs"), NIZK_Q);
    assert_eq!(sum_nizk, expected_sum, "nizk add != cyclo ring_add_poly");

    // Norm on the shared value agrees.
    assert_eq!(
        prod_nizk.infinity_norm(),
        cyclo_norm_inf(&prod_cyclo),
        "nizk/cyclo ∞-norm of product diverges"
    );
}

/// The aggregator's `folding::ajtai` is a DIFFERENT construction (prime-field
/// matrix–vector product over bn254 Fr, SHA-256-derived matrix): pin its
/// behavior separately; it is not byte-comparable with the ring-based pair.
#[test]
fn aggregator_field_ajtai_pinned_vectors() {
    let epoch = [0xAA; 32];
    let mat = FieldAjtaiMatrix::<Fr>::from_epoch(&epoch, 2, 3);
    assert_eq!((mat.rows, mat.cols), (2, 3));
    for (i, row) in mat.entries.iter().enumerate() {
        for (j, entry) in row.iter().enumerate() {
            assert_eq!(
                *entry,
                pinned_fr(PINNED_AGG_ENTRIES[i][j]),
                "aggregator Ajtai entry ({i},{j}) drifted"
            );
        }
    }

    // Determinism and epoch sensitivity.
    let mat2 = FieldAjtaiMatrix::<Fr>::from_epoch(&epoch, 2, 3);
    assert_eq!(mat.entries, mat2.entries, "from_epoch not deterministic");
    let mat3 = FieldAjtaiMatrix::<Fr>::from_epoch(&[0xAB; 32], 2, 3);
    assert_ne!(mat.entries, mat3.entries, "epoch not bound into matrix");
    // Shape is bound into the derivation seed: same epoch, different shape.
    let mat4 = FieldAjtaiMatrix::<Fr>::from_epoch(&epoch, 1, 3);
    assert_ne!(
        mat.entries[0], mat4.entries[0],
        "rows/cols not bound into matrix derivation"
    );

    // Commitment = matrix–vector product over Fr.
    let w = vec![Fr::from(5u64), Fr::from(7u64), Fr::from(11u64)];
    let c = mat.commit(&w);
    assert_eq!(c.len(), 2);
    for (i, ci) in c.iter().enumerate() {
        assert_eq!(
            *ci,
            pinned_fr(PINNED_AGG_COMMIT[i]),
            "aggregator Ajtai commitment {i} drifted"
        );
    }

    // Linearity (the property folding relies on).
    let w2 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let c1 = mat.commit(&w);
    let c2 = mat.commit(&w2);
    let w_sum: Vec<Fr> = w.iter().zip(&w2).map(|(&x, &y)| x + y).collect();
    let c_sum = mat.commit(&w_sum);
    for i in 0..2 {
        assert_eq!(c_sum[i], c1[i] + c2[i], "linearity broken at row {i}");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// (b) Fiat-Shamir transcripts
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn nizk_transcript_domain_prefix_pinned() {
    assert_eq!(DOMAIN_SEP_PREFIX, "pvthfhe/cyclo-ajtai-d2/v1/");
}

/// Fixed challenge vectors for the nizk (sigma-domain) transcript.
/// Each vector is pinned twice: against the frozen literal and against an
/// independent sha2 replay of the documented construction.
#[test]
fn nizk_transcript_fixed_challenge_vectors() {
    let session = b"primitive-equivalence-session";

    // T1: one absorb, 32-byte challenge.
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut out = [0u8; 32];
    t.challenge_bytes(b"challenge", &mut out);
    assert_eq!(hex::encode(out), PINNED_NIZK_FS_T1);
    assert_eq!(
        nizk_challenge_rederived(
            session,
            7,
            &[(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF])],
            b"challenge",
            32
        ),
        out,
        "T1 does not match the documented construction"
    );

    // T2: same script, different participant id.
    let mut t = NizkTranscript::new(session, 8);
    t.absorb(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut out = [0u8; 32];
    t.challenge_bytes(b"challenge", &mut out);
    assert_eq!(hex::encode(out), PINNED_NIZK_FS_T2);
    assert_eq!(
        nizk_challenge_rederived(
            session,
            8,
            &[(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF])],
            b"challenge",
            32
        ),
        out
    );

    // T3: two absorbs.
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"a", &[0x01]);
    t.absorb(b"b", &[0x02, 0x03]);
    let mut out = [0u8; 32];
    t.challenge_bytes(b"fold-challenge", &mut out);
    assert_eq!(hex::encode(out), PINNED_NIZK_FS_T3);
    assert_eq!(
        nizk_challenge_rederived(
            session,
            7,
            &[(b"a", &[0x01]), (b"b", &[0x02, 0x03])],
            b"fold-challenge",
            32
        ),
        out
    );

    // T4: 96-byte squeeze (exercises counter-mode extension, 3 blocks).
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"a", &[0x01]);
    t.absorb(b"b", &[0x02, 0x03]);
    let mut out = [0u8; 96];
    t.challenge_bytes(b"fold-challenge", &mut out);
    assert_eq!(hex::encode(out), PINNED_NIZK_FS_T4);
    assert_eq!(
        nizk_challenge_rederived(
            session,
            7,
            &[(b"a", &[0x01]), (b"b", &[0x02, 0x03])],
            b"fold-challenge",
            96
        ),
        out
    );
    // The first 32 bytes of a 96-byte squeeze equal the 32-byte squeeze of
    // the same script (counter-mode prefix property).
    assert_eq!(&out[..32], &pinned_bytes(PINNED_NIZK_FS_T3)[..]);

    // T5: empty absorb data, short (16-byte) challenge.
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"empty", &[]);
    let mut out = [0u8; 16];
    t.challenge_bytes(b"c", &mut out);
    assert_eq!(hex::encode(out), PINNED_NIZK_FS_T5);
    assert_eq!(
        nizk_challenge_rederived(session, 7, &[(b"empty", &[])], b"c", 16),
        out
    );

    // T6: continuation after a squeeze — the running state persists (the
    // challenge label was absorbed) and later absorbs extend it.
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut first = [0u8; 32];
    t.challenge_bytes(b"challenge", &mut first);
    t.absorb(b"more", &[0x99]);
    let mut second = [0u8; 32];
    t.challenge_bytes(b"second", &mut second);
    assert_eq!(hex::encode(second), PINNED_NIZK_FS_T6);
    let mut h = nizk_raw_hasher(session, 7);
    nizk_raw_absorb(&mut h, b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let _ = nizk_raw_challenge(&mut h, b"challenge", 32);
    nizk_raw_absorb(&mut h, b"more", &[0x99]);
    assert_eq!(
        nizk_raw_challenge(&mut h, b"second", 32),
        second,
        "T6 continuation does not match the documented construction"
    );
}

#[test]
fn nizk_transcript_binding_properties() {
    let session = b"primitive-equivalence-session";
    let base = |pid: u32| {
        let mut t = NizkTranscript::new(session, pid);
        t.absorb(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut out = [0u8; 32];
        t.challenge_bytes(b"challenge", &mut out);
        out
    };
    // Participant binding.
    assert_ne!(base(7), base(8));
    // Session binding.
    let mut other = NizkTranscript::new(b"other-session", 7);
    other.absorb(b"commit", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut o = [0u8; 32];
    other.challenge_bytes(b"challenge", &mut o);
    assert_ne!(base(7), o);
    // Absorb order matters (length-prefixed framing is order-sensitive).
    let mut t = NizkTranscript::new(session, 7);
    t.absorb(b"b", &[0x02, 0x03]);
    t.absorb(b"a", &[0x01]);
    let mut swapped = [0u8; 32];
    t.challenge_bytes(b"fold-challenge", &mut swapped);
    assert_ne!(hex::encode(swapped), PINNED_NIZK_FS_T3);
    // Chunking ambiguity resistance: absorb("a","bc") ≠ absorb("ab","c").
    let mut t1 = NizkTranscript::new(session, 7);
    t1.absorb(b"a", b"bc");
    let mut o1 = [0u8; 32];
    t1.challenge_bytes(b"ch", &mut o1);
    let mut t2 = NizkTranscript::new(session, 7);
    t2.absorb(b"ab", b"c");
    let mut o2 = [0u8; 32];
    t2.challenge_bytes(b"ch", &mut o2);
    assert_ne!(o1, o2);
}

/// Fixed challenge vectors for the cyclo (folding-domain) one-shot digests.
/// Each is pinned against the frozen literal and an independent sha2 replay.
#[test]
fn cyclo_fs_fixed_challenge_vectors() {
    let c1 = cyclo_fs::challenge_v1("session-alpha", 3, &[0x11; 32], &[0x22; 64], &[0x33; 16]);
    assert_eq!(hex::encode(c1), PINNED_CYCLO_FS_C1);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fs-v1")
        .chain_update(b"session-alpha")
        .chain_update(3u32.to_le_bytes())
        .chain_update([0x11; 32])
        .chain_update([0x22; 64])
        .chain_update([0x33; 16])
        .finalize()
        .into();
    assert_eq!(c1, rederived, "C1 does not match the documented construction");

    let c2 = cyclo_fs::challenge_v2(
        "session-alpha",
        3,
        &[0x44; 32],
        &[0x11; 32],
        &[0x22; 64],
        &[0x33; 16],
    );
    assert_eq!(hex::encode(c2), PINNED_CYCLO_FS_C2);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fs-v2")
        .chain_update(b"session-alpha")
        .chain_update(3u32.to_le_bytes())
        .chain_update([0x44; 32])
        .chain_update([0x11; 32])
        .chain_update([0x22; 64])
        .chain_update([0x33; 16])
        .finalize()
        .into();
    assert_eq!(c2, rederived);
    assert_ne!(c1, c2, "v1 and v2 domains must be separated");

    let c3 = cyclo_fs::commitment_v1("session-alpha", 5, &[0x55; 40], &[0x66; 24]);
    assert_eq!(hex::encode(c3), PINNED_CYCLO_FS_C3);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-v1")
        .chain_update(b"session-alpha")
        .chain_update(5u32.to_le_bytes())
        .chain_update([0x55; 40])
        .chain_update([0x66; 24])
        .finalize()
        .into();
    assert_eq!(c3, rederived);

    let c4 = cyclo_fs::public_io_v1(
        "session-alpha",
        5,
        &[0x77; 8],
        &[0x88; 8],
        0x0123_4567_89AB_CDEFu128,
    );
    assert_eq!(hex::encode(c4), PINNED_CYCLO_FS_C4);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-io-v1")
        .chain_update(b"session-alpha")
        .chain_update(5u32.to_le_bytes())
        .chain_update([0x77; 8])
        .chain_update([0x88; 8])
        .chain_update(0x0123_4567_89AB_CDEFu128.to_le_bytes())
        .finalize()
        .into();
    assert_eq!(c4, rederived);

    let c5 = cyclo_fs::init_commitment_v1("session-alpha", &[0x99; 20]);
    assert_eq!(hex::encode(c5), PINNED_CYCLO_FS_C5);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-v1")
        .chain_update(b"session-alpha")
        .chain_update([0x99; 20])
        .finalize()
        .into();
    assert_eq!(c5, rederived);

    let c6 = cyclo_fs::init_public_io_v1("session-alpha", &[0xAA; 20]);
    assert_eq!(hex::encode(c6), PINNED_CYCLO_FS_C6);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-io-v1")
        .chain_update(b"session-alpha")
        .chain_update([0xAA; 20])
        .finalize()
        .into();
    assert_eq!(c6, rederived);

    let c7 = cyclo_fs::params_digest_v1(b"pvthfhe-cyclo-params");
    assert_eq!(hex::encode(c7), PINNED_CYCLO_FS_C7);
    let rederived: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-params")
        .finalize()
        .into();
    assert_eq!(c7, rederived, "params_digest_v1 is a bare SHA-256 of the label");
}

/// The cyclo ternary transcript: fixed sampled sequences pinned both against
/// the frozen literals and against an independent replay of the documented
/// rejection-sampling construction.
#[test]
fn cyclo_ternary_transcript_fixed_sequence() {
    let mut tt = cyclo_fs::CycloTernaryTranscript::new("session-alpha", 5);
    tt.absorb(b"commit", &[1, 2, 3]);
    tt.absorb(b"empty", &[]);
    let seq: Vec<i8> = (0..8).map(|_| tt.sample_challenge()).collect();
    assert_eq!(seq, PINNED_TERNARY_SEQ, "ternary sequence drifted");
    tt.absorb(b"more", &[9, 9]);
    let seq2: Vec<i8> = (0..4).map(|_| tt.sample_challenge()).collect();
    assert_eq!(seq2, PINNED_TERNARY_SEQ2, "ternary continuation drifted");

    // Independent replay of the same construction.
    let (rseq, rseq2) = cyclo_ternary_sequence_rederived();
    assert_eq!(seq, rseq, "sequence does not match documented construction");
    assert_eq!(seq2, rseq2);

    // Range: every sample is a valid ternary value.
    assert!(seq.iter().chain(&seq2).all(|c| (-1..=1).contains(c)));

    // Participant binding: different participant id changes the stream.
    let mut other = cyclo_fs::CycloTernaryTranscript::new("session-alpha", 6);
    other.absorb(b"commit", &[1, 2, 3]);
    other.absorb(b"empty", &[]);
    let oseq: Vec<i8> = (0..8).map(|_| other.sample_challenge()).collect();
    assert_ne!(oseq, seq, "participant id not bound into ternary stream");
}

// ════════════════════════════════════════════════════════════════════════════
// (c) Norm / range-check helpers
// ════════════════════════════════════════════════════════════════════════════

/// Accept/reject equivalence battery over the shared domain: for every case,
/// cyclo `check_range` and aggregator `enforce_norm_inf` must reach the same
/// verdict, and on rejection must report the same observed norm.
#[test]
fn norm_check_accept_reject_equivalence_battery() {
    let half = (CYCLO_Q - 1) / 2;
    let mut boundary_poly = vec![0u64; PHI_COMMIT];
    boundary_poly[7] = CYCLO_Q.div_ceil(2);
    let mut neg_one_poly = vec![0u64; PHI_COMMIT];
    neg_one_poly[3] = CYCLO_Q - 1; // centred −1
    let mut neg_1024_poly = vec![0u64; PHI_COMMIT];
    neg_1024_poly[5] = CYCLO_Q - 1024; // centred −1024

    let cases: Vec<(Vec<u64>, u64, bool)> = vec![
        (vec![0u64; PHI_COMMIT], 0, true),
        (vec![5u64; PHI_COMMIT], 1024, true),
        (vec![1024u64; PHI_COMMIT], 1024, true), // boundary: norm == bound
        (vec![1025u64; PHI_COMMIT], 1024, false),
        (neg_one_poly.clone(), 1, true),
        (neg_one_poly.clone(), 0, false),
        (neg_1024_poly.clone(), 1024, true),
        (neg_1024_poly.clone(), 1023, false),
        (boundary_poly.clone(), half, true), // exact centred boundary
        (boundary_poly.clone(), half - 1, false),
        (norm_poly_residues(), half, true),
        (norm_poly_residues(), half - 1, false),
    ];

    for (idx, (residues, bound, expect_ok)) in cases.iter().enumerate() {
        let poly = RqPoly(residues.clone());
        let cyclo = check_range(&poly, *bound);
        let element = ring_elem_from_residues(residues);
        let agg = enforce_norm_inf(&element, fq(*bound), "s");
        assert_eq!(
            cyclo.is_ok(),
            *expect_ok,
            "case {idx}: cyclo verdict mismatch"
        );
        assert_eq!(
            agg.is_ok(),
            *expect_ok,
            "case {idx}: aggregator verdict mismatch"
        );
        if !expect_ok {
            let got = cyclo_norm_inf(&poly);
            // cyclo error payload pins the observed norm and bound.
            match cyclo.expect_err("case must fail") {
                CycloError::NormBoundExceeded { got: g, max } => {
                    assert_eq!((g, max), (got, *bound), "case {idx} payload")
                }
                other => panic!("case {idx}: unexpected cyclo error {other}"),
            }
            // aggregator reports the same numbers in its message string.
            let msg = agg.expect_err("case must fail");
            assert_eq!(
                msg,
                format!("s norm {got} exceeds bound {bound}"),
                "case {idx}: aggregator message"
            );
        }
    }
}

/// Norm VALUES agree across implementations on the shared domain, including
/// the exact centredness boundary and empty-input behavior.
#[test]
fn norm_value_equivalence_on_shared_domain() {
    let np = norm_poly_residues();
    let cyclo_val = cyclo_norm_inf(&RqPoly(np.clone()));
    let agg_val = fq_to_u64(&ring_elem_from_residues(&np).norm_inf());
    assert_eq!(cyclo_val, PINNED_NORM_POLY_NORM);
    assert_eq!(agg_val, PINNED_NORM_POLY_NORM, "norm_inf diverges");

    let pa = poly_a_residues();
    let cyclo_val = cyclo_norm_inf(&RqPoly(pa.clone()));
    let agg_val = fq_to_u64(&ring_elem_from_residues(&pa).norm_inf());
    assert_eq!(cyclo_val, PINNED_POLY_A_NORM);
    assert_eq!(agg_val, PINNED_POLY_A_NORM);

    // `centred` boundary mapping (cyclo-side; pinned).
    assert_eq!(centred(0), 0);
    assert_eq!(centred(1), 1);
    assert_eq!(centred(CYCLO_Q - 1), 1);
    assert_eq!(centred((CYCLO_Q - 1) / 2), (CYCLO_Q - 1) / 2);
    assert_eq!(centred(CYCLO_Q.div_ceil(2)), (CYCLO_Q - 1) / 2);
    assert_eq!(centred(CYCLO_Q - 1024), 1024);

    // norm_sq is cyclo-only; pin its value on the same input.
    assert_eq!(
        norm_sq(&RqPoly(np)),
        PINNED_NORM_POLY_NORM_SQ,
        "norm_sq drifted"
    );

    // Empty inputs: both implementations accept and report norm 0.
    assert_eq!(cyclo_norm_inf(&RqPoly(vec![])), 0);
    assert!(check_range(&RqPoly(vec![]), 0).is_ok());
    let empty: RingElement<FqCommit> = RingElement { coeffs: vec![] };
    assert_eq!(fq_to_u64(&empty.norm_inf()), 0);
    assert!(enforce_norm_inf(&empty, fq(0), "s").is_ok());
}

/// Exact error payload strings/fields (pinned — consolidation must preserve
/// error surfaces or consciously migrate them).
#[test]
fn norm_error_payloads_pinned() {
    let e = RingElement {
        coeffs: vec![fq(17); 256],
    };
    let msg = enforce_norm_inf(&e, fq(16), "e").expect_err("must fail");
    assert_eq!(msg, "e norm 17 exceeds bound 16");

    let err = check_range(&RqPoly(vec![17u64; PHI_COMMIT]), 16).expect_err("must fail");
    assert_eq!(err.to_string(), "norm bound exceeded: got 17, max 16");
    match err {
        CycloError::NormBoundExceeded { got, max } => assert_eq!((got, max), (17, 16)),
        other => panic!("unexpected error variant: {other}"),
    }
}

/// `validate_folding_witness` is aggregator-only (no cyclo counterpart); pin
/// its accept/reject behavior and message format.
#[test]
fn validate_folding_witness_pinned() {
    let s = RingElement {
        coeffs: vec![fq(5); 256],
    };
    let e_ok = RingElement {
        coeffs: vec![fq(10); 256],
    };
    let e_bad = RingElement {
        coeffs: vec![fq(17); 256],
    };
    let z = RingElement {
        coeffs: vec![fq(100); 256],
    };
    validate_folding_witness(&s, &e_ok, &z, &z, fq(1024), fq(16), fq(2049))
        .expect("valid folding witness must pass");
    let msg = validate_folding_witness(&s, &e_bad, &z, &z, fq(1024), fq(16), fq(2049))
        .expect_err("over-bound error term must fail");
    assert_eq!(msg, "e norm 17 exceeds bound 16");
    // The secret-key limb is checked first: both-bad reports "s".
    let s_bad = RingElement {
        coeffs: vec![fq(2000); 256],
    };
    let msg = validate_folding_witness(&s_bad, &e_bad, &z, &z, fq(1024), fq(16), fq(2049))
        .expect_err("must fail");
    assert_eq!(msg, "s norm 2000 exceeds bound 1024");
}

// ════════════════════════════════════════════════════════════════════════════
// (c) Ring helpers: aggregator RingElement<FqCommit> vs cyclo RqPoly ops
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn ring_add_equivalence() {
    let a = poly_a_residues();
    let b = poly_b_residues();
    let cyclo = ring_add_poly(&RqPoly(a.clone()), &RqPoly(b.clone()));
    let agg = ring_elem_from_residues(&a).add(&ring_elem_from_residues(&b));
    assert_eq!(agg.len(), PHI_COMMIT);
    for (i, (x, y)) in agg.coeffs.iter().zip(&cyclo.0).enumerate() {
        assert_eq!(fq_to_u64(x), *y, "add mismatch at coeff {i}");
    }
    assert_eq!(
        sha256_hex(&[&rqpoly_to_bytes(&cyclo)]),
        PINNED_RING_ADD_SHA256
    );
}

#[test]
fn ring_mul_schoolbook_equivalent_to_ntt() {
    let a = poly_a_residues();
    let b = poly_b_residues();
    let cyclo = ntt_mul(&RqPoly(a.clone()), &RqPoly(b.clone())).expect("ntt_mul");
    let agg = ring_elem_from_residues(&a).mul(&ring_elem_from_residues(&b));
    for (i, (x, y)) in agg.coeffs.iter().zip(&cyclo.0).enumerate() {
        assert_eq!(fq_to_u64(x), *y, "mul mismatch at coeff {i}");
    }
    assert_eq!(
        sha256_hex(&[&rqpoly_to_bytes(&cyclo)]),
        PINNED_RING_MUL_SHA256
    );

    // Negacyclic sanity on the shared domain: X·X^255 ≡ −1 (pinned value).
    let mut x1 = vec![0u64; PHI_COMMIT];
    x1[1] = 1;
    let mut x255 = vec![0u64; PHI_COMMIT];
    x255[255] = 1;
    let cyclo = ntt_mul(&RqPoly(x1.clone()), &RqPoly(x255.clone())).expect("ntt_mul");
    let agg = ring_elem_from_residues(&x1).mul(&ring_elem_from_residues(&x255));
    assert_eq!(cyclo.0[0], CYCLO_Q - 1, "X^256 must be −1 mod q");
    for (i, c) in cyclo.0.iter().enumerate().skip(1) {
        assert_eq!(*c, 0, "X^256 coeff {i} must vanish");
    }
    for (i, c) in agg.coeffs.iter().enumerate() {
        assert_eq!(fq_to_u64(c), cyclo.0[i], "X^256 mismatch at {i}");
    }
}

#[test]
fn ring_scalar_and_negation_equivalence() {
    let a = poly_a_residues();
    let elem = ring_elem_from_residues(&a);
    let poly = RqPoly(a.clone());

    // scale(7) == scalar_mul(·, 7).
    let cyclo = scalar_mul(&poly, 7);
    let agg = elem.scale(fq(7));
    for (i, (x, y)) in agg.coeffs.iter().zip(&cyclo.0).enumerate() {
        assert_eq!(fq_to_u64(x), *y, "scale(7) mismatch at coeff {i}");
    }
    assert_eq!(
        sha256_hex(&[&rqpoly_to_bytes(&cyclo)]),
        PINNED_RING_SCALE7_SHA256
    );

    // zero − x == ternary_mul(x, −1).
    let zero = RingElement::<FqCommit>::zero(PHI_COMMIT);
    let agg = zero.sub(&elem);
    let cyclo = ternary_mul(&poly, -1);
    for (i, (x, y)) in agg.coeffs.iter().zip(&cyclo.0).enumerate() {
        assert_eq!(fq_to_u64(x), *y, "negation mismatch at coeff {i}");
    }
    assert_eq!(
        sha256_hex(&[&rqpoly_to_bytes(&cyclo)]),
        PINNED_RING_NEG_SHA256
    );

    // scale(0) == ternary_mul(x, 0) == 0.
    let agg = elem.scale(fq(0));
    let cyclo = ternary_mul(&poly, 0);
    for (x, y) in agg.coeffs.iter().zip(&cyclo.0) {
        assert_eq!((fq_to_u64(x), *y), (0, 0));
    }
    // ternary_mul(x, 1) is the identity; out-of-range challenges yield zero
    // (pinned quirk of the current implementation).
    assert_eq!(ternary_mul(&poly, 1), poly);
    assert_eq!(ternary_mul(&poly, 2), RqPoly::zero());
}

#[test]
fn cyclo_ring_byte_codec_pinned() {
    let a = RqPoly(poly_a_residues());
    let bytes = rqpoly_to_bytes(&a);
    assert_eq!(bytes.len(), PHI_COMMIT * 8);
    let back = bytes_to_rqpoly(&bytes);
    assert_eq!(back, a, "u64-LE codec round trip broke");
    // Out-of-range u64 limbs are reduced mod q on decode (pinned).
    let reduced = bytes_to_rqpoly(&[0xFF; 8]);
    assert_eq!(reduced.0[0], PINNED_BYTES_REDUCED_FIRST);
    assert_eq!(reduced.0[0], u64::MAX % CYCLO_Q);
    // Short inputs are zero-padded to 256 coefficients (pinned).
    let short = bytes_to_rqpoly(&[1u8, 2, 3]);
    assert_eq!(short.0[0], 0x0003_0201);
    assert!(short.0[1..].iter().all(|&c| c == 0));
}
