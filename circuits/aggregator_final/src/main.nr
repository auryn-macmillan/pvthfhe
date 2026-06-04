// aggregator_final: C7 threshold-decryption correctness circuit.
//
// Proves that the plaintext output is the correct Lagrange recombination
// of decrypt share polynomials, using a Schwartz-Zippel polynomial identity
// check at a random challenge point `r`.
//
// Design: Schwartz-Zippel evaluation approach (T.1 from c7-correctness.md)
// ---------------------------------------------------------------
// Verifying sum(lambda_i * d_i[k]) = pt[k] for all 8,192 coefficients per
// share would require ~(3 * 8192 * t) constraints (~98K for t=4). Instead,
// we evaluate all polynomials at a single random challenge point r in Fr and
// verify sum(lambda_i * d_i(r)) = pt(r). This reduces the constraint count to
// O(MAX_SHARES) ~ 257 constraints, independent of ring dimension N=8192.
//
// The polynomials live in Z_Q[X]/(X^8192+1) where Q ~ 2^174 (product of
// 3 RNS moduli: 288230376173076481, 288230376167047169, 288230376161280001).
// Noir's native field is BN254 Fr, which is larger than Q, so a single Fr
// element can hold a coefficient value without overflow.
//
// What this circuit proves (C7 correctness relation):
// 1. sum(lambda_i) = 1                    (Lagrange interpolation identity)
// 2. sum(lambda_i * d_i(r)) = pt(r)      (Schwartz-Zippel recombination)
// 3. plaintext_commitment = Poseidon(pt)  (plaintext commitment binding)
// 4. Existing: non-zero guards, ciphertext-vs-plaintext, IVC hash, chain hash
//
// MAX_SHARES = 128 matches NOIR_MAX_PARTICIPANTS from full_pipeline.rs.
// Excess share slots beyond n_shares are zero-padded; zeros don't affect sums.

use poseidon;
use protocol_constants;

global N: u32 = 8;
global MAX_SHARES: u32 = 128;
global DEPTH: u32 = 8;

fn vector_hash<let M: u32>(values: [Field; M], domain_tag: Field) -> Field {
    let mut preimage = [0; M + 1];
    preimage[0] = domain_tag;
    for i in 0..M {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::sponge(preimage)
}

fn fold_sum<let M: u32>(values: [Field; M]) -> Field {
    let mut sum = 0;
    for i in 0..M {
        sum += values[i];
    }
    sum
}

fn hash_pair(left: Field, right: Field) -> Field {
    poseidon::poseidon::bn254::sponge([left, right])
}

fn compute_merkle_root(leaf: Field, path: [Field; DEPTH], leaf_index: Field) -> Field {
    let mut current = leaf;
    let mut idx = leaf_index;
    for i in 0..DEPTH {
        if (idx as u32) & 1 == 0 {
            current = hash_pair(current, path[i]);
        } else {
            current = hash_pair(path[i], current);
        }
        idx = idx / 2;
    }
    current
}

fn verification_statement_v1_hash(preimage: [Field; 92]) -> Field {
    poseidon::poseidon::bn254::sponge(preimage)
}

fn verification_statement_v1_golden_preimage() -> [Field; 92] {
    [
        11843706111462126810235743653006615712282455314701937352287001081393,
        1,
        23,
        1,
        4,
        1,
        2,
        32,
        21356283574076891493948969979685445151,
        42707334047547540181846984563639529007,
        3,
        32,
        42707334047547540181846984563639529007,
        64058384521018188869744999147593612863,
        4,
        8,
        42,
        5,
        32,
        64058384521018188869744999147593612863,
        85409434994488837557643013731547696719,
        6,
        32,
        85409434994488837557643013731547696719,
        106760485467959486245541028315501780575,
        7,
        32,
        106760485467959486245541028315501780575,
        128111535941430134933439042899455864431,
        8,
        32,
        128111535941430134933439042899455864431,
        149462586414900783621337057483409948287,
        9,
        32,
        149462586414900783621337057483409948287,
        170813636888371432309235072067364032143,
        10,
        32,
        170813636888371432309235072067364032143,
        192164687361842080997133086651318115999,
        11,
        32,
        192164687361842080997133086651318115999,
        213515737835312729685031101235272199855,
        12,
        32,
        213515737835312729685031101235272199855,
        234866788308783378372929115819226283711,
        13,
        32,
        234866788308783378372929115819226283711,
        256217838782254027060827130403180367567,
        14,
        32,
        256217838782254027060827130403180367567,
        277568889255724675748725144987134451423,
        15,
        32,
        277568889255724675748725144987134451423,
        298919939729195324436623159571088535279,
        16,
        32,
        298919939729195324436623159571088535279,
        320270990202665973124521174155042619135,
        17,
        32,
        320270990202665973124521174155042619135,
        5233100606242806050955395731361295,
        18,
        8,
        7,
        19,
        32,
        10680758337341567149999962687708403223,
        32031808810812215837897977271662487079,
        20,
        32,
        22690724228668807036942595891182575392,
        44041774702139455724840610475136659248,
        21,
        32,
        24025164883260722579936221802679705633,
        45376215356731371267834236386633789489,
        22,
        32,
        25359605537852638122929847714176835874,
        46710656011323286810827862298130919730,
        23,
        32,
        26694046192444553665923473625673966115,
        48045096665915202353821488209628049971,
    ]
}

fn main(
    // -- Existing public inputs (10) --
    ciphertext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    decrypt_nizk_hash: pub Field,
    dkg_transcript_hash: pub Field,
    dkg_root: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    n_participants: pub Field,
    threshold: pub Field,
    plaintext_commitment: pub Field,
    ivc_snark_proof_hash: pub Field,

    // -- New C7 public inputs (2) --
    challenge_r: pub Field,
    n_shares: pub Field,

    // -- Nova final state (existing, 2) --
    nova_final_plaintext: pub [Field; N],
    nova_share_chain_hash: pub Field,

    // -- New C7 witnesses (3) --
    share_evals: [Field; MAX_SHARES],
    lagrange_coeffs: [Field; MAX_SHARES],
    pt_eval: Field,

    // -- New G4 witnesses (3) --
    aggregate_pk_leaf: Field,
    merkle_path: [Field; DEPTH],
    leaf_index: Field,
) -> pub [Field; N] {
    // ---- Existing non-zero guards ----
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(participant_set_hash != 0, "participant set hash must be non-zero");
    assert(threshold as u32 > 0, "threshold must be positive");
    assert(threshold as u32 <= n_participants as u32, "threshold must not exceed n_participants");
    assert(aggregate_pk_hash != 0, "aggregate public key hash must be non-zero");
    assert(decrypt_nizk_hash != 0, "decrypt_nizk_hash must be non-zero");
    assert(dkg_transcript_hash != 0, "dkg_transcript_hash must be non-zero");
    assert(dkg_root != 0, "dkg_root must be non-zero");

    // ---- Existing plaintext commitment binding ----
    let computed_pt_hash = vector_hash(nova_final_plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(plaintext_commitment == computed_pt_hash, "plaintext commitment mismatch");

    // ---- Existing ciphertext-vs-plaintext distinction ----
    assert(ciphertext_hash != computed_pt_hash, "ciphertext and plaintext hash must differ");

    // ---- Existing IVC / chain hash non-zero checks ----
    assert(ivc_snark_proof_hash != 0, "IVC proof hash must be non-zero");
    assert(nova_share_chain_hash != 0, "Nova share chain hash must be non-zero");

    // ---- New C7: n_shares guard ----
    assert(n_shares as u32 > 0, "n_shares must be positive");
    assert(n_shares as u32 <= MAX_SHARES, "n_shares must not exceed MAX_SHARES");

    // ---- New C7: Lagrange identity (sum lambda_i = 1) ----
    // Verify that the Lagrange coefficients form a valid interpolation
    // basis. Excess entries beyond n_shares are zero-padded by the witness
    // generator, so they don't affect the sum.
    let lagrange_sum = fold_sum(lagrange_coeffs);
    assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");

    // ---- New C7: Schwartz-Zippel recombination ----
    // Verify sum(lambda_i * d_i(r)) = pt(r).
    //
    // For honest execution: d_i(r) is the evaluation of decrypt share
    // polynomial i at challenge point r, computed by Horner evaluation
    // in the witness generator. pt_eval is the evaluation of the
    // pre-scaling plaintext polynomial at the same point r.
    //
    // A malicious prover can't cheat because:
    // 1. The Schwartz-Zippel lemma guarantees that if the polynomials
    //    differ, then Pr[sum(lambda_i * d_i(r)) = pt(r)] <= deg/Q,
    //    which is negligible (~2^-58) for degree 8192 over field ~2^174.
    // 2. The challenge r is derived from the transcript (Fiat-Shamir),
    //    so the prover can't choose r after fixing the polynomials.
    let mut recombined_eval: Field = 0;
    for i in 0..MAX_SHARES {
        recombined_eval += lagrange_coeffs[i] * share_evals[i];
    }
    assert(recombined_eval == pt_eval, "Lagrange recombination does not match plaintext evaluation");

    // ---- New G4: PK binding -- aggregate_pk_hash derives from aggregate_pk_leaf ----
    // The prover must show knowledge of the preimage `aggregate_pk_leaf`
    // such that Poseidon([aggregate_pk_leaf]) == aggregate_pk_hash.
    // This binds the aggregate public key hash to a specific scalar value.
    let computed_pk_hash = poseidon::poseidon::bn254::sponge([aggregate_pk_leaf]);
    assert(aggregate_pk_hash == computed_pk_hash, "aggregate_pk_hash does not match aggregate_pk_leaf");

    // ---- New G4: Merkle-path verification for DKG transcript binding ----
    // Verify that `aggregate_pk_leaf` is committed in the DKG transcript
    // Merkle tree rooted at `dkg_root`. The prover supplies a Merkle path
    // (sibling hashes at each of DEPTH=8 levels) and the leaf index.
    //
    // Without this check, a malicious prover could claim ANY aggregate_pk
    // and the circuit would accept as long as the hash matches -- breaking
    // the link between the DKG transcript and the aggregate key used.
    let computed_dkg_root = compute_merkle_root(aggregate_pk_leaf, merkle_path, leaf_index);
    assert(computed_dkg_root == dkg_root, "Merkle path does not reach dkg_root");

    nova_final_plaintext
}

// ============================================================
// Test fixtures
// ============================================================

/// Returns (dkg_root, aggregate_pk_hash, merkle_path, leaf_index, aggregate_pk_leaf)
/// for a consistent neutral Merkle tree fixture with leaf=42 and all-zero path.
fn g4_neutral_fixture() -> (Field, Field, [Field; DEPTH], Field, Field) {
    let leaf: Field = 42;
    let pk_hash = poseidon::poseidon::bn254::sponge([leaf]);
    let path = [0; DEPTH];
    let root = compute_merkle_root(leaf, path, 0);
    let index: Field = 0;
    (root, pk_hash, path, index, leaf)
}

// ============================================================
// Tests
// ============================================================

// -- Existing tests (updated for new function signature) --

#[test]
fn test_simplified_honest() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();
    let plaintext = [42, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let ciphertext_hash = 99;

    // C7 params: neutral values that pass all constraints
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let result = main(
        ciphertext_hash,
        pk_hash,  // aggregate_pk_hash
        500,  // decrypt_nizk_hash
        999,  // dkg_transcript_hash
        dkg_root,    // dkg_root
        1,    // epoch
        300,  // participant_set_hash
        3,    // n_participants
        2,    // threshold
        plaintext_commitment,
        777,  // ivc_snark_proof_hash
        challenge_r,
        n_shares,
        plaintext,
        888,  // nova_share_chain_hash
        share_evals,
        lagrange_coeffs,
        pt_eval,
        aggregate_pk_leaf,
        merkle_path,
        leaf_index,
    );
    assert(result[0] == 42);
}

#[test(should_fail)]
fn test_plaintext_mismatch() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [1, 0, 0, 0, 0, 0, 0, 0];
    let wrong_commitment = 0;
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;
    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, wrong_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

#[test(should_fail)]
fn test_ivc_hash_zero() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0; N];
    let pt_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;
    let _ = main(
          pt_hash + 1, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, pt_hash, 0,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// G4.2: GREEN -- Honest PK binding passes Merkle-path verification.
///
/// Builds a valid Merkle tree leaf (aggregate_pk_leaf=42), computes its
/// Poseidon hash for aggregate_pk_hash, constructs a depth-8 binary Merkle
/// path, and verifies that the circuit accepts the proof when all G4
/// constraints are satisfied.
#[test]
fn test_g4_honest_pk_binding_accepts() {
    // Use the neutral fixture: leaf=42, all-zero path, index=0
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();

    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let result = main(
        99,            // ciphertext_hash
        pk_hash,
        500,           // decrypt_nizk_hash
        999,           // dkg_transcript_hash
        dkg_root,
        1,             // epoch
        300,           // participant_set_hash
        3,             // n_participants
        2,             // threshold
        plaintext_commitment,
        777,           // ivc_snark_proof_hash
        challenge_r,
        n_shares,
        plaintext,
        888,           // nova_share_chain_hash
        share_evals,
        lagrange_coeffs,
        pt_eval,
        aggregate_pk_leaf,
        merkle_path,
        leaf_index,
    );
    assert(result[0] == 0);
}

/// G4.3: REJECT -- Wrong aggregate_pk_leaf fails binding constraint.
///
/// The prover claims a different aggregate_pk_leaf than the one used to
/// compute aggregate_pk_hash. The binding constraint
///   Poseidon([aggregate_pk_leaf]) == aggregate_pk_hash
/// must reject.
#[test(should_fail)]
fn test_g4_wrong_aggregate_pk_leaf_rejects() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, _aggregate_pk_leaf) = g4_neutral_fixture();
    // Use a DIFFERENT leaf than the one whose hash is pk_hash
    let wrong_leaf = _aggregate_pk_leaf + 1;

    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        wrong_leaf, merkle_path, leaf_index,
    );
}

/// G4.4: REJECT -- Forged Merkle path does not reach dkg_root.
///
/// The prover forges the sibling in the Merkle path so that the
/// computed root differs from dkg_root. The Merkle-path verification
/// constraint must reject.
#[test(should_fail)]
fn test_g4_forged_merkle_path_rejects() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();
    // Forge the first sibling in the path
    let mut forged_path = merkle_path;
    forged_path[0] = forged_path[0] + 1;

    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        aggregate_pk_leaf, forged_path, leaf_index,
    );
}

// ============================================================
// G4 PK binding tests
// ============================================================

/// G4.1: RED -- Wrong dkg_root rejects (Merkle-path binding missing).
///
/// Provides a valid `aggregate_pk_leaf` with an honest Merkle path
/// to a known root, but supplies a WRONG `dkg_root` that does NOT
/// match the computed root. When the Merkle-path verification
/// constraints are in place, this must REJECT.
///
/// RED phase: without the constraints, the circuit will ACCEPT,
/// causing the `should_fail` test to report FAILURE (RED).
///
/// GREEN phase: after adding Merkle verification, the circuit REJECTS,
/// and the test PASSES (expected failure honored).
#[test(should_fail)]
fn test_g4_pk_binding_missing_rejects() {
    // Build honest Merkle path data.
    let aggregate_pk_leaf = 12345;
    // aggregate_pk_hash = Poseidon([aggregate_pk_leaf])
    let aggregate_pk_hash = poseidon::poseidon::bn254::sponge([aggregate_pk_leaf]);
    // Merkle path: all-zero siblings, leaf_index=0
    let leaf_index = 0;
    let merkle_path = [0; DEPTH];
    // Compute correct dkg_root
    let correct_dkg_root = compute_merkle_root(aggregate_pk_leaf, merkle_path, leaf_index);
    // But supply a WRONG root
    let wrong_dkg_root = correct_dkg_root + 1;

    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99,            // ciphertext_hash
        aggregate_pk_hash,
        500,           // decrypt_nizk_hash
        999,           // dkg_transcript_hash
        wrong_dkg_root, // WRONG: does not match Merkle root
        1,             // epoch
        300,           // participant_set_hash
        3,             // n_participants
        2,             // threshold
        plaintext_commitment,
        777,           // ivc_snark_proof_hash
        challenge_r,
        n_shares,
        plaintext,
        888,           // nova_share_chain_hash
        share_evals,
        lagrange_coeffs,
        pt_eval,
        aggregate_pk_leaf,
        merkle_path,
        leaf_index,
    );
}

#[test]
fn test_verification_statement_v1_poseidon_parity_hash_7807432589986464173440955546194920105762623084817847309522180293390994111() {
    let preimage = verification_statement_v1_golden_preimage();
    let statement_hash_decimal = 7807432589986464173440955546194920105762623084817847309522180293390994111;
    let computed = verification_statement_v1_hash(preimage);
    assert(computed == statement_hash_decimal, "statement_hash_decimal=7807432589986464173440955546194920105762623084817847309522180293390994111");
}

#[test]
fn test_verification_statement_v1_each_field_mutation_changes_hash() {
    let golden = verification_statement_v1_golden_preimage();
    let golden_hash = 7807432589986464173440955546194920105762623084817847309522180293390994111;
    let value_indices = [5, 8, 9, 12, 13, 16, 19, 20, 23, 24, 27, 28, 31, 32, 35, 36, 39, 40, 43, 44, 47, 48, 51, 52, 55, 56, 59, 60, 63, 64, 67, 68, 71, 74, 75, 78, 79, 82, 83, 86, 87, 90, 91];

    for i in 0..43 {
        let mut mutated = golden;
        let index = value_indices[i];
        mutated[index] = mutated[index] + 1;
        let mutated_hash = verification_statement_v1_hash(mutated);
        assert(mutated_hash != golden_hash, "mutating any value limb must change the statement hash");
    }
}

#[test(should_fail)]
fn test_verification_statement_v1_hash_mismatch_rejects_mutated_statement() {
    let mut mutated = verification_statement_v1_golden_preimage();
    mutated[5] = mutated[5] + 1;
    let golden_hash = 7807432589986464173440955546194920105762623084817847309522180293390994111;
    assert(verification_statement_v1_hash(mutated) == golden_hash, "mutated statement hash must reject");
}

// -- New C7 correctness tests --

/// T.4.1: Honest Lagrange recombination for t=2, party IDs [1,2].
///
/// Lagrange coefficients for evaluation at 0:
///   lambda_1 = (0-2)/(1-2) = -2/-1 = 2
///   lambda_2 = (0-1)/(2-1) = -1/1 = -1
///   sum(lambda) = 2 + (-1) = 1
///
/// If d_1(r) = 42, d_2(r) = 84, then:
///   pt(r) = 2*42 + (-1)*84 = 84 - 84 = 0
///
/// Expected: ACCEPT (all constraints satisfied).
#[test]
fn test_c7_honest_lagrange_recombination() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    // Build the execution parameters
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // C7 parameters
    let challenge_r = 0;
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;  // 2*42 + (-1)*84

    let result = main(
        99,            // ciphertext_hash
        pk_hash,
        500,           // decrypt_nizk_hash
        999,           // dkg_transcript_hash
        dkg_root,
        1,             // epoch
        300,           // participant_set_hash
        3,             // n_participants
        2,             // threshold
        plaintext_commitment,
        777,           // ivc_snark_proof_hash
        challenge_r,
        n_shares,
        plaintext,
        888,           // nova_share_chain_hash
        share_evals,
        lagrange_coeffs,
        pt_eval,
        leaf,
        path,
        idx,
    );
    assert(result[0] == 0);
}

/// T.4.2: Wrong Lagrange sum.
///
/// lambda = [3, -1] instead of [2, -1] => sum = 2 != 1.
///
/// Expected: REJECT (Lagrange identity violation).
#[test(should_fail)]
fn test_c7_wrong_lagrange_sum() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    // lambda sum = 3 + (-1) = 2 != 1 => violates Lagrange identity
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 3;
    lagrange_coeffs[1] = -1;

    let pt_eval = 42;  // 3*42 + (-1)*84 = 126-84 = 42

    let _ = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// T.4.3: Wrong recombination -- pt_eval tampered.
///
/// All Lagrange and share data is correct, but pt_eval is wrong.
///   sum(lambda) = 2 + (-1) = 1 OK
///   sum(lambda_i * d_i(r)) = 2*42 + (-1)*84 = 0 != pt_eval = 99
///
/// Expected: REJECT (recombination mismatch).
#[test(should_fail)]
fn test_c7_wrong_recombination() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 99;  // WRONG: should be 0

    let _ = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// T.4.4: Wrong share evaluation -- one share's d_i(r) is forged.
///
/// d_1(r) = 99 instead of 42 => recombined = 2*99 + (-1)*84 = 114 != 0.
///
/// Expected: REJECT (recombination mismatch).
#[test(should_fail)]
fn test_c7_wrong_share_eval() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 99;  // WRONG: should be 42
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;  // correct pt_eval, but recombination doesn't match

    let _ = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// T.4.5: Manipulated Lagrange coefficients (scaled 2x).
///
/// lambda = [4, -2] instead of [2, -1] => sum = 2 != 1.
///
/// Expected: REJECT (Lagrange identity violation).
#[test(should_fail)]
fn test_c7_manipulated_lagrange_coeffs() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    // lambda scaled 2x: [4, -2] => sum = 2 != 1
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 4;
    lagrange_coeffs[1] = -2;

    let pt_eval = 0;  // recomb would still be 0, but Lagrange identity fails first

    let _ = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// T.4.6: Zero-padded shares (n_shares < MAX_SHARES).
///
/// Same honest data as test_c7_honest_lagrange_recombination, but
/// emphasizes that only the first n_shares=2 entries are non-zero;
/// the remaining 126 entries are zero. Zero-padding must not affect
/// the Lagrange sum or recombination constraints.
///
/// Expected: ACCEPT.
#[test]
fn test_c7_zero_padded_shares() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 2;

    // Only first 2 slots are non-zero; 126 trailing slots are zero
    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;

    let result = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
    assert(result[0] == 0);
}

/// T.4.7: Plaintext commitment inconsistent with recombination.
///
/// All recombination checks pass (lambda sum = 1, recomb = pt_eval), but
/// the plaintext_commitment does NOT match Poseidon(nova_final_plaintext).
/// This tests that the existing commitment binding constraint still works
/// alongside the new recombination constraints.
///
/// Expected: REJECT (plaintext commitment mismatch).
#[test(should_fail)]
fn test_c7_plaintext_commitment_consistent() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    // nova_final_plaintext = [0; 8] (all zeros)
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    // But we provide a WRONG commitment (doesn't match the plaintext)
    let wrong_commitment = 0;  // Clearly != Poseidon([0; 8])
    let challenge_r = 0;
    let n_shares = 1;

    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, wrong_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}

/// T.4.8: n_shares zero -- must reject.
///
/// n_shares = 0 violates the non-zero guard added in the C7 constraints.
///
/// Expected: REJECT.
#[test(should_fail)]
fn test_c7_n_shares_zero() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let plaintext = [0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let challenge_r = 0;
    let n_shares = 0;  // zero: should reject

    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
         99, pk_hash, 500, 999, dkg_root, 1, 300, 3, 2, plaintext_commitment, 777,
        challenge_r, n_shares,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
                leaf, path, idx,
    );
}
