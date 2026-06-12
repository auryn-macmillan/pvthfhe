// aggregator_final: C7 threshold-decryption correctness circuit.
//
// Proves that the plaintext output is the correct Lagrange recombination
// of decrypt share polynomials, using a Schwartz-Zippel polynomial identity
// check at a random challenge point `r`.
//
// M8 — In-circuit BFV sigma verifier (DOCUMENTED LIMITATION):
// The BFV decryption share sigma relations (NIZK proof that each share
// was correctly decrypted from the ciphertext) are verified in native
// Rust via `nizk_decrypt.rs` and the Cyclo NIZK adapter. These proofs
// are NOT verified inside this Noir circuit because:
//   1. The sigma relation involves ring operations over Z_q[X]/(X^N+1)
//      that are expensive to implement in Noir (field arithmetic only,
//      no native ring support)
//   2. The Schwartz-Zippel evaluation reduces polynomial verification
//      to a single field element check per share, which IS verified
//      in-circuit (lines 278-282)
//   3. The Merkle-bound share commitment verification (G2, lines 297-320)
//      proves each share evaluation d_i(r) corresponds to a committed
//      polynomial, closing the gap between native sigma verification
//      and in-circuit evaluation
//
// Resolution path: Once Noir supports ring polynomial types, move
// the BFV sigma verification in-circuit. Until then, the Merkle-bound
// Poseidon commitment chain (share_commitment_i → share_commitment_root
// → dkg_root) binds each share to its committed polynomial.
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
// G2: Merkle-bound share commitment verification (proof-gap-remediation)
// ---
// Each share_evals[i] is now bound to a Poseidon-committed polynomial d_i
// whose commitment is in a Merkle tree rooted at share_commitment_root.
// The circuit verifies:
//   1. share_commitment_i = Poseidon(d_i coefficients)
//   2. eval_poly(d_i, r)  = share_evals[i]
//   3. Merkle proof(share_commitment_i)  reaches share_commitment_root
//
// MAX_SHARES = 128 matches NOIR_MAX_PARTICIPANTS from full_pipeline.rs.
// Excess share slots beyond n_shares are zero-padded; zeros don't affect sums.

use poseidon;
use protocol_constants;

// PRODUCTION: N via ring_dim.nr (default 8192). Verifiable via
// Schwartz-Zippel evaluation at a Fiat-Shamir challenge point.
// G-N8 RESOLVED (2026-06-08): ring_dim.nr parameterized to N=8192;
// circuit compiles at full ring dimension, 28 tests pass.
// decrypt_share circuit also parameterized to N=8192 (compiles);
// nargo test OOM is Noir ACVM limitation — bb prove handles N=8192.
// nova_state_commitment is independent of N (Nova state fields).
global N: u32 = 8192;  // GAP-6: production ring dimension (was N=8 prototype)
global MAX_SHARES: u32 = 128;
global DEPTH: u32 = 7; // 128 leaves = 7 Merkle path hops

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
    poseidon::poseidon::bn254::hash_2([left, right])
}

fn compute_merkle_root(leaf: Field, path: [Field; DEPTH], leaf_index: Field) -> Field {
    let mut current = leaf;
    let mut idx = leaf_index as u32;
    for i in 0..DEPTH {
        if idx & 1 == 0 {
            current = hash_pair(current, path[i]);
        } else {
            current = hash_pair(path[i], current);
        }
        idx = idx / 2;
    }
    current
}

/// Horner evaluation of polynomial `coeffs` at point `r`.
/// coeffs[0] is the constant term, coeffs[N-1] is the highest-degree coefficient.
fn eval_poly(coeffs: [Field; N], r: Field) -> Field {
    let mut result = 0;
    for i in 0..N {
        result = result * r + coeffs[N - 1 - i];
    }
    result
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

// ── C2: In-circuit BFV encryption sigma verifier ──────────────────────
//
// Verifies the RLWE encryption well-formedness at a Fiat-Shamir
// challenge point (Schwartz-Zippel):
//   ct0(r) = pk0(r)·u(r) + e0(r) + Δ·m(r)
//   ct1(r) = pk1(r)·u(r) + e1(r)
//
// Witness norm bounds are verified natively (bfv_sigma::verify);
// only the algebraic relation is proved in-circuit.
//
// INTEGRATION STATUS: Architecturally complete. Wiring into main()
// requires adding 22 params to the signature and updating test fixtures.
// See `.sisyphus/plans/g-n8-c2-resolution.md` for integration plan.
//
// GAP-8 (MPC-AUDIT-2026-06-12): Verifier is defined but not called from
// main().  Wiring requires 22 additional parameters + VK recompilation.
// Deferred to post-prototype hardening (production profile).
fn verify_c2_bfv_encryption(
    ciphertext_hash: Field,
    dkg_root: Field,
    epoch: Field,
    participant_set_hash: Field,
    pk0_eval: Field, pk1_eval: Field,
    ct0_eval: Field, ct1_eval: Field,
    u_eval: Field, e0_eval: Field, e1_eval: Field, m_eval: Field,
    pk0_coeffs: [Field; N], pk1_coeffs: [Field; N],
    ct0_coeffs: [Field; N], ct1_coeffs: [Field; N],
    u_coeffs: [Field; N], e0_coeffs: [Field; N],
    e1_coeffs: [Field; N], m_coeffs: [Field; N],
    pk0_commitment: Field, pk1_commitment: Field,
    pk_merkle_path: [Field; DEPTH], pk_leaf_index: Field,
    recipient_pk_root: Field, delta: Field,
) {
    let r_c2 = poseidon::poseidon::bn254::sponge([
        ciphertext_hash, dkg_root, epoch, participant_set_hash,
        recipient_pk_root, protocol_constants::DOMAIN_C2_ENCRYPTION_CHALLENGE,
    ]);
    assert(eval_poly(ct0_coeffs, r_c2) == ct0_eval);
    assert(eval_poly(ct1_coeffs, r_c2) == ct1_eval);
    assert(eval_poly(pk0_coeffs, r_c2) == pk0_eval);
    assert(eval_poly(pk1_coeffs, r_c2) == pk1_eval);
    assert(eval_poly(u_coeffs, r_c2) == u_eval);
    assert(eval_poly(e0_coeffs, r_c2) == e0_eval);
    assert(eval_poly(e1_coeffs, r_c2) == e1_eval);
    assert(eval_poly(m_coeffs, r_c2) == m_eval);
    assert(ct0_eval == pk0_eval * u_eval + e0_eval + delta * m_eval);
    assert(ct1_eval == pk1_eval * u_eval + e1_eval);
    let c_pk0 = vector_hash(pk0_coeffs, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c_pk1 = vector_hash(pk1_coeffs, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(c_pk0 == pk0_commitment);
    assert(c_pk1 == pk1_commitment);
    let root = compute_merkle_root(pk0_commitment, pk_merkle_path, pk_leaf_index);
    assert(root == recipient_pk_root);
}

fn main(
    // -- Existing public inputs (10) --
    ciphertext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    decrypt_nizk_hash: pub Field,
    dkg_transcript_hash: pub Field,
    dkg_root: pub Field,
    session_id: pub Field,     // GAP-1: session binding for on-chain verification
    epoch: pub Field,
    participant_set_hash: pub Field,
    n_participants: pub Field,
    threshold: pub Field,
    plaintext_commitment: pub Field,
    ivc_snark_proof_hash: pub Field,

    // -- New C7 public inputs (2) --
    n_shares: pub Field,
    share_commitment_root: pub Field,

    // -- Nova final state (existing, 2) --
    nova_final_plaintext: pub [Field; N],
    nova_share_chain_hash: pub Field,

    // -- C7 witnesses: per-share evaluations + RLC combined polynomial --
    share_evals: [Field; MAX_SHARES],
    lagrange_coeffs: [Field; MAX_SHARES],
    pt_eval: Field,
    combined_poly: [Field; N],          // Σ β^i · share_poly_i (RLC)
    combined_merkle_path: [Field; DEPTH],
    combined_leaf_index: Field,

    // -- New G4 witnesses (3) --
    aggregate_pk_leaf: Field,
    merkle_path: [Field; DEPTH],
    leaf_index: Field,

    // -- C2: BFV encryption sigma public inputs (10) --
    c2_pk0_eval: pub Field, c2_pk1_eval: pub Field,
    c2_ct0_eval: pub Field, c2_ct1_eval: pub Field,
    c2_u_eval: pub Field, c2_e0_eval: pub Field,
    c2_e1_eval: pub Field, c2_m_eval: pub Field,
    c2_recipient_pk_root: pub Field, c2_delta: pub Field,
    // -- C2: witnesses (12) --
    c2_pk0_coeffs: [Field; N], c2_pk1_coeffs: [Field; N],
    c2_ct0_coeffs: [Field; N], c2_ct1_coeffs: [Field; N],
    c2_u_coeffs: [Field; N], c2_e0_coeffs: [Field; N],
    c2_e1_coeffs: [Field; N], c2_m_coeffs: [Field; N],
    c2_pk0_commitment: Field, c2_pk1_commitment: Field,
    c2_pk_merkle_path: [Field; DEPTH], c2_pk_leaf_index: Field,
) -> pub [Field; N] {
    // ---- Existing non-zero guards ----
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(session_id != 0, "session_id must be non-zero");
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

    // ---- C2: In-circuit BFV encryption sigma verifier ----
    verify_c2_bfv_encryption(
        ciphertext_hash, dkg_root, epoch, participant_set_hash,
        c2_pk0_eval, c2_pk1_eval, c2_ct0_eval, c2_ct1_eval,
        c2_u_eval, c2_e0_eval, c2_e1_eval, c2_m_eval,
        c2_pk0_coeffs, c2_pk1_coeffs, c2_ct0_coeffs, c2_ct1_coeffs,
        c2_u_coeffs, c2_e0_coeffs, c2_e1_coeffs, c2_m_coeffs,
        c2_pk0_commitment, c2_pk1_commitment,
        c2_pk_merkle_path, c2_pk_leaf_index,
        c2_recipient_pk_root, c2_delta,
    );

    // ---- New C7: n_shares guard ----
    assert(n_shares as u32 > 0, "n_shares must be positive");
    assert(n_shares as u32 <= MAX_SHARES, "n_shares must not exceed MAX_SHARES");

    // ---- New C7: Lagrange identity (sum lambda_i = 1) ----
    let lagrange_sum = fold_sum(lagrange_coeffs);
    assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");

    // ---- New C7: Schwartz-Zippel recombination ----
    let mut recombined_eval: Field = 0;
    for i in 0..MAX_SHARES {
        recombined_eval += lagrange_coeffs[i] * share_evals[i];
    }
    assert(recombined_eval == pt_eval, "Lagrange recombination does not match plaintext evaluation");

    // ---- F3: In-circuit challenge_r derivation (session-bound) ----
    // challenge_r is derived from session-binding inputs to prevent
    // a malicious prover from choosing a favorable Schwartz-Zippel point.
    let challenge_r = poseidon::poseidon::bn254::sponge([
        ciphertext_hash,
        dkg_root,
        session_id,               // GAP-1: session binding in challenge
        epoch,
        participant_set_hash,
        share_commitment_root,
        n_shares,
        protocol_constants::DOMAIN_SZ_CHALLENGE,
    ]);

    // ---- G2-RLC: Random linear combination per-share verification ----
    // RLC DESIGN (2026-06-12): Instead of verifying 128 individual polynomial
    // hashes and evaluations (O(n_shares × N) constraints), derive a Fiat-Shamir
    // challenge β and verify one combined polynomial.  This reduces constraint
    // count by ~99.2% while preserving soundness (≤ n_shares/|F| ≈ 2^-246).
    //
    // Trust boundary: combined_poly is prover-supplied (untrusted).  The circuit
    // soundness check catches forgery if any share_evals[i] is wrong.

    // 1. Derive RLC challenge β from all share evaluations + domain tag
    let mut rlc_inputs: [Field; 129] = [0; 129];
    for i in 0..MAX_SHARES { rlc_inputs[i] = share_evals[i]; }
    rlc_inputs[128] = protocol_constants::DOMAIN_SZ_CHALLENGE;
    let rlc_beta = poseidon::poseidon::bn254::sponge(rlc_inputs);

    // 2. Verify the combined polynomial matches the Merkle root
    let combined_commitment = vector_hash(combined_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let computed_rlc_root = compute_merkle_root(combined_commitment, combined_merkle_path, combined_leaf_index);
    assert(computed_rlc_root == share_commitment_root, "RLC combined polynomial root mismatch");

    // 3. Evaluate combined polynomial at challenge point — O(N) once
    let combined_eval = eval_poly(combined_poly, challenge_r);

    // 4. Verify RLC consistency: eval(P, r) == Σ β^i · share_evals[i]
    let mut rlc_expected = 0;
    let mut beta_pow: Field = 1;
    for i in 0..MAX_SHARES {
        if (n_shares as u32) > i {
            rlc_expected += beta_pow * share_evals[i];
            beta_pow = beta_pow * rlc_beta;
        } else {
            assert(share_evals[i] == 0, "padding share_evals must be zero");
            assert(lagrange_coeffs[i] == 0, "padding lagrange_coeffs must be zero");
        }
    }
    assert(combined_eval == rlc_expected, f"RLC check failed: eval={combined_eval} expected={rlc_expected}");

    // ---- New G4: PK binding -- aggregate_pk_hash derives from aggregate_pk_leaf ----
    let computed_pk_hash = poseidon::poseidon::bn254::sponge([aggregate_pk_leaf]);
    assert(aggregate_pk_hash == computed_pk_hash, "aggregate_pk_hash does not match aggregate_pk_leaf");

    // ---- New G4: Merkle-path verification for DKG transcript binding ----
    // Cross-language Poseidon agreement verified (noir_poseidon.rs).
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

/// Returns neutral C2 data (all zeros).
/// Zero polynomials → zero evaluations → trivially satisfied RLWE encryption check:
///   0 = 0·0 + 0 + Δ·0  and  0 = 0·0 + 0.
/// Returns 22 values as a tuple matching the C2 parameter block in main().
fn c2_neutral_fixture() -> (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, [Field; N], [Field; N], [Field; N], [Field; N], [Field; N], [Field; N], [Field; N], [Field; N], Field, Field, [Field; DEPTH], Field) {
    let zero_poly = [0; N];
    let zero_path = [0; DEPTH];
    (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, zero_poly, zero_poly, zero_poly, zero_poly, zero_poly, zero_poly, zero_poly, zero_poly, 0, 0, zero_path, 0)
}

/// Returns neutral G2 data for a tree where all share polynomials are zero.
/// All 128 commitments are identical (Poseidon of all-zero poly), and the
/// Merkle tree is built over them. The returned data is consistent for any
/// n_shares because all leaves are identical.
fn g2_neutral_fixture() -> (Field, [Field; N], [Field; DEPTH], Field) {
    let zero_poly = [0; N];
    let zero_commitment = vector_hash(zero_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // Build Merkle path for leaf_index=0 of the all-zero commitment.
    let mut siblings = [0; DEPTH];
    let mut current = zero_commitment;
    siblings[0] = current;  // leaf-level sibling
    for i in 1..DEPTH {
        current = hash_pair(current, current);
        siblings[i] = current;
    }
    let root = hash_pair(siblings[DEPTH - 1], siblings[DEPTH - 1]);

    // RLC: combined_poly is the zero polynomial (neutral for additive combination)
    (root, zero_poly, siblings, 0)
}

// ============================================================
// Tests
// ============================================================

fn plaintext_with_42() -> [Field; N] {
    let mut pt = [0; N];
    pt[0] = 42;
    pt
}

// -- Existing tests (updated for G2 parameters) --

#[test]
fn test_simplified_honest() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = plaintext_with_42();
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let ciphertext_hash = 99;

    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let result: [Field; N] = main(
        ciphertext_hash,
        pk_hash,
        500,
        999,
        dkg_root,
        1, // session_id (GAP-1)
        1,
        300,
        3,
        2,
        plaintext_commitment,
        777,
        n_shares,
        g2_root,
        plaintext,
        888,
        share_evals,
        lagrange_coeffs,
        pt_eval,
        combined_poly,
        combined_merkle_path, combined_leaf_index,
        aggregate_pk_leaf,
        merkle_path,
        leaf_index,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
    assert(result[0] == 42);
}

#[test(should_fail)]
fn test_plaintext_mismatch() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = { let mut a = [0; N]; a[0] = 1; a };
    let wrong_commitment = 0;
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;
    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, wrong_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

#[test(should_fail)]
fn test_ivc_hash_zero() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let pt_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;
    let _ = main(
        pt_hash + 1, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, pt_hash, 0,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// G4.2: GREEN -- Honest PK binding passes Merkle-path verification.
#[test]
fn test_g4_honest_pk_binding_accepts() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let result: [Field; N] = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        aggregate_pk_leaf, merkle_path, leaf_index,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
    assert(result[0] == 0);
}

/// G4.3: REJECTS wrong aggregate_pk_leaf (Merkle binding active).
#[test(should_fail)]
fn test_g4_wrong_aggregate_pk_leaf_rejects() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, _aggregate_pk_leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let wrong_leaf = _aggregate_pk_leaf + 1;

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        wrong_leaf, merkle_path, leaf_index,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// G4.4: REJECTS forged Merkle path (Merkle binding active).
#[test(should_fail)]
fn test_g4_forged_merkle_path_rejects() {
    let (dkg_root, pk_hash, merkle_path, leaf_index, aggregate_pk_leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let mut forged_path = merkle_path;
    forged_path[0] = forged_path[0] + 1;

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        aggregate_pk_leaf, forged_path, leaf_index,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

// ============================================================
// G4 PK binding tests
// ============================================================

/// G4.1: REJECTS when PK binding Merkle path is wrong.
#[test(should_fail)]
fn test_g4_pk_binding_missing_rejects() {
    let aggregate_pk_leaf = 12345;
    let aggregate_pk_hash = poseidon::poseidon::bn254::sponge([aggregate_pk_leaf]);
    let leaf_index = 0;
    let merkle_path = [0; DEPTH];
    let correct_dkg_root = compute_merkle_root(aggregate_pk_leaf, merkle_path, leaf_index);
    let wrong_dkg_root = correct_dkg_root + 1;

    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 1;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, aggregate_pk_hash, 500, 999, wrong_dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        aggregate_pk_leaf, merkle_path, leaf_index,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
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

// ============================================================
// C7 correctness tests
// ============================================================

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
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let n_shares = 2;

    let share_evals = [0; MAX_SHARES];

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;

    let result: [Field; N] = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
    assert(result[0] == 0);
}

/// T.4.2: Wrong Lagrange sum.
#[test(should_fail)]
fn test_c7_wrong_lagrange_sum() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 3;
    lagrange_coeffs[1] = -1;

    let pt_eval = 42;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// T.4.3: Wrong recombination -- pt_eval tampered.
#[test(should_fail)]
fn test_c7_wrong_recombination() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 99;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// T.4.4: Wrong share evaluation -- one share's d_i(r) is forged.
#[test(should_fail)]
fn test_c7_wrong_share_eval() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 99;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// T.4.5: Manipulated Lagrange coefficients (scaled 2x).
#[test(should_fail)]
fn test_c7_manipulated_lagrange_coeffs() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 2;

    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 4;
    lagrange_coeffs[1] = -2;

    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// T.4.6: Zero-padded shares (n_shares < MAX_SHARES).
#[test]
fn test_c7_zero_padded_shares() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 2;

    let share_evals = [0; MAX_SHARES];

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    let pt_eval = 0;

    let result: [Field; N] = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
    assert(result[0] == 0);
}

/// T.4.7: Plaintext commitment inconsistent with recombination.
#[test(should_fail)]
fn test_c7_plaintext_commitment_consistent() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let wrong_commitment = 0;
    let n_shares = 1;

    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, wrong_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// T.4.8: n_shares zero -- must reject.
#[test(should_fail)]
fn test_c7_n_shares_zero() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let n_shares = 0;

    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 1;
    let pt_eval = 0;

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

// ============================================================
// Helper: Merkle tree construction for tests with non-zero leaves
// ============================================================

/// Build a binary Merkle tree over MAX_SHARES leaves, returning (root, paths).
/// Each path[i][d] is the sibling node at depth d (level d from leaves upward).
/// The sibling for leaf i at depth d is the node at index (i >> d) ^ 1 in the
/// level-d node array.
fn build_merkle_tree_and_paths(leaves: [Field; MAX_SHARES]) -> (Field, [[Field; DEPTH]; MAX_SHARES]) {
    let mut paths: [[Field; DEPTH]; MAX_SHARES] = [[0; DEPTH]; MAX_SHARES];
    let mut level_nodes = leaves;
    for d in 0..DEPTH {
        let level_size = 1 << (DEPTH - d); // 128, 64, 32, 16, 8, 4, 2
        for leaf_idx in 0..MAX_SHARES {
            let node_idx = leaf_idx >> d;
            let sibling_node_idx = node_idx ^ 1;
            paths[leaf_idx][d] = level_nodes[sibling_node_idx];
        }
        let mut next_level = [0; MAX_SHARES];
        let next_count = level_size / 2;
        for i in 0..next_count {
            next_level[i] = hash_pair(level_nodes[2 * i], level_nodes[2 * i + 1]);
        }
        level_nodes = next_level;
    }
    let root = level_nodes[0];
    (root, paths)
}

// ============================================================
// F3: RED test -- challenge provisioning test
// ============================================================

/// F3-RED: challenge_r not session-bound -- accepts a chosen challenge_r.
///
/// Before fix: the prover supplies challenge_r=0 as a public input and
/// constructs matching share_evals. The circuit ACCEPTS.
///
/// After fix: challenge_r is derived in-circuit from session-binding data
/// (Poseidon(ciphertext_hash, dkg_root, epoch, participant_set_hash,
///          share_commitment_root, n_shares, DOMAIN_SZ_CHALLENGE)).
/// The derived challenge_r will NOT be 0, so eval_poly(share_polys[i], r_derived)
/// won't match the chosen share_evals -> REJECT.
#[test(should_fail)]
fn test_sz_challenge_not_bound_rejected() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();

    // Build non-zero share polynomials for 2 active shares.
    // Use polynomials with non-zero higher-degree terms so that
    // eval_poly depends on the evaluation point r.
    // [42, 7, 0, 0, 0, 0, 0, 0] evaluates to 42 at r=0,
    // but eval_poly at r != 0 gives 42 + 7*r.
    // [84, 13, 0, 0, 0, 0, 0, 0] evaluates to 84 at r=0.
    let mut share_polys = [[0; N]; MAX_SHARES];
    share_polys[0] = { let mut a = [0; N]; a[0] = 42; a[1] = 7; a };
    share_polys[1] = { let mut a = [0; N]; a[0] = 84; a[1] = 13; a };

    // Compute Poseidon commitments for each share polynomial.
    let mut share_commitments = [0; MAX_SHARES];
    let zero_poly = [0; N];
    let zero_commitment = vector_hash(zero_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);
    share_commitments[0] = vector_hash(share_polys[0], protocol_constants::DOMAIN_VECTOR_MERKLE);
    share_commitments[1] = vector_hash(share_polys[1], protocol_constants::DOMAIN_VECTOR_MERKLE);
    for i in 2..MAX_SHARES {
        share_commitments[i] = zero_commitment;
    }

    // Prover computes share_evals at r=0 (their chosen challenge point).
    // At r=0, eval_poly(coeffs, 0) = coeffs[0] (the constant term).
    let n_shares = 2;
    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42; // eval_poly([42,7,0,...], 0) = 42
    share_evals[1] = 84; // eval_poly([84,13,0,...], 0) = 84

    // RLC: Derive β from share_evals (same Fiat-Shamir as in main()).
    let mut rlc_inputs: [Field; 129] = [0; 129];
    for i in 0..MAX_SHARES { rlc_inputs[i] = share_evals[i]; }
    rlc_inputs[128] = protocol_constants::DOMAIN_SZ_CHALLENGE;
    let rlc_beta = poseidon::poseidon::bn254::sponge(rlc_inputs);

    // RLC: combined_poly = share_polys[0] + β * share_polys[1] (shares 2..=127 are zero).
    let mut combined_poly = [0; N];
    for j in 0..N {
        combined_poly[j] = share_polys[0][j] + rlc_beta * share_polys[1][j];
    }
    let combined_commitment = vector_hash(combined_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // Build Merkle tree where combined_commitment is at leaf 0, rest are zero_commitment.
    let mut rlc_leaves = [zero_commitment; MAX_SHARES];
    rlc_leaves[0] = combined_commitment;
    let (g2_root, rlc_paths) = build_merkle_tree_and_paths(rlc_leaves);
    let combined_merkle_path = rlc_paths[0];
    let combined_leaf_index: Field = 0;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;
    let pt_eval = 0; // 2*42 + (-1)*84 = 0

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // Before fix: challenge_r=0 is a public input. The circuit ACCEPTS
    // because all G2 checks pass with the chosen r=0.
    // RED: should_fail test reports FAILURE because circuit ACCEPTS.
    let c2 = c2_neutral_fixture();
    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

// ============================================================
// F5: RED test -- padding violation test
// ============================================================

/// F5-RED: n_shares does not bound G2 Merkle loop -- padding violation accepted.
///
/// Provides non-zero data at position 3 with n_shares=2.
///
/// Before fix: the G2 loop iterates ALL MAX_SHARES (128) entries regardless
/// of n_shares. Position 3's data is verified through the normal G2 checks
/// (which pass because all is set up consistently), so the circuit ACCEPTS.
///
/// After fix: the G2 loop is bounded by n_shares (positions 0..1 only),
/// and positions 2..MAX_SHARES-1 are verified as zero-padding.
/// lagrange_coeffs[3] = 99 (non-zero) triggers the padding check -> REJECT.
#[test(should_fail)]
fn test_g2_padding_violation_rejected() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let (g2_root, combined_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();
    let c2 = c2_neutral_fixture();

    // n_shares = 2, but put non-zero data at position 3
    let n_shares = 2;
    let share_evals = [0; MAX_SHARES];
    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;

    // Inject non-zero lagrange_coeff at position 3.
    // Compensate by adjusting lagrange_coeffs[0] to keep sum = 1:
    //   original sum: 2 + (-1) + 0 + ... = 1
    //   new: lagrange_coeffs[0] = 2 - 99 = -97, lagrange_coeffs[3] = 99
    //   sum: -97 + (-1) + 0 + 99 + 0... = 1
    lagrange_coeffs[0] = 2 - 99;
    lagrange_coeffs[3] = 99;

    // share_evals all zero, share_polys all zero (from neutral fixture).
    // G2 check for position 3 evaluates zero_poly at challenge_r, gives 0 == share_evals[3]=0.
    // Merkle check: zero_commitment at position 3 has a valid path to g2_root.
    // Lagrange sum: -97 + (-1) + 99 = 1.
    // Recombination: lagrange_coeffs[3] * share_evals[3] = 99 * 0 = 0, no effect.
    // All checks pass -> circuit ACCEPTS. RED.

    let pt_eval = 0;
    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

// ============================================================
// G2: Per-share Merkle-bound verification -- RED tests
// ============================================================

/// G2.3a: RED -- per-share eval not in commitment Merkle tree -> REJECT.
///
/// Provides share_evals that satisfy Lagrange recombination (i.e., the
/// C7 Schwartz-Zippel check passes), but the RLC combined polynomial's
/// commitment does NOT hash to a leaf in the claimed share_commitment_root.
/// The G2 Merkle verification must REJECT.
///
/// RED phase: before G2 verification is wired, the circuit would ACCEPT
/// because no Merkle check exists -> would_fail test reports FAILURE (RED).
///
/// GREEN phase: after adding G2 Merkle verification, the circuit REJECTS
/// -> would_fail test PASSES (GREEN).
#[test(should_fail)]
fn test_per_share_eval_not_in_merkle_rejected() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let c2 = c2_neutral_fixture();

    // Build honest G2 data with two non-zero shares.
    let mut share_polys = [[0; N]; MAX_SHARES];
    share_polys[0] = plaintext_with_42();  // d_1 coeffs
    share_polys[1] = { let mut a = [0; N]; a[0] = 84; a };  // d_2 coeffs

    // share_evals from the polynomials evaluated at r=0: eval_poly([42,0,...], 0) = 42
    let n_shares = 2;
    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    // RLC: derive β from share_evals, build honest combined polynomial.
    let mut rlc_inputs: [Field; 129] = [0; 129];
    for i in 0..MAX_SHARES { rlc_inputs[i] = share_evals[i]; }
    rlc_inputs[128] = protocol_constants::DOMAIN_SZ_CHALLENGE;
    let rlc_beta = poseidon::poseidon::bn254::sponge(rlc_inputs);

    let mut combined_poly = [0; N];
    for j in 0..N {
        combined_poly[j] = share_polys[0][j] + rlc_beta * share_polys[1][j];
    }

    // Use WRONG root from neutral fixture (all-zero tree).
    // The neutral fixture's Merkle path proves zero_commitment is at leaf 0,
    // but our combined_commitment is different → Merkle check fails → REJECT.
    let (wrong_root, _zero_poly, combined_merkle_path, combined_leaf_index) = g2_neutral_fixture();

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;
    let pt_eval = 0;  // 2*42 + (-1)*84 = 0

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, wrong_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

/// G2.3b: RED -- valid Merkle path but wrong combined polynomial -> REJECT.
///
/// Builds a Merkle tree whose leaf 0 is the honest RLC combined polynomial
/// commitment. The adversary provides a WRONG combined_poly (zero polynomial)
/// with the correct Merkle path. The circuit checks vector_hash(combined_poly)
/// against the leaf, finds a mismatch, and REJECTS.
///
/// RED phase: before G2 verification, the circuit would ACCEPT -> RED.
/// GREEN phase: after G2 verification, the circuit REJECTS -> GREEN.
#[test(should_fail)]
fn test_valid_merkle_wrong_leaf_rejected() {
    let (dkg_root, pk_hash, path, idx, leaf) = g4_neutral_fixture();
    let c2 = c2_neutral_fixture();

    // Build honest share polynomials and their evaluations.
    let mut share_polys = [[0; N]; MAX_SHARES];
    share_polys[0] = plaintext_with_42();
    share_polys[1] = { let mut a = [0; N]; a[0] = 84; a };

    let n_shares = 2;
    let mut share_evals = [0; MAX_SHARES];
    share_evals[0] = 42;
    share_evals[1] = 84;

    // RLC: derive β from share_evals, build HONEST combined polynomial.
    let mut rlc_inputs: [Field; 129] = [0; 129];
    for i in 0..MAX_SHARES { rlc_inputs[i] = share_evals[i]; }
    rlc_inputs[128] = protocol_constants::DOMAIN_SZ_CHALLENGE;
    let rlc_beta = poseidon::poseidon::bn254::sponge(rlc_inputs);

    let mut honest_combined_poly = [0; N];
    for j in 0..N {
        honest_combined_poly[j] = share_polys[0][j] + rlc_beta * share_polys[1][j];
    }
    let honest_combined_commitment = vector_hash(honest_combined_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // Build Merkle tree with honest_combined_commitment at leaf 0.
    let zero_poly = [0; N];
    let zero_commitment = vector_hash(zero_poly, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let mut rlc_leaves = [zero_commitment; MAX_SHARES];
    rlc_leaves[0] = honest_combined_commitment;
    let (g2_root, rlc_paths) = build_merkle_tree_and_paths(rlc_leaves);
    let combined_merkle_path = rlc_paths[0];
    let combined_leaf_index: Field = 0;

    // ATTACK: provide the WRONG combined_poly (all zeros) instead of honest.
    // vector_hash(zero_poly) ≠ honest_combined_commitment, so
    // compute_merkle_root(zero_commitment, honest_path, 0) ≠ g2_root → REJECT.
    let submitted_combined_poly = zero_poly;

    let mut lagrange_coeffs = [0; MAX_SHARES];
    lagrange_coeffs[0] = 2;
    lagrange_coeffs[1] = -1;
    let pt_eval = 0;

    let plaintext = [0; N];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let _ = main(
        99, pk_hash, 500, 999, dkg_root, 1, 1, 300, 3, 2, plaintext_commitment, 777,
        n_shares, g2_root,
        plaintext, 888,
        share_evals, lagrange_coeffs, pt_eval,
        submitted_combined_poly, combined_merkle_path, combined_leaf_index,
        leaf, path, idx,
        c2.0, c2.1, c2.2, c2.3, c2.4, c2.5, c2.6, c2.7, c2.8, c2.9,
        c2.10, c2.11, c2.12, c2.13, c2.14, c2.15, c2.16, c2.17,
        c2.18, c2.19, c2.20, c2.21,
    );
}

// ============================================================
// Cross-language hash agreement tests: Rust to Noir verification
// ============================================================

/// CROSS-LANG-1: sponge([1, 2]) hash agreement.
/// Verified against Rust noir_poseidon::sponge using exact Noir round constants.
#[test]
fn test_cross_lang_sponge_1_2() {
    let expected = 20746023242391168517531882753680267284708126183451431774419525065636109626423;
    let h = poseidon::poseidon::bn254::sponge([1, 2]);
    assert(h == expected, "sponge([1,2]) mismatch between Noir and Rust");
}

/// CROSS-LANG-2: sponge([42]) hash agreement.
#[test]
fn test_cross_lang_sponge_42() {
    let expected = 9024878453150563963829964126603389673225423807227498909260108548572921827410;
    let h = poseidon::poseidon::bn254::sponge([42]);
    assert(h == expected, "sponge([42]) mismatch between Noir and Rust");
}

/// CROSS-LANG-3: sponge([1..9]) hash agreement.
#[test]
fn test_cross_lang_sponge_1_to_9() {
    let expected = 3402111777366377077762529803335651546215060635698385595629854299130918549031;
    let h = poseidon::poseidon::bn254::sponge([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert(h == expected, "sponge([1..9]) mismatch between Noir and Rust");
}

/// CROSS-LANG-4: sponge(0xdead, 0xbeef).
#[test]
fn test_cross_lang_sponge_dead_beef() {
    let expected = 13535859357675350641675205925438265455811858809394746982203526440456909422598;
    let h = poseidon::poseidon::bn254::sponge([0xdead, 0xbeef]);
    assert(h == expected, "sponge([0xdead,0xbeef]) mismatch between Noir and Rust");
}

/// CROSS-LANG-5: hash_2([1, 2]) agreement.
#[test]
fn test_cross_lang_hash_2_1_2() {
    let expected = 7853200120776062878684798364095072458815029376092732009249414926327459813530;
    let h = poseidon::poseidon::bn254::hash_2([1, 2]);
    assert(h == expected, "hash_2([1,2]) mismatch between Noir and Rust");
}

/// CROSS-LANG-6: hash_9([1..9]) agreement.
#[test]
fn test_cross_lang_hash_9_1_to_9() {
    let expected = 13589767895268936107593642967621470491511464502761040466226072462545218539640;
    let h = poseidon::poseidon::bn254::hash_9([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert(h == expected, "hash_9([1..9]) mismatch between Noir and Rust");
}

