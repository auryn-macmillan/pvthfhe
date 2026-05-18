// decrypt_share: Verifies a single party's R3 partial-decryption share.
//
// Replaces rolling_digest (non-CRH) with Poseidon (collision-resistant)
// using domain-separation tags. Q is bound to protocol_constants::Q.

use poseidon;
use protocol_constants;

global N: u32 = 8;
global LOG_N: u32 = 3;
global B_E: u32 = 16;

fn vector_hash<let M: u32>(values: [Field; M], domain_tag: Field) -> Field {
    let mut preimage = [0; M + 1];
    preimage[0] = domain_tag;
    for i in 0..M {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::sponge(preimage)
}

fn bind_8_with_domain(values: [Field; 8], domain_tag: Field) -> Field {
    let mut preimage = [0; 9];
    preimage[0] = domain_tag;
    for i in 0..8 {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::hash_9(preimage)
}

fn eval_poly(coeffs: [Field; N], r: Field) -> Field {
    let mut result = 0;
    for i in 0..N {
        result = result * r + coeffs[N - 1 - i];
    }
    result
}

fn r_pow_n(r: Field) -> Field {
    let mut result = r;
    for _ in 0..LOG_N {
        result = result * result;
    }
    result
}

fn statement_hash(
    party_id: Field, pk_i_hash: Field, dkg_root: Field,
    ciphertext_hash: Field, epoch: Field, c1_hash: Field, d_i_hash: Field,
) -> Field {
    bind_8_with_domain([
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
        N as Field + B_E as Field,
    ], protocol_constants::DOMAIN_STATEMENT_BINDING)
}

fn ciphertext_binding(
    party_id: Field, pk_i_hash: Field, dkg_root: Field, epoch: Field, c1_hash: Field,
) -> Field {
    bind_8_with_domain([
        party_id, pk_i_hash, dkg_root, epoch, c1_hash, 1, 2, 3,
    ], protocol_constants::DOMAIN_CIPHERTEXT_BINDING)
}

fn dkg_binding(party_id: Field, pk_i_hash: Field, epoch: Field, c1_hash: Field) -> Field {
    bind_8_with_domain([
        party_id, pk_i_hash, epoch, c1_hash, N as Field, B_E as Field, 11, 19,
    ], protocol_constants::DOMAIN_DKG_BINDING)
}

fn main(
    party_id: pub Field, pk_i_hash: pub Field, dkg_root: pub Field,
    ciphertext_hash: pub Field, epoch: pub Field, c1_hash: pub Field,
    d_i_hash: pub Field, compact_statement_hash: pub Field,
    sk_i: [Field; N], e_i: [Field; N], c1: [Field; N], d_i: [Field; N],
    z_q: Field,
) {
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(party_id != 0, "party_id must be non-zero");
    for i in 0..N {
        let sk = sk_i[i];
        assert(sk * (sk - 1) * (sk + 1) == 0, "sk_i must be in {-1, 0, 1}");
    }
    for i in 0..N {
        let err = e_i[i];
        let err_u32 = err as u32;
        if err_u32 > B_E {
            let neg_err_u32 = (-err) as u32;
            assert(neg_err_u32 <= B_E, "error coefficient exceeds signed bound");
        }
    }
    let computed_pk_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(computed_pk_hash == pk_i_hash, "pk_i hash mismatch");
    let computed_c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(computed_c1_hash == c1_hash, "c1 hash mismatch");
    let computed_dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    assert(computed_dkg_root == dkg_root, "dkg_root binding mismatch");
    let computed_ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    assert(computed_ciphertext_hash == ciphertext_hash, "ciphertext binding mismatch");
    let computed_d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(computed_d_i_hash == d_i_hash, "d_i hash mismatch");
    let computed_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    assert(computed_statement_hash == compact_statement_hash, "statement hash mismatch");
    let r = bind_8_with_domain([
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
        compact_statement_hash,
    ], protocol_constants::DOMAIN_CHALLENGE_DERIVE);
    let lhs = eval_poly(d_i, r);
    let rhs = eval_poly(c1, r) * eval_poly(sk_i, r) + eval_poly(e_i, r);
    let r_to_n_plus_one = r_pow_n(r) + 1;
    assert(r_to_n_plus_one != 0, "r^n+1 must be non-zero");
    assert(rhs - lhs == protocol_constants::Q * z_q, "R3 partial-decrypt relation violation");
}

// --- Tests ---

#[test]
fn test_honest_r3_decryption() {
    let party_id = 1; let epoch = 1;
    let sk_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;
    let pk_i_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_collision_different_vectors() {
    let a = [1, 0, 0, 0, 0, 0, 0, 0];
    let b = [2, 0, 0, 0, 0, 0, 0, 0];
    let ha = vector_hash(a, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let hb = vector_hash(b, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(ha == hb, "hash collision found");
}

#[test(should_fail)]
fn test_tamper_sk_out_of_range() {
    let party_id = 1; let epoch = 1;
    let sk_i = [2, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [5, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;
    let pk_i_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_tamper_error_out_of_bound() {
    let party_id = 1; let epoch = 1;
    let sk_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [17, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;
    let pk_i_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_tamper_r3_relation_violation() {
    let party_id = 1; let epoch = 1;
    let sk_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [0, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;
    let pk_i_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_tamper_wrong_z_q() {
    let party_id = 1; let epoch = 1;
    let sk_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 1;
    let pk_i_hash = vector_hash(sk_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_tamper_hash_mismatch() {
    let party_id = 1; let epoch = 1;
    let sk_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let e_i = [1, 0, 0, 0, 0, 0, 0, 0];
    let c1 = [2, 0, 0, 0, 0, 0, 0, 0];
    let d_i = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;
    let pk_i_hash = 99999;
    let c1_hash = vector_hash(c1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let d_i_hash = vector_hash(d_i, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    let ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    let compact_statement_hash = statement_hash(
        party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, c1_hash, d_i_hash,
    );
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch,
        c1_hash, d_i_hash, compact_statement_hash, sk_i, e_i, c1, d_i, z_q);
}

#[test(should_fail)]
fn test_tamper_collision_domain_tag() {
    let values = [1, 2, 3, 4, 5, 6, 7, 8];
    let h1 = bind_8_with_domain(values, protocol_constants::DOMAIN_STATEMENT_BINDING);
    let h2 = bind_8_with_domain(values, protocol_constants::DOMAIN_CHALLENGE_DERIVE);
    assert(h1 == h2, "cross-domain collision detected");
}
