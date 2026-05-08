global N: u32 = 8192;
global LOG_N: u32 = 13;
global B_E: u32 = 16;

global DIGEST_BASE: Field = 131;
global DIGEST_DOMAIN: Field = 987654321;

fn rolling_digest(values: [Field; N]) -> Field {
    let mut acc = DIGEST_DOMAIN;
    let mut factor = 1;

    for i in 0..N {
        acc = acc + values[i] * factor;
        factor = factor * DIGEST_BASE;
    }

    acc
}

fn rolling_digest_8(values: [Field; 8]) -> Field {
    let mut acc = DIGEST_DOMAIN;
    let mut factor = 1;

    for i in 0..8 {
        acc = acc + values[i] * factor;
        factor = factor * DIGEST_BASE;
    }

    acc
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
    party_id: Field,
    pk_i_hash: Field,
    dkg_root: Field,
    ciphertext_hash: Field,
    epoch: Field,
    c1_hash: Field,
    d_i_hash: Field,
) -> Field {
    rolling_digest_8([
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
        N as Field + B_E as Field,
    ])
}

fn ciphertext_binding(
    party_id: Field,
    pk_i_hash: Field,
    dkg_root: Field,
    epoch: Field,
    c1_hash: Field,
) -> Field {
    rolling_digest_8([
        party_id,
        pk_i_hash,
        dkg_root,
        epoch,
        c1_hash,
        1,
        2,
        3,
    ])
}

fn dkg_binding(party_id: Field, pk_i_hash: Field, epoch: Field, c1_hash: Field) -> Field {
    rolling_digest_8([
        party_id,
        pk_i_hash,
        epoch,
        c1_hash,
        N as Field,
        B_E as Field,
        11,
        19,
    ])
}

fn main(
    party_id: pub Field,
    pk_i_hash: pub Field,
    dkg_root: pub Field,
    ciphertext_hash: pub Field,
    epoch: pub Field,
    c1_hash: pub Field,
    d_i_hash: pub Field,
    compact_statement_hash: pub Field,
    sk_i: [Field; N],
    e_i: [Field; N],
    c1: [Field; N],
    d_i: [Field; N],
    q: Field,
) {
    assert(epoch as u64 > 0);

    for i in 0..N {
        let sk = sk_i[i];
        assert(sk * (sk - 1) * (sk + 1) == 0);

        let err = e_i[i] as u32;
        assert(err <= B_E);
    }

    let computed_pk_hash = rolling_digest(sk_i);
    assert(computed_pk_hash == pk_i_hash);

    let computed_c1_hash = rolling_digest(c1);
    assert(computed_c1_hash == c1_hash);

    let computed_dkg_root = dkg_binding(party_id, pk_i_hash, epoch, c1_hash);
    assert(computed_dkg_root == dkg_root);

    let computed_ciphertext_hash = ciphertext_binding(party_id, pk_i_hash, dkg_root, epoch, c1_hash);
    assert(computed_ciphertext_hash == ciphertext_hash);

    let computed_d_i_hash = rolling_digest(d_i);
    assert(computed_d_i_hash == d_i_hash);

    let computed_statement_hash = statement_hash(
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
    );
    assert(computed_statement_hash == compact_statement_hash);

    let r = rolling_digest_8([
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        c1_hash,
        d_i_hash,
        compact_statement_hash,
    ]);
    let lhs = eval_poly(d_i, r);
    let rhs = eval_poly(c1, r) * eval_poly(sk_i, r) + eval_poly(e_i, r);
    let r_to_n_plus_one = r_pow_n(r) + 1;
    assert(r_to_n_plus_one != 0);
    assert(rhs - lhs == q * r_to_n_plus_one);
}
