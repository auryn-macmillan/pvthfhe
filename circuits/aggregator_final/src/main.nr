global N: u32 = 8192;
global LOG_N: u32 = 13;
global N_PARTICIPANTS: Field = 3;
global THRESHOLD: Field = 2;

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

fn main(
    ciphertext_hash: pub Field,
    plaintext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    dkg_root: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    d_commitment: pub Field,
    d1: [Field; N],
    d2: [Field; N],
    d3: [Field; N],
    plaintext: [Field; N],
    q: Field,
) {
    assert(epoch as u64 > 0);
    assert(ciphertext_hash != plaintext_hash);
    assert(participant_set_hash != 0);

    let d1_hash = rolling_digest(d1);
    let d2_hash = rolling_digest(d2);
    let d3_hash = rolling_digest(d3);
    let plaintext_check = rolling_digest(plaintext);
    assert(plaintext_check == plaintext_hash);

    let d_commitment_computed = rolling_digest_8([
        d1_hash,
        d2_hash,
        d3_hash,
        dkg_root,
        participant_set_hash,
        epoch,
        N_PARTICIPANTS,
        THRESHOLD,
    ]);
    assert(d_commitment_computed == d_commitment);

    let r = rolling_digest_8([
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        0,
    ]);
    let lhs = eval_poly(plaintext, r);
    let rhs = 3 * eval_poly(d1, r) - 3 * eval_poly(d2, r) + eval_poly(d3, r);
    let r_to_n_plus_one = r_pow_n(r) + 1;
    assert(r_to_n_plus_one != 0);
    assert(rhs - lhs == q * r_to_n_plus_one);
    assert(aggregate_pk_hash != 0);
}
