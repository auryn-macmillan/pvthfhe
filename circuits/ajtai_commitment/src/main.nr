use dep::poseidon;
use protocol_constants::{PHI, M, Q_COMMIT};

fn eval_poly(coeffs: [Field; PHI], r: Field) -> Field {
    let mut result = 0;
    for i in 0..PHI { result = result * r + coeffs[PHI - 1 - i]; }
    result
}
fn pow256(r: Field) -> Field {
    let mut result = r;
    for _ in 0..8 { result = result * result; }
    result
}

fn main(
    a_evals: [Field; M],
    s: [Field; PHI],
    c: [[Field; PHI]; M],
    r: Field,
    q_ring: [Field; M],
    q_mod: [Field; M],
) -> pub Field {  // ← commitment_hash is the public output
    // Hash c coefficients
    let mut row_hashes = [0; M];
    for i in 0..M {
        let mut inputs = [0; 257]; inputs[0] = 9;
        for j in 0..PHI { inputs[j + 1] = c[i][j]; }
        row_hashes[i] = poseidon::poseidon::bn254::sponge(inputs);
    }
    let mut final_inputs = [0; 14]; final_inputs[0] = 9;
    for i in 0..M { final_inputs[i + 1] = row_hashes[i]; }
    let commitment_hash = poseidon::poseidon::bn254::sponge(final_inputs);

    let s_r = eval_poly(s, r);
    let r256_plus_1 = pow256(r) + 1;
    for i in 0..M {
        let c_i_r = eval_poly(c[i], r);
        let expected = c_i_r + (Q_COMMIT) * q_mod[i] + r256_plus_1 * q_ring[i];
        assert(a_evals[i] * s_r == expected, f"row {i} S-Z failed");
    }
    commitment_hash  // public output → on-chain verifier checks this
}

#[test]
fn test_zero() {
    let h = main([0; M], [0; PHI], [[0; PHI]; M], 42, [0; M], [0; M]);
    dep::std::println(h);
}
