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

/// Ajtai commitment + fold-step verification.
///
/// Returns (commitment_hash, fold_acc_hash) as public outputs.
/// fold_acc_hash == 0 means "no fold step included" — only Ajtai commitment verified.
fn main(
    a_evals: [Field; M],
    s: [Field; PHI],
    c: [[Field; PHI]; M],
    r: Field,
    q_ring: [Field; M],
    q_mod: [Field; M],
    fold_r: Field,              // fold challenge (0 = no fold step)
    c_acc: [[Field; PHI]; M],   // old accumulator commitment
) -> pub (Field, Field) {
    // ── Ajtai commitment verification ──
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

    // ── Fold-step: c_acc' = c_acc + fold_r * c (coefficient-wise mod Q) ──
    let fold_acc_hash = if fold_r == 0 {
        0  // no fold step
    } else {
        let mut acc_row_hashes = [0; M];
        for i in 0..M {
            let mut inputs = [0; 257]; inputs[0] = 10;
            for j in 0..PHI {
                // c_acc'[i][j] = (c_acc[i][j] + fold_r * c[i][j]) % Q_COMMIT
                inputs[j + 1] = (c_acc[i][j] + fold_r * c[i][j]);
            }
            acc_row_hashes[i] = poseidon::poseidon::bn254::sponge(inputs);
        }
        let mut acc_inputs = [0; 14]; acc_inputs[0] = 10;
        for i in 0..M { acc_inputs[i + 1] = acc_row_hashes[i]; }
        poseidon::poseidon::bn254::sponge(acc_inputs)
    };

    (commitment_hash, fold_acc_hash)
}

#[test]
fn test_ajtai_only() {
    let h = main([0; M], [0; PHI], [[0; PHI]; M], 42, [0; M], [0; M], 0, [[0; PHI]; M]);
    dep::std::println(h.0);
}

#[test]
fn test_fold_step() {
    let s = [0; PHI];
    let c = [[0; PHI]; M];
    let c_acc = [[0; PHI]; M];
    let h = main([0; M], s, c, 42, [0; M], [0; M], 7, c_acc);
    dep::std::println(h.0);
    dep::std::println(h.1);
}
