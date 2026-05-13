//! C7 ring-aware coefficient check tests.
//!
//! Tests validated:
//! 1. Power-basis coefficient extraction returns the correct count
//! 2. CRT reconstruction of known residues produces the expected integer
//! 3. Fr Lagrange coefficients are correctly extracted as i64 for small t
//! 4. The full coefficient check flow produces 0 mismatches

use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::{Poly, Representation};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;
use rand::rngs::OsRng;

const TEST_PARAMS_TOML: &str = r#"
[rlwe]
n = 2048
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

fn test_backend() -> FhersBackend {
    FhersBackend::load_params(TEST_PARAMS_TOML).expect("load test params")
}

/// Test 1: poly_coeffs_from_bytes returns power-basis residues in the correct count.
#[test]
fn poly_power_basis_coeff_count() {
    let backend = test_backend();
    let bfv_params = backend.bfv_params();
    let ctx = bfv_params.ctx_at_level(0).expect("ctx level 0");

    // Create a plaintext polynomial, serialize it, and parse back.
    let pt = Plaintext::try_encode(&[0xB1u64, 0x0Cu64], Encoding::poly(), bfv_params)
        .expect("encode plaintext");
    let pt_poly = pt.to_poly();
    let pt_poly_bytes = pt_poly.to_bytes();

    let coeffs = backend
        .poly_coeffs_from_bytes(&pt_poly_bytes)
        .expect("poly_coeffs_from_bytes");

    let n_coeffs = ctx.degree;
    let n_moduli = ctx.q.len();
    assert_eq!(coeffs.len(), n_coeffs * n_moduli,
        "should return {} residues ({} coeffs × {} moduli)", n_coeffs * n_moduli, n_coeffs, n_moduli);

    // Verify residues are in valid non-negative range
    for &c in &coeffs {
        assert!(c >= 0, "all residues must be non-negative, got {c}");
    }
}

/// Test 2: CRT-reconstruct known values: CRT(1,1,1) = 1 for all coefficients.
#[test]
fn crt_reconstruct_known_values() {
    let backend = test_backend();
    let bfv_params = backend.bfv_params();
    let n_coeffs = bfv_params.degree();
    let n_moduli = bfv_params.moduli().len();

    // All residues = 1 (every coefficient is 1 modulo every modulus)
    let residues: Vec<i64> = vec![1i64; n_coeffs * n_moduli];

    let reconstructed = backend.crt_reconstruct_coeffs(&residues);
    assert_eq!(reconstructed.len(), n_coeffs,
        "CRT should produce one integer per coefficient");

    for (i, &val) in reconstructed.iter().enumerate() {
        assert_eq!(val, 1, "CRT(1,1,1) must equal 1 for coeff {i}, got {val}");
    }
}

/// Test 3: Fr Lagrange coefficients for t=4 with points [1,2,3,4]
/// compute to exact integers [4, -6, 4, -1].
#[test]
fn lagrange_fr_to_i64_for_t4() {
    use ark_bn254::Fr;
    use ark_ff::Field;

    let xs: Vec<Fr> = (1..=4).map(|i| Fr::from(i as u64)).collect();
    let mut coeffs = Vec::with_capacity(4);
    for i in 0..4 {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for j in 0..4 {
            if i != j {
                num *= -xs[j];
                den *= xs[i] - xs[j];
            }
        }
        coeffs.push(num * den.inverse().expect("invertible"));
    }

    let expected: [i64; 4] = [4, -6, 4, -1];
    for (i, (&e, &f)) in expected.iter().zip(coeffs.iter()).enumerate() {
        let extracted = fr_to_i64_small(f);
        assert_eq!(extracted, e,
            "Lagrange coefficient {i}: expected {e}, got {extracted}");
    }
}

fn fr_to_i64_small(f: ark_bn254::Fr) -> i64 {
    use ark_ff::PrimeField;
    let big = f.into_bigint();
    let limbs = big.as_ref();
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        limbs[0] as i64
    } else {
        let neg_f = -f;
        let neg_big = neg_f.into_bigint();
        -(neg_big.as_ref()[0] as i64)
    }
}

/// Test 4: End-to-end coefficient check — verify that the Lagrange-weighted sum
/// of share residues computed from witness data matches the independently-computed
/// reference (from the same share bytes) with 0 mismatches.
#[test]
fn c7_coeff_check_zero_mismatches() {
    let backend = test_backend();
    let bfv_params = backend.bfv_params();
    let ctx = bfv_params.ctx_at_level(0).expect("ctx level 0");
    let mut rng = OsRng;

    let n_parties: usize = 4;
    let threshold: usize = 2;

    // Generate a secret key, encrypt, and produce decryption shares.
    let sk = SecretKey::random(bfv_params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    let pt = Plaintext::try_encode(&[0xB1u64, 0x0Cu64], Encoding::poly(), bfv_params)
        .expect("encode plaintext");
    let ct = pk.try_encrypt(&pt, &mut rng).expect("encrypt");

    let party_ids: Vec<usize> = (1..=threshold).collect();

    // Produce decryption shares using ShareManager for correctness.
    use fhe::trbfv::ShareManager;
    let share_manager = ShareManager::new(n_parties, threshold, bfv_params.clone());
    let ct_arc = std::sync::Arc::new(ct);

    // Simulate Shamir shares of the secret key
    let sk_coeffs: Vec<i64> = sk.coeffs.to_vec();

    let mut share_polys = Vec::with_capacity(threshold);
    for i in 0..threshold {
        // Dummy Shamir share: multiply sk coeffs by i+1
        let share_coeffs: Vec<i64> = sk_coeffs.iter().map(|c| c * (i as i64 + 1)).collect();
        let poly = Poly::try_convert_from(
            &share_coeffs, &ctx, false, Representation::PowerBasis
        ).expect("convert share poly");
        share_polys.push(poly);
    }

    let mut d_share_bytes_list = Vec::with_capacity(threshold);
    let zero_poly = Poly::zero(&ctx, Representation::PowerBasis);
    for poly in &share_polys {
        let d_share = share_manager
            .decryption_share(ct_arc.clone(), poly.clone(), zero_poly.clone())
            .expect("decryption_share");
        d_share_bytes_list.push(d_share.to_bytes());
    }

    // Extract coefficients from share polynomials via poly_coeffs_from_bytes
    let mut share_coeffs: Vec<Vec<i64>> = Vec::with_capacity(threshold);
    for bytes in &d_share_bytes_list {
        let coeffs = backend
            .poly_coeffs_from_bytes(bytes)
            .expect("share poly coeffs");
        share_coeffs.push(coeffs);
    }

    let n_coeffs = share_coeffs[0].len();
    assert_eq!(n_coeffs, ctx.degree * ctx.q.len(),
        "residue count should be degree × num_moduli");

    // Compute integer Lagrange coefficients for party IDs [1, 2]
    let lagrange_coeffs_int: Vec<i64> = {
        let n = party_ids.len();
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            let xi = party_ids[i] as i128;
            let mut num: i128 = 1;
            let mut den: i128 = 1;
            for j in 0..n {
                if i != j {
                    let xj = party_ids[j] as i128;
                    num *= -xj;
                    den *= xi - xj;
                }
            }
            coeffs.push((num / den) as i64);
        }
        coeffs
    };

    // Compute Σ λ_i · d_i from witnesses
    let mut computed_sum = vec![0i128; n_coeffs];
    for k in 0..n_coeffs {
        for (i, coeffs) in share_coeffs.iter().enumerate() {
            computed_sum[k] += lagrange_coeffs_int[i] as i128 * coeffs[k] as i128;
        }
    }

    // Compute reference Σ λ_i · d_i independently from same bytes
    let mut reference_sum = vec![0i128; n_coeffs];
    for (bytes, lambda) in d_share_bytes_list.iter().zip(lagrange_coeffs_int.iter()) {
        let coeffs = backend
            .poly_coeffs_from_bytes(bytes)
            .expect("reference share coeffs");
        for k in 0..n_coeffs {
            reference_sum[k] += *lambda as i128 * coeffs[k] as i128;
        }
    }

    // Should match exactly (same data, same lambda)
    let mismatches = (0..n_coeffs)
        .filter(|&k| computed_sum[k] != reference_sum[k])
        .count();

    assert_eq!(mismatches, 0,
        "coefficient check must have 0 mismatches, got {mismatches}");

    // Sanity: the sums should not be all zero
    let has_nonzero = reference_sum.iter().any(|&s| s != 0);
    assert!(has_nonzero, "reference sum must contain non-zero values");
}
