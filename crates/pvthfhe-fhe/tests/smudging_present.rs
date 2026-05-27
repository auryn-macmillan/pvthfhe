//! RED test for R1.4: verifies smudging noise is absent from `partial_decrypt`.
//!
//! Without smudging, every call to `partial_decrypt` produces the same result
//! (the method is deterministic given the same inputs). After smudging is added,
//! each call produces a different result due to freshly sampled Gaussian noise.

use fhe_math::rq::Poly;
use fhe_traits::DeserializeWithContext;
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;
use sha2::{Digest, Sha256};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Smudging variance σ² = (3.5062048768e12)² ≈ 1.229e25.
/// See `.sisyphus/design/smudging.md` §4.
const SIGMA_SMUDGE_SQ: f64 = 1.229_347_346_789_580_8e25;

/// Minimum acceptable variance for smudging detection.
/// We use σ²/2 as a conservative threshold — actual variance should be
/// close to σ² across independent Gaussian samples.
const MIN_VARIANCE: f64 = SIGMA_SMUDGE_SQ / 2.0;

#[test]
fn smudging_noise_is_present_in_partial_decrypt() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [99u8; 32];
    let mut rng = thread_rng();

    // Keygen for 5 parties
    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend
        .setup_threshold(5, 3, Sha256::digest(session_id).into())
        .expect("setup threshold");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let ciphertext = backend
        .encrypt(&pk, b"smudging-red-test", &mut rng)
        .expect("encrypt");

    let num_samples: usize = 100;
    let ctx = backend
        .bfv_params()
        .ctx_at_level(0)
        .expect("level-0 context");

    // Collect the first coefficient of each decryption share.
    let mut coeff0_values = Vec::with_capacity(num_samples);
    for _ in 0..num_samples {
        let decrypt_share = backend
            .partial_decrypt(&ciphertext, 1, &mut rng)
            .expect("partial decrypt");

        let decoded =
            wire::decode_decrypt_share(&decrypt_share.bytes).expect("decode decrypt share");
        let poly = Poly::from_bytes(decoded.d_share_poly.as_slice(), &ctx)
            .expect("deserialize share poly");

        // Coefficient 0 of limb 0
        let coeffs = poly.coefficients();
        let coeff0 = coeffs[[0, 0]] as f64;
        coeff0_values.push(coeff0);
    }

    // Compute variance
    let n = coeff0_values.len() as f64;
    let mean: f64 = coeff0_values.iter().sum::<f64>() / n;
    let variance: f64 = coeff0_values
        .iter()
        .map(|&v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;

    eprintln!(
        "Smudging variance check: mean={mean:.6e}, variance={variance:.6e}, min_expected={MIN_VARIANCE:.6e}",
    );

    assert!(
        variance >= MIN_VARIANCE,
        "partial_decrypt must add smudging noise: variance={variance:.6e} < min_expected={MIN_VARIANCE:.6e}. \
         Without smudging, all decryption shares are identical and variance ≈ 0."
    );
}
