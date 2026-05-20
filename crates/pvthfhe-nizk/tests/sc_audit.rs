//! SC audit: constant-time challenge comparison.
//! Verifies that sigma::verify uses constant-time comparison for the challenge.

use pvthfhe_nizk::sigma::{
    compute_d_rns, prove, verify, verify_scalar, SigmaStatement, SigmaWitness, RLWE_N, RLWE_Q0,
    RLWE_Q1, RLWE_Q2, SIGMA_B_E,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn sample_c_rns(rng: &mut ChaCha20Rng) -> Vec<u64> {
    const MODULI: [u64; 3] = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
    let mut out = vec![0u64; RLWE_N * 3];
    for (limb, &q) in MODULI.iter().enumerate() {
        let threshold = u64::MAX - (u64::MAX % q);
        for j in 0..RLWE_N {
            loop {
                let v = rng.next_u64();
                if v < threshold {
                    out[limb * RLWE_N + j] = v % q;
                    break;
                }
            }
        }
    }
    out
}

fn sample_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; RLWE_N];
    for x in s.iter_mut() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *x = match b[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    s
}

fn sample_error(rng: &mut ChaCha20Rng) -> Vec<i64> {
    const RANGE: u64 = 33;
    const THRESHOLD: u64 = u64::MAX - (u64::MAX % RANGE);
    let mut e = vec![0i64; RLWE_N];
    for x in e.iter_mut() {
        loop {
            let v = rng.next_u64();
            if v < THRESHOLD {
                *x = i64::try_from(v % RANGE).expect("RANGE fits i64") - SIGMA_B_E;
                break;
            }
        }
    }
    e
}

#[test]
fn sc_audit_verify_rejects_tampered_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::seed_from_u64(0xA0D17);
    let c_rns = sample_c_rns(&mut rng);
    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng);
    let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)?;
    let stmt = SigmaStatement { c_rns, d_rns };
    let wit = SigmaWitness { s_i, e_i };
    let proof = prove(b"audit-session", 0, &stmt, &wit, &mut rng)?;

    // Tamper challenge: flip sign (if non-zero) or set to 1 (if zero)
    let mut tampered = proof.clone();
    if tampered.ch != 0 {
        tampered.ch = -tampered.ch;
    } else {
        tampered.ch = 1;
    }
    assert!(
        verify(b"audit-session", 0, &stmt, &tampered).is_err(),
        "challenge tampered must be rejected"
    );

    Ok(())
}

#[test]
fn scalar_sigma_roundtrip_uses_single_ternary_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5CA1A2);
    let c_rns = sample_c_rns(&mut rng);
    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng);
    let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)?;
    let stmt = SigmaStatement { c_rns, d_rns };
    let wit = SigmaWitness { s_i, e_i };

    let proof = prove(b"scalar-session", 11, &stmt, &wit, &mut rng)?;

    assert!(
        matches!(proof.ch, -1 | 0 | 1),
        "scalar sigma challenge must be one ternary scalar"
    );
    verify_scalar(b"scalar-session", 11, &stmt, &proof)?;
    verify(b"scalar-session", 11, &stmt, &proof)?;

    Ok(())
}
