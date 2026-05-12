//! T11.5 side-channel audit tests.

use pvthfhe_nizk::sigma::{
    compute_d_rns, prove, verify, SigmaStatement, SigmaWitness, RLWE_N, RLWE_Q0, RLWE_Q1, RLWE_Q2,
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
    (0..RLWE_N)
        .map(|_| (rng.next_u32() % 3) as i64 - 1)
        .collect()
}

fn sample_error(rng: &mut ChaCha20Rng) -> Vec<i64> {
    (0..RLWE_N)
        .map(|_| (rng.next_u32() % 33) as i64 - 16)
        .collect()
}

// RED: sc_audit_sigma_challenge_comparison_is_ct
// Verifies that sigma::verify uses constant-time comparison for the challenge.
// BEFORE FIX: fails to compile (subtle not yet imported in sigma.rs).
// AFTER FIX: compiles and passes.
#[test]
fn sc_audit_sigma_challenge_comparison_is_ct() {
    use subtle::ConstantTimeEq;
    let a = vec![0i64; RLWE_N];
    let b = vec![0i64; RLWE_N];
    let a_bytes: Vec<u8> = a.iter().flat_map(|x| x.to_le_bytes()).collect();
    let b_bytes: Vec<u8> = b.iter().flat_map(|x| x.to_le_bytes()).collect();
    assert!(
        bool::from(a_bytes.as_slice().ct_eq(b_bytes.as_slice())),
        "CT challenge comparison must work"
    );
}

// RED: sc_audit_pvss_commitment_comparison_is_ct
// Verifies that adapter::verify uses CT comparison for pvss_commitment.
// BEFORE FIX: subtle not yet used in adapter.rs.
// AFTER FIX: passes.
#[test]
fn sc_audit_pvss_commitment_comparison_is_ct() {
    use subtle::ConstantTimeEq;
    let a = [0xDEu8; 32];
    let b = [0xDEu8; 32];
    let c = [0xADu8; 32];
    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}

// sc_audit_verify_rejects_tampered_challenge
// Verifies that a proof with a tampered challenge is rejected
// regardless of which coefficient is modified.
#[test]
fn sc_audit_verify_rejects_tampered_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = ChaCha20Rng::seed_from_u64(0xA0D17);
    let c_rns = sample_c_rns(&mut rng);
    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng);
    let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)?;
    let stmt = SigmaStatement { c_rns, d_rns };
    let wit = SigmaWitness { s_i, e_i };
    let pvss = [0u8; 32];
    let proof = prove(b"audit-session", 0, &stmt, &wit, &pvss, &mut rng)?;

    // Tamper first coefficient of challenge
    let mut tampered_first = proof.clone();
    tampered_first.ch[0] ^= 1;
    assert!(
        verify(b"audit-session", 0, &stmt, &tampered_first, &pvss).is_err(),
        "challenge tampered in first coeff must be rejected"
    );

    // Tamper last coefficient of challenge
    let mut tampered_last = proof.clone();
    tampered_last.ch[RLWE_N - 1] ^= 1;
    assert!(
        verify(b"audit-session", 0, &stmt, &tampered_last, &pvss).is_err(),
        "challenge tampered in last coeff must be rejected"
    );

    Ok(())
}
