use crate::NizkError;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// Bootstrap statement: two LWE ciphertexts + bootstrapping key commitment.
#[derive(Clone, Debug)]
pub struct BootstrapStatement {
    /// Pre-bootstrapping LWE ciphertext bytes (16 bytes: a || b, little-endian u64).
    pub ct_in_bytes: Vec<u8>,
    /// Post-bootstrapping LWE ciphertext bytes (16 bytes: a || b, little-endian u64).
    pub ct_out_bytes: Vec<u8>,
    /// SHA-256 commitment to the bootstrapping key.
    pub bsk_hash: [u8; 32],
}

/// Bootstrap witness: the prover's secret data for N=1 LWE.
#[derive(Clone, Debug)]
pub struct BootstrapWitness {
    /// Ternary secret key (single coefficient in {-1, 0, 1}).
    pub secret_key: Vec<i64>,
    /// Noise difference e_in - e_out (single coefficient, bounded).
    pub bsk_noise: Vec<i64>,
}

/// Scalar sigma proof for LWE (N=1) bootstrapping.
#[derive(Clone, Debug)]
pub struct BootstrapSigmaProof {
    /// Commitment t = c·y_s + y_e mod q.
    pub t: u64,
    /// Response z_s = y_s + ch·s.
    pub z_s: i64,
    /// Response z_e = y_e + ch·e.
    pub z_e: i64,
    /// Fiat-Shamir challenge ch ∈ {-1, 0, 1}.
    pub ch: i64,
}

/// Multi-round parallel sigma proof for LWE bootstrapping.
#[derive(Clone, Debug)]
pub struct BootstrapSigmaMultiProof {
    /// Per-round sigma proofs.
    pub rounds: Vec<BootstrapSigmaProof>,
}

const B_Y: i64 = 2i64.pow(58);
const B_Z: i64 = 2i64.pow(61);

/// Parse LWE ciphertext coefficients.
fn parse_lwe_ct(bytes: &[u8]) -> Result<(u64, u64), NizkError> {
    if bytes.len() < 16 {
        return Err(NizkError::InvalidInput {
            reason: "ciphertext bytes too short",
            party_id: None,
        });
    }
    let a_bytes: [u8; 8] = bytes[..8].try_into().map_err(|_| NizkError::InvalidInput {
        reason: "ciphertext bytes too short",
        party_id: None,
    })?;
    let b_bytes: [u8; 8] = bytes[8..16]
        .try_into()
        .map_err(|_| NizkError::InvalidInput {
            reason: "ciphertext bytes too short",
            party_id: None,
        })?;
    let a = u64::from_le_bytes(a_bytes);
    let b = u64::from_le_bytes(b_bytes);
    Ok((a, b))
}

/// Default TFHE modulus.
const TFHE_Q: u64 = 18_446_744_073_709_551_557;

/// Derive scalar sigma relation (c, d) from two LWE ciphertexts.
fn derive_sigma_relation(ct_in_bytes: &[u8], ct_out_bytes: &[u8]) -> Result<(u64, u64), NizkError> {
    let (a_in, b_in) = parse_lwe_ct(ct_in_bytes)?;
    let (a_out, b_out) = parse_lwe_ct(ct_out_bytes)?;
    let q = TFHE_Q;
    let q128 = q as u128;
    let c = ((a_in as u128).wrapping_sub(a_out as u128) % q128) as u64;
    let d = ((b_in as u128).wrapping_sub(b_out as u128) % q128) as u64;
    Ok((c, d))
}

fn scalar_mul_mod(a: u64, b: i64, q: u64) -> u64 {
    let product = a as i128 * b as i128;
    let r = product.rem_euclid(q as i128);
    r as u64
}

fn scalar_add_mod(a: u64, b: i64, q: u64) -> u64 {
    let sum = a as i128 + b as i128;
    let r = sum.rem_euclid(q as i128);
    r as u64
}

fn scalar_add_u64_mod(a: u64, b: u64, q: u64) -> u64 {
    let sum = a as u128 + b as u128;
    (sum % q as u128) as u64
}

fn sample_bounded_scalar(rng: &mut dyn RngCore, bound: i64) -> i64 {
    let range = (2 * bound + 1) as u64;
    let max = (u64::MAX / range) * range;
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let r = u64::from_le_bytes(bytes);
        if r < max {
            return (r % range) as i64 - bound;
        }
    }
}

fn derive_challenge(
    t: u64,
    c: u64,
    d: u64,
    bsk_hash: &[u8; 32],
    session_id: &[u8],
    party_id: u32,
    round: usize,
) -> i64 {
    let mut h = Sha256::new();
    h.update(pvthfhe_domain_tags::Tag::BootstrapSigmaChallenge.as_bytes());
    h.update(session_id);
    h.update(party_id.to_le_bytes());
    h.update((round as u64).to_le_bytes());
    h.update(bsk_hash);
    h.update(t.to_le_bytes());
    h.update(c.to_le_bytes());
    h.update(d.to_le_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let fr = Fr::from_le_bytes_mod_order(&digest);
    if fr.is_zero() {
        return 0;
    }
    let bigint = fr.into_bigint();
    let mut half_mod = Fr::MODULUS;
    half_mod.div2();
    if bigint > half_mod {
        -1
    } else {
        1
    }
}

/// Produce a single-round bootstrap sigma proof.
///
/// `round_index` binds the repetition round into the FS transcript to prevent
/// cross-round replay when SIGMA_REPETITIONS > 1.
pub fn prove(
    session_id: &[u8],
    party_id: u32,
    stmt: &BootstrapStatement,
    wit: &BootstrapWitness,
    rng: &mut dyn RngCore,
    _d_commitment: &[u8; 32],
    round_index: usize,
) -> Result<BootstrapSigmaProof, NizkError> {
    let (c, d) = derive_sigma_relation(&stmt.ct_in_bytes, &stmt.ct_out_bytes)?;
    let q = TFHE_Q;
    let s = wit.secret_key.first().copied().unwrap_or(0);
    let e = wit.bsk_noise.first().copied().unwrap_or(0);

    for _attempt in 0..100 {
        let y_s = sample_bounded_scalar(rng, B_Y);
        let y_e = sample_bounded_scalar(rng, B_Y);
        let t = scalar_add_mod(scalar_mul_mod(c, y_s, q), y_e, q);
        let ch = derive_challenge(t, c, d, &stmt.bsk_hash, session_id, party_id, round_index);
        let z_s = y_s + ch * s;
        let z_e = y_e + ch * e;

        if z_s.abs() > B_Z || z_e.abs() > B_Z {
            continue;
        }
        return Ok(BootstrapSigmaProof { t, z_s, z_e, ch });
    }
    Err(NizkError::VerificationFailed {
        reason: "sigma rejection sampling exhausted",
        party_id: None,
    })
}

/// Verify a single-round bootstrap sigma proof.
///
/// This sigma proves that ct_out comes from the same LWE secret key as ct_in
/// under the claimed bootstrapping key hash. It does NOT prove the full blind
/// rotation was correct (CMUX chain verification is deferred to P2).
///
/// `round_index` must match the value used during [`prove`] to ensure
/// round-serial-number binding in multi-round protocols.
pub fn verify(
    session_id: &[u8],
    party_id: u32,
    stmt: &BootstrapStatement,
    proof: &BootstrapSigmaProof,
    _d_commitment: &[u8; 32],
    round_index: usize,
) -> Result<(), NizkError> {
    let (c, d) = derive_sigma_relation(&stmt.ct_in_bytes, &stmt.ct_out_bytes)?;
    let q = TFHE_Q;

    if proof.ch != -1 && proof.ch != 0 && proof.ch != 1 {
        return Err(NizkError::VerificationFailed {
            reason: "challenge must be -1, 0, or 1",
            party_id: None,
        });
    }
    let expected_ch = derive_challenge(
        proof.t,
        c,
        d,
        &stmt.bsk_hash,
        session_id,
        party_id,
        round_index,
    );
    if proof.ch != expected_ch {
        return Err(NizkError::VerificationFailed {
            reason: "challenge mismatch",
            party_id: None,
        });
    }
    if proof.z_s.abs() > B_Z || proof.z_e.abs() > B_Z {
        return Err(NizkError::VerificationFailed {
            reason: "response norm exceeded",
            party_id: None,
        });
    }

    let lhs = scalar_add_mod(scalar_mul_mod(c, proof.z_s, q), proof.z_e, q);
    let rhs = scalar_add_u64_mod(scalar_mul_mod(d, proof.ch, q), proof.t, q);
    if lhs != rhs {
        return Err(NizkError::VerificationFailed {
            reason: "algebraic equation failed",
            party_id: None,
        });
    }
    Ok(())
}

/// Produce multi-round parallel bootstrap sigma proofs.
pub fn prove_multi(
    session_id: &[u8],
    party_id: u32,
    stmt: &BootstrapStatement,
    wit: &BootstrapWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
    num_rounds: usize,
) -> Result<BootstrapSigmaMultiProof, NizkError> {
    let mut rounds = Vec::with_capacity(num_rounds);
    for i in 0..num_rounds {
        rounds.push(prove(
            session_id,
            party_id,
            stmt,
            wit,
            rng,
            d_commitment,
            i,
        )?);
    }
    Ok(BootstrapSigmaMultiProof { rounds })
}

/// Verify multi-round parallel bootstrap sigma proofs.
pub fn verify_multi(
    session_id: &[u8],
    party_id: u32,
    stmt: &BootstrapStatement,
    proof: &BootstrapSigmaMultiProof,
    d_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    if proof.rounds.is_empty() {
        return Err(NizkError::VerificationFailed {
            reason: "bootstrap sigma multi-proof must have at least one round",
            party_id: None,
        });
    }
    for (i, round_proof) in proof.rounds.iter().enumerate() {
        verify(session_id, party_id, stmt, round_proof, d_commitment, i)?;
    }
    Ok(())
}

/// Compute compact bootstrap result hash for on-chain binding.
pub fn compute_bootstrap_result_hash(
    stmt: &BootstrapStatement,
    session_id: &[u8],
    party_id: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pvthfhe_domain_tags::Tag::BootstrapResult.as_bytes());
    hasher.update(session_id);
    hasher.update(party_id.to_le_bytes());
    hasher.update(stmt.bsk_hash);
    hasher.update(&stmt.ct_in_bytes);
    hasher.update(&stmt.ct_out_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_lwe_ct(a: u64, s: i64, e: i64, m: i64) -> Vec<u8> {
        let q = TFHE_Q;
        let half_q = (q >> 1) as i64;
        let msg_term = m * half_q;
        let b_i128 = a as i128 * s as i128 + e as i128 + msg_term as i128;
        let b = b_i128.rem_euclid(q as i128) as u64;
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out
    }

    #[test]
    fn test_derive_sigma_relation_zero_diff() {
        let _q = TFHE_Q;
        let a = 1u64;
        let s = 0i64;
        let e = 0i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a, s, e, m);
        let ct_out = make_lwe_ct(a, s, e, m);
        let (c, d) = derive_sigma_relation(&ct_in, &ct_out).unwrap();
        assert_eq!(c, 0);
        assert_eq!(d, 0);
    }

    #[test]
    fn test_prove_verify_honest() {
        let a_in = 42u64;
        let a_out = 17u64;
        let s = 1i64;
        let e_in = 3i64;
        let e_out = 1i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a_in, s, e_in, m);
        let ct_out = make_lwe_ct(a_out, s, e_out, m);

        let stmt = BootstrapStatement {
            ct_in_bytes: ct_in,
            ct_out_bytes: ct_out,
            bsk_hash: [1u8; 32],
        };
        let wit = BootstrapWitness {
            secret_key: vec![s],
            bsk_noise: vec![e_in - e_out],
        };

        let mut rng = StdRng::seed_from_u64(42);
        let proof = prove(b"test", 1, &stmt, &wit, &mut rng, &[0u8; 32], 0).unwrap();
        verify(b"test", 1, &stmt, &proof, &[0u8; 32], 0).unwrap();
    }

    #[test]
    fn test_rejects_wrong_witness() {
        let a_in = 42u64;
        let a_out = 17u64;
        let s_true = 1i64;
        let s_false = -1i64;
        let e_in = 3i64;
        let e_out = 1i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a_in, s_true, e_in, m);
        let ct_out = make_lwe_ct(a_out, s_true, e_out, m);

        let stmt = BootstrapStatement {
            ct_in_bytes: ct_in,
            ct_out_bytes: ct_out,
            bsk_hash: [1u8; 32],
        };
        let wrong_wit = BootstrapWitness {
            secret_key: vec![s_false],
            bsk_noise: vec![e_in - e_out],
        };

        let mut rng = StdRng::seed_from_u64(999);
        let proof = prove(b"test", 1, &stmt, &wrong_wit, &mut rng, &[0u8; 32], 0).unwrap();
        assert!(verify(b"test", 1, &stmt, &proof, &[0u8; 32], 0).is_err());
    }

    #[test]
    fn test_rejects_tampered_ct() {
        let a_in = 42u64;
        let a_out = 17u64;
        let s = 1i64;
        let e_in = 3i64;
        let e_out = 1i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a_in, s, e_in, m);
        let ct_out = make_lwe_ct(a_out, s, e_out, m);

        let stmt = BootstrapStatement {
            ct_in_bytes: ct_in.clone(),
            ct_out_bytes: ct_out.clone(),
            bsk_hash: [1u8; 32],
        };
        let mut tampered = ct_out.clone();
        tampered[0] ^= 0xFF;
        let tampered_stmt = BootstrapStatement {
            ct_in_bytes: ct_in,
            ct_out_bytes: tampered,
            bsk_hash: [1u8; 32],
        };

        let wit = BootstrapWitness {
            secret_key: vec![s],
            bsk_noise: vec![e_in - e_out],
        };

        let mut rng = StdRng::seed_from_u64(42);
        let proof = prove(b"test", 1, &stmt, &wit, &mut rng, &[0u8; 32], 0).unwrap();
        assert!(verify(b"test", 1, &tampered_stmt, &proof, &[0u8; 32], 0).is_err());
    }

    #[test]
    fn test_prove_multi_verify() {
        let a_in = 99u64;
        let a_out = 33u64;
        let s = 1i64;
        let e_in = 2i64;
        let e_out = 4i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a_in, s, e_in, m);
        let ct_out = make_lwe_ct(a_out, s, e_out, m);

        let stmt = BootstrapStatement {
            ct_in_bytes: ct_in,
            ct_out_bytes: ct_out,
            bsk_hash: [2u8; 32],
        };
        let wit = BootstrapWitness {
            secret_key: vec![s],
            bsk_noise: vec![e_in - e_out],
        };

        let mut rng = StdRng::seed_from_u64(12345);
        let multi = prove_multi(b"multi", 2, &stmt, &wit, &mut rng, &[0u8; 32], 4).unwrap();
        assert_eq!(multi.rounds.len(), 4);
        verify_multi(b"multi", 2, &stmt, &multi, &[0u8; 32]).unwrap();
    }

    /// P0-1: Empty multi-round proof must be rejected (vacuous verification).
    #[test]
    fn test_empty_multi_round_proof_rejected() {
        let stmt = BootstrapStatement {
            ct_in_bytes: vec![1u8; 16],
            ct_out_bytes: vec![2u8; 16],
            bsk_hash: [3u8; 32],
        };
        let proof = BootstrapSigmaMultiProof { rounds: vec![] };
        let result = verify_multi(b"session", 1, &stmt, &proof, &[0u8; 32]);
        assert!(result.is_err(), "empty multi-round proof must be rejected");
    }

    /// G5.2a: RED→GREEN — prove with one bsk_hash, verify with a different one → REJECT.
    ///
    /// Uses multi-round verification (8 rounds) for reliability, since single-round
    /// challenges only map to {-1,0,1} giving ~33% accidental collision per round.
    #[test]
    fn test_wrong_bsk_hash_rejected() {
        let a_in = 42u64;
        let a_out = 17u64;
        let s = 1i64;
        let e_in = 3i64;
        let e_out = 1i64;
        let m = 0i64;
        let ct_in = make_lwe_ct(a_in, s, e_in, m);
        let ct_out = make_lwe_ct(a_out, s, e_out, m);

        let bsk_hash_honest = [1u8; 32];
        let bsk_hash_adversary = [99u8; 32];

        let stmt_honest = BootstrapStatement {
            ct_in_bytes: ct_in.clone(),
            ct_out_bytes: ct_out.clone(),
            bsk_hash: bsk_hash_honest,
        };

        let stmt_adversary = BootstrapStatement {
            ct_in_bytes: ct_in,
            ct_out_bytes: ct_out,
            bsk_hash: bsk_hash_adversary,
        };

        let wit = BootstrapWitness {
            secret_key: vec![s],
            bsk_noise: vec![e_in - e_out],
        };

        let mut rng = StdRng::seed_from_u64(42);
        let multi_proof =
            prove_multi(b"test", 1, &stmt_honest, &wit, &mut rng, &[0u8; 32], 8).unwrap();
        assert_eq!(multi_proof.rounds.len(), 8);

        let result = verify_multi(b"test", 1, &stmt_adversary, &multi_proof, &[0u8; 32]);
        assert!(
            result.is_err(),
            "verification must reject when bsk_hash differs from the one used during prove"
        );

        verify_multi(b"test", 1, &stmt_honest, &multi_proof, &[0u8; 32])
            .expect("honest bsk_hash must still verify");
    }

    #[test]
    fn test_result_hash_deterministic() {
        let stmt = BootstrapStatement {
            ct_in_bytes: vec![1u8; 16],
            ct_out_bytes: vec![2u8; 16],
            bsk_hash: [3u8; 32],
        };
        let h1 = compute_bootstrap_result_hash(&stmt, b"session", 1);
        let h2 = compute_bootstrap_result_hash(&stmt, b"session", 1);
        assert_eq!(h1, h2);
    }
}
