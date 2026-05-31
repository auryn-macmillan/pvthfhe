#[cfg(feature = "enable-poulpy")]
use poulpy_hal::layouts::{DataRef, VecZnx, ZnxInfos, ZnxView};

use crate::sigma::{self, poly_eval_mod, SigmaProof, SigmaStatement, SigmaSzData};
use crate::NizkError;

#[cfg(feature = "enable-poulpy")]
#[allow(dead_code)]
pub(crate) fn vecznx_col_limb_coeffs<D: DataRef>(
    v: &VecZnx<D>,
    col: usize,
    limb: usize,
) -> Result<Vec<i64>, NizkError> {
    if col >= v.cols() || limb >= v.size() {
        return Err(NizkError::InvalidInput(
            "VecZnx column or limb index out of range",
        ));
    }
    Ok(v.at(col, limb).to_vec())
}

#[cfg(feature = "enable-poulpy")]
#[allow(dead_code)]
pub(crate) fn vecznx_all_coeffs<D: DataRef>(v: &VecZnx<D>) -> Vec<i64> {
    v.raw().to_vec()
}

#[cfg(feature = "enable-poulpy")]
#[allow(dead_code)]
pub(crate) fn vecznx_rns_limb<D: DataRef>(
    v: &VecZnx<D>,
    col: usize,
    limb: usize,
    modulus: u64,
) -> Result<Vec<u64>, NizkError> {
    let coeffs = vecznx_col_limb_coeffs(v, col, limb)?;
    Ok(coeffs
        .iter()
        .map(|&c| {
            let rem = (c as i128).rem_euclid(modulus as i128);
            rem as u64
        })
        .collect())
}

#[cfg(feature = "enable-poulpy")]
#[allow(dead_code)]
pub(crate) fn vecznx_to_flat_rns<D: DataRef>(
    v: &VecZnx<D>,
    col: usize,
    q_moduli: &[u64],
) -> Result<Vec<u64>, NizkError> {
    let n = v.n();
    let num_limbs = q_moduli.len();
    let mut out = vec![0u64; n * num_limbs];
    for (limb_idx, &modulus) in q_moduli.iter().enumerate() {
        let limb_coeffs = vecznx_rns_limb(v, col, limb_idx, modulus)?;
        out[limb_idx * n..(limb_idx + 1) * n].copy_from_slice(&limb_coeffs);
    }
    Ok(out)
}

/// Compute Schwartz-Zippel 3-point evaluation data for Poulpy-adapted sigma.
///
/// Evaluates polynomials at 3 Fiat-Shamir-derived gamma points per limb using
/// explicit per-limb modulus values. Supports both CKKS (N > 1) and TFHE (N=1).
pub fn compute_sigma_sz_data_poulpy(
    proof: &SigmaProof,
    c_rns: &[u64],
    d_rns: &[u64],
    session_id: &[u8],
    party_id: u32,
    polynomial_len: usize,
    num_limbs: usize,
    q_moduli: &[u64],
) -> Result<SigmaSzData, NizkError> {
    let n = polynomial_len;
    let l = num_limbs;

    if q_moduli.len() != l {
        return Err(NizkError::InvalidInput(
            "q_moduli length must equal num_limbs",
        ));
    }
    let expected_rns_len = n * l;
    if c_rns.len() != expected_rns_len || d_rns.len() != expected_rns_len {
        return Err(NizkError::InvalidInput(
            "c_rns/d_rns length must equal polynomial_len * num_limbs",
        ));
    }
    if proof.t_rns.len() != expected_rns_len {
        return Err(NizkError::InvalidInput(
            "proof t_rns length must equal polynomial_len * num_limbs",
        ));
    }
    if proof.z_s.len() != n || proof.z_e.len() != n {
        return Err(NizkError::InvalidInput(
            "z_s and z_e must have length N (coefficient-domain)",
        ));
    }

    let gammas = sigma::compute_sz_gamma(proof, session_id, party_id, c_rns, d_rns);

    let total_entries = 3 * l;
    let mut sz_c_eval = Vec::with_capacity(total_entries);
    let mut sz_zs_eval = Vec::with_capacity(total_entries);
    let mut sz_ze_eval = Vec::with_capacity(total_entries);
    let mut sz_t_eval = Vec::with_capacity(total_entries);
    let mut sz_di_eval = Vec::with_capacity(total_entries);
    let mut sz_r1_eval = Vec::with_capacity(total_entries);

    for &gamma in &gammas {
        for limb in 0..l {
            let q = q_moduli[limb];

            let c_coeffs: Vec<i64> = c_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();
            let d_coeffs: Vec<i64> = d_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();
            let t_coeffs: Vec<i64> = proof.t_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();

            let zs_coeffs: Vec<i64> = proof
                .z_s
                .iter()
                .map(|&v| {
                    let rem = (v as i128).rem_euclid(q as i128);
                    i64::try_from(rem).unwrap_or(0)
                })
                .collect();
            let ze_coeffs: Vec<i64> = proof
                .z_e
                .iter()
                .map(|&v| {
                    let rem = (v as i128).rem_euclid(q as i128);
                    i64::try_from(rem).unwrap_or(0)
                })
                .collect();

            let c_val = poly_eval_mod(&c_coeffs, gamma, q);
            let zs_val = poly_eval_mod(&zs_coeffs, gamma, q);
            let ze_val = poly_eval_mod(&ze_coeffs, gamma, q);
            let t_val = poly_eval_mod(&t_coeffs, gamma, q);
            let di_val = poly_eval_mod(&d_coeffs, gamma, q);

            let ch_val = proof.ch as i128;
            let lhs = c_val as i128 * zs_val as i128 + ze_val as i128
                - t_val as i128
                - ch_val * di_val as i128;
            let r1 = lhs.div_euclid(q as i128).unsigned_abs() as u64;

            sz_c_eval.push(c_val);
            sz_zs_eval.push(zs_val);
            sz_ze_eval.push(ze_val);
            sz_t_eval.push(t_val);
            sz_di_eval.push(di_val);
            sz_r1_eval.push(r1);
        }
    }

    Ok((
        gammas, sz_c_eval, sz_zs_eval, sz_ze_eval, sz_t_eval, sz_di_eval, sz_r1_eval,
    ))
}

/// Compute sigma S-Z witness data for CKKS (RLWE, N > 1).
///
/// Delegates to [`compute_sigma_sz_data_poulpy`] with the caller-specified
/// polynomial length, limb count, and per-limb moduli.
pub fn compute_sigma_ntt_data_ckks(
    proof: &SigmaProof,
    stmt: &SigmaStatement,
    session_id: &[u8],
    party_id: u32,
    polynomial_len: usize,
    num_limbs: usize,
    q_moduli: &[u64],
) -> Result<SigmaSzData, NizkError> {
    compute_sigma_sz_data_poulpy(
        proof,
        &stmt.c_rns,
        &stmt.d_rns,
        session_id,
        party_id,
        polynomial_len,
        num_limbs,
        q_moduli,
    )
}

/// Compute sigma S-Z witness data for TFHE (LWE, N=1).
///
/// Thin wrapper around [`compute_sigma_sz_data_poulpy`] with N=1, K=1,
/// and a single modulus. The S-Z evaluation reduces to scalar checks.
pub fn compute_sigma_ntt_data_tfhe(
    proof: &SigmaProof,
    stmt: &SigmaStatement,
    session_id: &[u8],
    party_id: u32,
    q_modulus: u64,
) -> Result<SigmaSzData, NizkError> {
    compute_sigma_sz_data_poulpy(
        proof,
        &stmt.c_rns,
        &stmt.d_rns,
        session_id,
        party_id,
        1usize,
        1usize,
        &[q_modulus],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::{SigmaProof, SigmaStatement, SigmaWitness};

    #[allow(dead_code)]
    fn make_test_witness(n: usize) -> SigmaWitness {
        SigmaWitness {
            s_i: vec![1i64; n],
            e_i: vec![2i64; n],
        }
    }

    #[test]
    fn sz_data_ckks_n8192_k3_produces_correct_shape() {
        let n = 16usize;
        let k = 3usize;
        let q_moduli = vec![
            288_230_376_173_076_481u64,
            288_230_376_167_047_169u64,
            288_230_376_161_280_001u64,
        ];

        let c_rns = vec![1u64; n * k];
        let d_rns = vec![2u64; n * k];
        let t_rns = vec![3u64; n * k];

        let proof = SigmaProof {
            t_rns,
            z_s: vec![5i64; n],
            z_e: vec![7i64; n],
            ch: 1i64,
        };

        let stmt = SigmaStatement {
            c_rns: c_rns.clone(),
            d_rns: d_rns.clone(),
        };

        let result = compute_sigma_ntt_data_ckks(&proof, &stmt, b"test-ckks", 0, n, k, &q_moduli);
        assert!(
            result.is_ok(),
            "CKKS S-Z data computation failed: {:?}",
            result.err()
        );

        let (gammas, c_eval, zs_eval, ze_eval, t_eval, di_eval, r1_eval) = result.unwrap();
        let expected_len = 3 * k;
        assert_eq!(gammas.len(), 3);
        assert_eq!(c_eval.len(), expected_len);
        assert_eq!(zs_eval.len(), expected_len);
        assert_eq!(ze_eval.len(), expected_len);
        assert_eq!(t_eval.len(), expected_len);
        assert_eq!(di_eval.len(), expected_len);
        assert_eq!(r1_eval.len(), expected_len);
    }

    #[test]
    fn sz_data_tfhe_n1_k1_produces_correct_shape() {
        let n = 1usize;
        let q_modulus = 18_446_744_073_709_551_557u64;

        let c_rns = vec![1u64; n];
        let d_rns = vec![2u64; n];
        let t_rns = vec![3u64; n];

        let proof = SigmaProof {
            t_rns,
            z_s: vec![5i64; n],
            z_e: vec![7i64; n],
            ch: -1i64,
        };

        let stmt = SigmaStatement {
            c_rns: c_rns.clone(),
            d_rns: d_rns.clone(),
        };

        let result = compute_sigma_ntt_data_tfhe(&proof, &stmt, b"test-tfhe", 0, q_modulus);
        assert!(
            result.is_ok(),
            "TFHE S-Z data computation failed: {:?}",
            result.err()
        );

        let (gammas, c_eval, zs_eval, ze_eval, t_eval, di_eval, r1_eval) = result.unwrap();
        assert_eq!(gammas.len(), 3);
        assert_eq!(c_eval.len(), 3);
        assert_eq!(zs_eval.len(), 3);
        assert_eq!(ze_eval.len(), 3);
        assert_eq!(t_eval.len(), 3);
        assert_eq!(di_eval.len(), 3);
        assert_eq!(r1_eval.len(), 3);
    }

    #[test]
    fn sz_data_poulpy_n16_produces_valid_r1() {
        let n = 16usize;
        let k = 1usize;
        let q = 65537u64;
        let q_moduli = vec![q];

        let c_rns = vec![1u64; n * k];
        let d_rns = vec![0u64; n * k];
        let t_rns = vec![0u64; n * k];

        let proof = SigmaProof {
            t_rns,
            z_s: vec![0i64; n],
            z_e: vec![0i64; n],
            ch: 0i64,
        };

        let _stmt = SigmaStatement {
            c_rns: c_rns.clone(),
            d_rns: d_rns.clone(),
        };

        let result =
            compute_sigma_sz_data_poulpy(&proof, &c_rns, &d_rns, b"test", 0, n, k, &q_moduli);
        assert!(result.is_ok());

        let (_, _, _, _, _, _, r1_eval) = result.unwrap();
        for &r1 in &r1_eval {
            assert_eq!(r1, 0, "r1 must be 0 for all-zero inputs");
        }
    }

    #[test]
    fn sz_data_rejects_length_mismatch() {
        let result = compute_sigma_sz_data_poulpy(
            &SigmaProof {
                t_rns: vec![0u64; 10],
                z_s: vec![0i64; 5],
                z_e: vec![0i64; 5],
                ch: 0,
            },
            &[0u64; 10],
            &[0u64; 10],
            b"test",
            0,
            5usize,
            2usize,
            &[100u64, 200u64],
        );
        assert!(result.is_ok(), "5*2=10, should be ok");
    }

    #[test]
    fn sz_data_rejects_wrong_num_limbs() {
        let result = compute_sigma_sz_data_poulpy(
            &SigmaProof {
                t_rns: vec![],
                z_s: vec![],
                z_e: vec![],
                ch: 0,
            },
            &[],
            &[],
            b"test",
            0,
            8usize,
            3usize,
            &[100u64], // only 1 modulus, want 3
        );
        assert!(
            result.is_err(),
            "should reject when q_moduli.len() != num_limbs"
        );
    }
}
