use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityProof {
    pub chunk_coefficients: Vec<Vec<Fr>>,
    pub n: usize,
    pub t: usize,
    pub norm_witness_hash: [u8; 32],
    pub encryption_validity_hash: [u8; 32],
}

pub fn hash_norm_witness(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-norm-witness-v1");
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_encryption_validity(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-encryption-validity-v1");
    hasher.update(data);
    hasher.finalize().into()
}

pub fn generate_parity_matrix(n: usize, t: usize) -> Vec<Vec<Fr>> {
    if n <= t + 1 {
        return Vec::new();
    }
    let n_rows = n - t - 1;
    let order = t + 1;

    let mut binom: Vec<Fr> = Vec::with_capacity(order + 1);
    binom.push(Fr::from(1u64));
    for j in 0..order {
        let next = binom[j]
            * Fr::from((order - j) as u64)
            * Fr::from((j + 1) as u64)
                .inverse()
                .expect("j+1 < Fr modulus");
        binom.push(next);
    }

    let mut h = Vec::with_capacity(n_rows);
    for k in 0..n_rows {
        let mut row = vec![Fr::ZERO; n];
        for j in 0..=order {
            let idx = k + j;
            let sign = if (order - j) % 2 == 0 {
                Fr::ONE
            } else {
                -Fr::ONE
            };
            row[idx] = sign * binom[j];
        }
        h.push(row);
    }
    h
}

fn check_parity(shares: &[Fr], h: &[Vec<Fr>]) -> bool {
    for row in h {
        let dot: Fr = row
            .iter()
            .zip(shares.iter())
            .map(|(h_ij, s_j)| *h_ij * s_j)
            .fold(Fr::ZERO, |a, x| a + x);
        if !dot.is_zero() {
            return false;
        }
    }
    true
}

fn interpolate_from_shares(shares: &[Fr], t: usize) -> Option<Vec<Fr>> {
    let pts: Vec<(usize, Fr)> = shares
        .iter()
        .enumerate()
        .take(t + 1)
        .map(|(i, &y)| (i + 1, y))
        .collect();
    interpolate_coeffs(&pts)
}

fn interpolate_coeffs(points: &[(usize, Fr)]) -> Option<Vec<Fr>> {
    let n = points.len();
    if n == 0 {
        return None;
    }
    let mut coeffs = vec![Fr::ZERO; n];
    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let x_i_fr = Fr::from(x_i as u64);
        let mut basis = vec![Fr::ONE];
        let mut denom = Fr::ONE;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j_fr = Fr::from(x_j as u64);
            denom *= x_i_fr - x_j_fr;
            let mut new_basis = vec![Fr::ZERO; basis.len() + 1];
            for (k, &c) in basis.iter().enumerate() {
                new_basis[k] += c * (-x_j_fr);
                new_basis[k + 1] += c;
            }
            basis = new_basis;
        }
        let inv = denom.inverse()?;
        let scale = y_i * inv;
        for (k, &c) in basis.iter().enumerate() {
            coeffs[k] += c * scale;
        }
    }
    Some(coeffs)
}

fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::ZERO, |acc, &c| acc * x + c)
}

pub fn prove_parity(
    chunk_shares: &[Vec<Fr>],
    n: usize,
    t: usize,
    norm_witness_data: &[u8],
    encryption_validity_data: &[u8],
) -> Option<ParityProof> {
    let h = generate_parity_matrix(n, t);
    for shares in chunk_shares {
        if shares.len() != n {
            return None;
        }
        if !h.is_empty() && !check_parity(shares, &h) {
            return None;
        }
    }
    let mut chunk_coeffs = Vec::with_capacity(chunk_shares.len());
    for shares in chunk_shares {
        chunk_coeffs.push(interpolate_from_shares(shares, t)?);
    }
    Some(ParityProof {
        chunk_coefficients: chunk_coeffs,
        n,
        t,
        norm_witness_hash: hash_norm_witness(norm_witness_data),
        encryption_validity_hash: hash_encryption_validity(encryption_validity_data),
    })
}

pub fn verify_parity(
    share_frs: &[Fr],
    index_i: usize,
    proof: &ParityProof,
    expected_norm_witness_hash: [u8; 32],
    expected_encryption_validity_hash: [u8; 32],
) -> bool {
    if share_frs.len() != proof.chunk_coefficients.len() {
        return false;
    }
    if index_i == 0 || index_i > proof.n {
        return false;
    }
    if proof.norm_witness_hash != expected_norm_witness_hash {
        return false;
    }
    if proof.encryption_validity_hash != expected_encryption_validity_hash {
        return false;
    }
    let x = Fr::from(index_i as u64);
    for (chunk_idx, coeffs) in proof.chunk_coefficients.iter().enumerate() {
        if eval_poly(coeffs, x) != share_frs[chunk_idx] {
            return false;
        }
    }
    true
}

const FR_BYTES: usize = 32;

pub fn serialize_parity_proof(proof: &ParityProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(proof.chunk_coefficients.len() as u32).to_be_bytes());
    out.extend_from_slice(&(proof.t as u32).to_be_bytes());
    out.extend_from_slice(&(proof.n as u32).to_be_bytes());
    for coeffs in &proof.chunk_coefficients {
        out.extend_from_slice(&(coeffs.len() as u32).to_be_bytes());
        for coeff in coeffs {
            let mut bytes = [0u8; FR_BYTES];
            let limbs = coeff.into_bigint().to_bytes_le();
            let take = limbs.len().min(FR_BYTES);
            bytes[..take].copy_from_slice(&limbs[..take]);
            out.extend_from_slice(&bytes);
        }
    }
    out.extend_from_slice(&proof.norm_witness_hash);
    out.extend_from_slice(&proof.encryption_validity_hash);
    out
}

pub fn deserialize_parity_proof(bytes: &[u8]) -> Option<ParityProof> {
    if bytes.len() < 76 {
        return None;
    }
    let num_chunks = u32::from_be_bytes(bytes[..4].try_into().ok()?) as usize;
    let t = u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize;
    let n = u32::from_be_bytes(bytes[8..12].try_into().ok()?) as usize;
    let mut offset: usize = 12;
    let mut chunk_coeffs = Vec::with_capacity(num_chunks);
    for _ in 0..num_chunks {
        if offset + 4 > bytes.len() {
            return None;
        }
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        let mut coeffs = Vec::with_capacity(len);
        for _ in 0..len {
            if offset + FR_BYTES > bytes.len() {
                return None;
            }
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                let lo = offset + i * 8;
                limbs[i] = u64::from_le_bytes(bytes[lo..lo + 8].try_into().ok()?);
            }
            coeffs.push(Fr::from_bigint(ark_ff::BigInt::<4>::new(limbs))?);
            offset += FR_BYTES;
        }
        chunk_coeffs.push(coeffs);
    }
    if offset + 64 > bytes.len() {
        return None;
    }
    let norm_witness_hash: [u8; 32] = bytes[offset..offset + 32].try_into().ok()?;
    offset += 32;
    let encryption_validity_hash: [u8; 32] = bytes[offset..offset + 32].try_into().ok()?;
    Some(ParityProof {
        chunk_coefficients: chunk_coeffs,
        n,
        t,
        norm_witness_hash,
        encryption_validity_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn parity_generation_dimensions() {
        let (n, t) = (10, 4);
        let h = generate_parity_matrix(n, t);
        assert_eq!(h.len(), n - t - 1);
        for row in &h {
            assert_eq!(row.len(), n);
        }

        let h2 = generate_parity_matrix(3, 2);
        assert!(h2.is_empty());

        let h3 = generate_parity_matrix(5, 5);
        assert!(h3.is_empty());
    }

    #[test]
    fn parity_check_valid_polynomial() {
        let mut rng = thread_rng();
        let (n, t) = (10, 4);
        let secret = Fr::rand(&mut rng);
        let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
        let values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();

        let h = generate_parity_matrix(n, t);
        assert!(!h.is_empty());
        assert!(check_parity(&values, &h));
    }

    #[test]
    fn parity_check_invalid_polynomial() {
        let mut rng = thread_rng();
        let (n, t) = (10, 4);
        let secret = Fr::rand(&mut rng);
        let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
        let mut values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();

        values[0] += Fr::ONE;

        let h = generate_parity_matrix(n, t);
        assert!(!check_parity(&values, &h));
    }

    #[test]
    fn parity_prove_verify_roundtrip() {
        let mut rng = thread_rng();
        let (n, t) = (10, 4);
        let num_chunks = 3;

        let mut chunk_shares: Vec<Vec<Fr>> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let secret = Fr::rand(&mut rng);
            let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
            chunk_shares.push(shares.iter().map(|(_, y)| *y).collect());
        }

        let empty_norm = hash_norm_witness(&[]);
        let empty_enc = hash_encryption_validity(&[]);
        let proof = prove_parity(&chunk_shares, n, t, &[], &[]).expect("prove_parity");

        for recipient in 1..=n {
            let mut share_frs = Vec::with_capacity(num_chunks);
            for chunk in &chunk_shares {
                share_frs.push(chunk[recipient - 1]);
            }
            assert!(verify_parity(
                &share_frs, recipient, &proof, empty_norm, empty_enc
            ));
        }

        let mut bad_frs = Vec::with_capacity(num_chunks);
        for chunk in &chunk_shares {
            bad_frs.push(chunk[0] + Fr::ONE);
        }
        assert!(!verify_parity(&bad_frs, 1, &proof, empty_norm, empty_enc));
    }

    #[test]
    fn parity_prove_verify_single_chunk() {
        let mut rng = thread_rng();
        let (n, t) = (16, 7);
        let secret = Fr::rand(&mut rng);
        let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
        let values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();

        let empty_norm = hash_norm_witness(&[]);
        let empty_enc = hash_encryption_validity(&[]);
        let proof = prove_parity(&[values.clone()], n, t, &[], &[]).expect("prove_parity");

        for i in 1..=n {
            assert!(verify_parity(
                &[values[i - 1]],
                i,
                &proof,
                empty_norm,
                empty_enc
            ));
        }
    }

    #[test]
    fn parity_serialization_roundtrip() {
        let mut rng = thread_rng();
        let (n, t) = (10, 4);
        let num_chunks = 2;
        let mut chunk_shares = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let secret = Fr::rand(&mut rng);
            let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
            chunk_shares.push(shares.iter().map(|(_, y)| *y).collect());
        }
        let proof = prove_parity(&chunk_shares, n, t, &[], &[]).expect("prove");

        let serialized = serialize_parity_proof(&proof);
        let deserialized = deserialize_parity_proof(&serialized).expect("deserialize");
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn parity_vacuous_case() {
        let mut rng = thread_rng();
        let secret = Fr::rand(&mut rng);
        let shares = shamir::split(&secret, 3, 2, &mut rng).expect("split");
        let values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();

        let h = generate_parity_matrix(3, 2);
        assert!(h.is_empty());
        assert!(check_parity(&values, &h));

        let empty_norm = hash_norm_witness(&[]);
        let empty_enc = hash_encryption_validity(&[]);
        let proof = prove_parity(&[values.clone()], 3, 2, &[], &[]).expect("prove vacuous");
        assert!(verify_parity(
            &[values[0]],
            1,
            &proof,
            empty_norm,
            empty_enc
        ));
    }

    #[test]
    fn parity_extended() {
        let mut rng = thread_rng();
        let (n, t) = (10, 4);
        let num_chunks = 3;

        let mut chunk_shares: Vec<Vec<Fr>> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let secret = Fr::rand(&mut rng);
            let shares = shamir::split(&secret, n, t, &mut rng).expect("split");
            chunk_shares.push(shares.iter().map(|(_, y)| *y).collect());
        }

        let norm_witness = b"test-norm-witness-data-for-binding";
        let enc_validity = b"test-encryption-validity-data";

        let proof =
            prove_parity(&chunk_shares, n, t, norm_witness, enc_validity).expect("prove_parity");

        let expected_norm = hash_norm_witness(norm_witness);
        let expected_enc = hash_encryption_validity(enc_validity);

        assert_eq!(proof.norm_witness_hash, expected_norm);
        assert_eq!(proof.encryption_validity_hash, expected_enc);

        for recipient in 1..=n {
            let mut share_frs = Vec::with_capacity(num_chunks);
            for chunk in &chunk_shares {
                share_frs.push(chunk[recipient - 1]);
            }
            assert!(verify_parity(
                &share_frs,
                recipient,
                &proof,
                expected_norm,
                expected_enc
            ));
        }

        // Wrong norm witness hash
        let wrong_norm = [0u8; 32];
        assert!(!verify_parity(
            &[chunk_shares[0][0]],
            1,
            &proof,
            wrong_norm,
            expected_enc,
        ));

        // Wrong encryption validity hash
        let wrong_enc = [0u8; 32];
        assert!(!verify_parity(
            &[chunk_shares[0][0]],
            1,
            &proof,
            expected_norm,
            wrong_enc,
        ));

        // Both wrong
        assert!(!verify_parity(
            &[chunk_shares[0][0]],
            1,
            &proof,
            wrong_norm,
            wrong_enc,
        ));

        // Serialization roundtrip preserves hashes
        let serialized = serialize_parity_proof(&proof);
        let deserialized = deserialize_parity_proof(&serialized).expect("deserialize");
        assert_eq!(proof, deserialized);
    }
}
