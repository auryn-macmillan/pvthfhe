//! Lattice-native sigma protocol for BFV encryption well-formedness.
//!
//! # Relation
//! Statement: (pk0, pk1, ct0, ct1) in R_Q^4, plus public delta values Δ[ℓ].
//! Witness:   (u, e0, e1, m) with bounded coefficients.
//! Relation:
//!   ct0[ℓ] = pk0[ℓ] * u + e0[ℓ] + Δ[ℓ] * m   mod q_ℓ   (per CRT limb ℓ)
//!   ct1[ℓ] = pk1[ℓ] * u + e1[ℓ]               mod q_ℓ   (per CRT limb ℓ)
//!
//! Witness bounds:
//!   |u_i|  ≤ B_U   (CBD with variance ~10)
//!   |e0_i| ≤ BFV_SIGMA_B_E   (discrete Gaussian error)
//!   |e1_i| ≤ BFV_SIGMA_B_E   (discrete Gaussian error)
//!   |m_i|  ≤ B_M   (raw plaintext polynomial, ≤ 65536 for BFV t=2^16)
//!
//! # Challenge Space
//! Binary polynomial ch in {0,1}^N derived via Fiat-Shamir (SHA-256 over
//! serialized commitment t0/t1 and all public statement fields).
//!
//! # Response Bounds
//! Masking bound B_Y = 2^30.
//! z_u = y_u + ch * u   (bound B_Z_U = B_Y + N * B_U)
//! z_e0 = y_e0 + ch * e0 (bound B_Z_E = B_Y + N * BFV_SIGMA_B_E)
//! z_e1 = y_e1 + ch * e1 (bound B_Z_E = B_Y + N * BFV_SIGMA_B_E)
//! z_m = y_m + ch * m   (bound B_Z_M = B_Y + N * B_M)
//! All fit in i64 since largest bound < 2^31 << 2^63.

use fhe_math::rq::{Context, Poly, Representation};
use fhe_traits::DeserializeWithContext;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

use crate::sigma::{
    int_poly_to_rns, poly_mul_rq, poly_mul_rq_to_int, rns_add, sample_bounded, RLWE_N, RLWE_Q0,
    RLWE_Q1, RLWE_Q2,
};
use crate::NizkError;

const MODULI: [u64; 3] = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
const RNS_LEN: usize = RLWE_N * 3;

/// Masking bound B_Y = 2^30.
pub const B_Y: i64 = 1_073_741_824;

/// Bound on encryption randomness coefficients (CBD with variance 10).
pub const B_U: i64 = 10_000;
/// Bound on BFV error polynomial coefficients.
pub const BFV_SIGMA_B_E: i64 = 10_000;
/// Plaintext modulus bound (t = 2^16 = 65536).
pub const B_M: i64 = 65_536;

const N_I64: i64 = 8192_i64;

/// Verifier norm bound for z_u: B_Y + N * B_U.
pub const B_Z_U: i64 = B_Y + N_I64 * B_U;
/// Verifier norm bound for z_e0 / z_e1: B_Y + N * BFV_SIGMA_B_E.
pub const B_Z_E: i64 = B_Y + N_I64 * BFV_SIGMA_B_E;
/// Verifier norm bound for z_m: B_Y + N * B_M.
pub const B_Z_M: i64 = B_Y + N_I64 * B_M;

fn rlwe_context() -> Result<&'static Arc<Context>, NizkError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        Context::new(&MODULI, RLWE_N)
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| NizkError::InvalidInput("failed to build RLWE context"))
}

/// Compute the BFV delta values: Δ[ℓ] = ⌊q_ℓ / t⌋.
pub fn bfv_delta_rns(t_plain: u64) -> Result<Vec<u64>, NizkError> {
    if t_plain == 0 {
        return Err(NizkError::InvalidInput(
            "plaintext modulus must be positive",
        ));
    }
    let ctx = rlwe_context()?;
    Ok(ctx.q.iter().map(|m| m.modulus() / t_plain).collect())
}

/// Public statement for the BFV encryption sigma protocol.
#[derive(Clone, Debug)]
pub struct BfvSigmaStatement {
    /// Public key polynnomial pk0 in RNS power-basis (length = 3*N).
    pub pk0_rns: Vec<u64>,
    /// Public key polynomial pk1 in RNS power-basis (length = 3*N).
    pub pk1_rns: Vec<u64>,
    /// Ciphertext polynomial ct0 in RNS power-basis (length = 3*N).
    pub ct0_rns: Vec<u64>,
    /// Ciphertext polynomial ct1 in RNS power-basis (length = 3*N).
    pub ct1_rns: Vec<u64>,
    /// BFV scaling factor per CRT limb (length = num_limbs = 3).
    pub delta_limbs: Vec<u64>,
}

/// Prover witness for the BFV encryption sigma protocol.
#[derive(Clone, Debug)]
pub struct BfvSigmaWitness {
    /// Encryption randomness polynomial u (length N, integer coefficients).
    pub u: Vec<i64>,
    /// Error polynomial for ct0 leg e0 (length N, integer coefficients).
    pub e0: Vec<i64>,
    /// Error polynomial for ct1 leg e1 (length N, integer coefficients).
    pub e1: Vec<i64>,
    /// Raw plaintext polynomial m (length N, integer coefficients, |m_i| ≤ B_M).
    pub m: Vec<i64>,
}

/// Sigma proof for the BFV encryption relation.
#[derive(Clone, Debug)]
pub struct BfvSigmaProof {
    /// Commitment t0 in RNS power-basis (length = 3*N).
    pub t0_rns: Vec<u64>,
    /// Commitment t1 in RNS power-basis (length = 3*N).
    pub t1_rns: Vec<u64>,
    /// Response z_u over Z^N (integer coefficients, length N).
    pub u_resp: Vec<i64>,
    /// Response z_e0 over Z^N (integer coefficients, length N).
    pub e0_resp: Vec<i64>,
    /// Response z_e1 over Z^N (integer coefficients, length N).
    pub e1_resp: Vec<i64>,
    /// Response z_m over Z^N (integer coefficients, length N).
    pub m_resp: Vec<i64>,
    /// Fiat-Shamir challenge polynomial ch in {0,1}^N (length N).
    pub ch: Vec<i64>,
}

/// Encode a raw byte slice into a plaintext polynomial suitable for the
/// sigma protocol.  Each byte becomes a coefficient; the polynomial is
/// zero-padded to N = 8192 coefficients.
pub fn encode_raw_plaintext(plaintext: &[u8]) -> Vec<i64> {
    let mut m = vec![0i64; RLWE_N];
    let len = plaintext.len().min(RLWE_N);
    for (i, &byte) in plaintext[..len].iter().enumerate() {
        m[i] = i64::from(byte);
    }
    m
}

/// Decode an fhe-math Poly serialised representation into the per-limb
/// u64 RNS coefficient array used by this module.
///
/// The byte slice must be a valid fhe-math `Poly` serialisation over
/// the same context (N=8192, 3 limbs).  The function converts to
/// power-basis before extracting coefficients.
pub fn poly_bytes_to_rns(poly_bytes: &[u8]) -> Result<Vec<u64>, NizkError> {
    let ctx = rlwe_context()?;
    let mut poly = Poly::from_bytes(poly_bytes, ctx)
        .map_err(|_| NizkError::InvalidInput("failed to deserialise Poly from bytes"))?;
    poly.change_representation(Representation::PowerBasis);
    Ok(Vec::<u64>::from(&poly))
}

/// Scale an integer polynomial `m_int` by the BFV delta per RNS limb.
///
/// Returns the Δ[ℓ] · p polynomial in RNS power-basis form.
/// Callers are responsible for coefficient domain bounds (e.g. B_M for
/// plaintexts, B_Y for masking polynomials).
pub fn scale_plaintext_to_rns(m_int: &[i64], delta: &[u64]) -> Result<Vec<u64>, NizkError> {
    let ctx = rlwe_context()?;
    let num_limbs = ctx.q.len();
    let n = RLWE_N;
    let mut out = vec![0u64; n * num_limbs];
    for (limb, &d) in delta.iter().enumerate() {
        let modulus = u128::from(ctx.q[limb].modulus());
        let d = u128::from(d);
        for (j, &coeff) in m_int.iter().enumerate() {
            let magnitude = u128::from(coeff.unsigned_abs());
            let scaled = (magnitude * d) % modulus;
            let r = if coeff < 0 && scaled != 0 {
                modulus - scaled
            } else {
                scaled
            };
            out[limb * n + j] = u64::try_from(r)
                .map_err(|_| NizkError::InvalidInput("scaled plaintext result out of u64 range"))?;
        }
    }
    Ok(out)
}

/// Produce a BFV sigma proof.
pub fn prove(
    stmt: &BfvSigmaStatement,
    wit: &BfvSigmaWitness,
    binding_data: &[u8],
    rng: &mut dyn RngCore,
) -> Result<BfvSigmaProof, NizkError> {
    if stmt.pk0_rns.len() != RNS_LEN
        || stmt.pk1_rns.len() != RNS_LEN
        || stmt.ct0_rns.len() != RNS_LEN
        || stmt.ct1_rns.len() != RNS_LEN
    {
        return Err(NizkError::InvalidInput("statement RNS lengths must be 3*N"));
    }
    if wit.u.len() != RLWE_N
        || wit.e0.len() != RLWE_N
        || wit.e1.len() != RLWE_N
        || wit.m.len() != RLWE_N
    {
        return Err(NizkError::InvalidInput(
            "witness polynomials must have length N",
        ));
    }
    if stmt.delta_limbs.len() != 3 {
        return Err(NizkError::InvalidInput("delta_limbs must have length 3"));
    }

    let ctx = rlwe_context()?;

    let y_u = sample_bounded(rng, RLWE_N, B_Y)?;
    let y_e0 = sample_bounded(rng, RLWE_N, B_Y)?;
    let y_e1 = sample_bounded(rng, RLWE_N, B_Y)?;
    let y_m = sample_bounded(rng, RLWE_N, B_Y)?;

    let y_u_rns = int_poly_to_rns(&y_u, ctx)?;
    let y_e0_rns = int_poly_to_rns(&y_e0, ctx)?;
    let y_e1_rns = int_poly_to_rns(&y_e1, ctx)?;

    let pk0_yu_rns = poly_mul_rq(&stmt.pk0_rns, &y_u_rns, ctx)?;
    let delta_ym_rns = scale_plaintext_to_rns(&y_m, &stmt.delta_limbs)?;
    let t0_rns = rns_add(&rns_add(&pk0_yu_rns, &y_e0_rns, ctx)?, &delta_ym_rns, ctx)?;

    let pk1_yu_rns = poly_mul_rq(&stmt.pk1_rns, &y_u_rns, ctx)?;
    let t1_rns = rns_add(&pk1_yu_rns, &y_e1_rns, ctx)?;

    let ch = derive_challenge(
        &t0_rns,
        &t1_rns,
        &stmt.pk0_rns,
        &stmt.pk1_rns,
        &stmt.ct0_rns,
        &stmt.ct1_rns,
        &stmt.delta_limbs,
        binding_data,
    );

    let ch_u = poly_mul_rq_to_int(&ch, &wit.u, ctx)?;
    let ch_e0 = poly_mul_rq_to_int(&ch, &wit.e0, ctx)?;
    let ch_e1 = poly_mul_rq_to_int(&ch, &wit.e1, ctx)?;
    let ch_m = poly_mul_rq_to_int(&ch, &wit.m, ctx)?;

    let u_resp: Vec<i64> = y_u.iter().zip(ch_u.iter()).map(|(&a, &b)| a + b).collect();
    let e0_resp: Vec<i64> = y_e0
        .iter()
        .zip(ch_e0.iter())
        .map(|(&a, &b)| a + b)
        .collect();
    let e1_resp: Vec<i64> = y_e1
        .iter()
        .zip(ch_e1.iter())
        .map(|(&a, &b)| a + b)
        .collect();
    let m_resp: Vec<i64> = y_m.iter().zip(ch_m.iter()).map(|(&a, &b)| a + b).collect();

    Ok(BfvSigmaProof {
        t0_rns,
        t1_rns,
        u_resp,
        e0_resp,
        e1_resp,
        m_resp,
        ch,
    })
}

/// Verify a BFV sigma proof against a statement.
pub fn verify(
    stmt: &BfvSigmaStatement,
    proof: &BfvSigmaProof,
    binding_data: &[u8],
) -> Result<(), NizkError> {
    if stmt.pk0_rns.len() != RNS_LEN
        || stmt.pk1_rns.len() != RNS_LEN
        || stmt.ct0_rns.len() != RNS_LEN
        || stmt.ct1_rns.len() != RNS_LEN
    {
        return Err(NizkError::InvalidInput("statement RNS lengths must be 3*N"));
    }
    if proof.t0_rns.len() != RNS_LEN || proof.t1_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput(
            "proof t0/t1_rns length must be 3*N",
        ));
    }
    if proof.u_resp.len() != RLWE_N
        || proof.e0_resp.len() != RLWE_N
        || proof.e1_resp.len() != RLWE_N
        || proof.m_resp.len() != RLWE_N
        || proof.ch.len() != RLWE_N
    {
        return Err(NizkError::InvalidInput(
            "proof polynomial lengths must be N",
        ));
    }

    let ctx = rlwe_context()?;

    let expected_ch = derive_challenge(
        &proof.t0_rns,
        &proof.t1_rns,
        &stmt.pk0_rns,
        &stmt.pk1_rns,
        &stmt.ct0_rns,
        &stmt.ct1_rns,
        &stmt.delta_limbs,
        binding_data,
    );
    let expected_ch_bytes: Vec<u8> = expected_ch.iter().flat_map(|x| x.to_le_bytes()).collect();
    let proof_ch_bytes: Vec<u8> = proof.ch.iter().flat_map(|x| x.to_le_bytes()).collect();
    if !bool::from(
        expected_ch_bytes
            .as_slice()
            .ct_eq(proof_ch_bytes.as_slice()),
    ) {
        return Err(NizkError::VerificationFailed("challenge mismatch"));
    }

    let max_u = proof.u_resp.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_u > B_Z_U {
        return Err(NizkError::VerificationFailed("z_u norm bound exceeded"));
    }
    let max_e0 = proof.e0_resp.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_e0 > B_Z_E {
        return Err(NizkError::VerificationFailed("z_e0 norm bound exceeded"));
    }
    let max_e1 = proof.e1_resp.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_e1 > B_Z_E {
        return Err(NizkError::VerificationFailed("z_e1 norm bound exceeded"));
    }
    let max_m = proof.m_resp.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_m > B_Z_M {
        return Err(NizkError::VerificationFailed("z_m norm bound exceeded"));
    }

    let u_resp_rns = int_poly_to_rns(&proof.u_resp, ctx)?;
    let e0_resp_rns = int_poly_to_rns(&proof.e0_resp, ctx)?;
    let e1_resp_rns = int_poly_to_rns(&proof.e1_resp, ctx)?;

    let pk0_u_resp_rns = poly_mul_rq(&stmt.pk0_rns, &u_resp_rns, ctx)?;
    let delta_m_resp_rns = scale_plaintext_to_rns(&proof.m_resp, &stmt.delta_limbs)?;
    let lhs0_rns = rns_add(
        &rns_add(&pk0_u_resp_rns, &e0_resp_rns, ctx)?,
        &delta_m_resp_rns,
        ctx,
    )?;

    let ch_rns = int_poly_to_rns(&proof.ch, ctx)?;
    let ch_ct0_rns = poly_mul_rq(&ch_rns, &stmt.ct0_rns, ctx)?;
    let rhs0_rns = rns_add(&proof.t0_rns, &ch_ct0_rns, ctx)?;

    if lhs0_rns != rhs0_rns {
        return Err(NizkError::VerificationFailed(
            "BFV ct0 equation: pk0*u_resp + e0_resp + Δ*m_resp != t0 + ch*ct0",
        ));
    }

    let pk1_u_resp_rns = poly_mul_rq(&stmt.pk1_rns, &u_resp_rns, ctx)?;
    let lhs1_rns = rns_add(&pk1_u_resp_rns, &e1_resp_rns, ctx)?;
    let ch_ct1_rns = poly_mul_rq(&ch_rns, &stmt.ct1_rns, ctx)?;
    let rhs1_rns = rns_add(&proof.t1_rns, &ch_ct1_rns, ctx)?;

    if lhs1_rns != rhs1_rns {
        return Err(NizkError::VerificationFailed(
            "BFV ct1 equation: pk1*u_resp + e1_resp != t1 + ch*ct1",
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_challenge(
    t0_rns: &[u64],
    t1_rns: &[u64],
    pk0_rns: &[u64],
    pk1_rns: &[u64],
    ct0_rns: &[u64],
    ct1_rns: &[u64],
    delta_limbs: &[u64],
    binding_data: &[u8],
) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-bfv-sigma-challenge-v1");

    let t0_bytes: Vec<u8> = t0_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(t0_bytes);
    let t1_bytes: Vec<u8> = t1_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(t1_bytes);
    let pk0_bytes: Vec<u8> = pk0_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(pk0_bytes);
    let pk1_bytes: Vec<u8> = pk1_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(pk1_bytes);
    let ct0_bytes: Vec<u8> = ct0_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(ct0_bytes);
    let ct1_bytes: Vec<u8> = ct1_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(ct1_bytes);
    let delta_bytes: Vec<u8> = delta_limbs.iter().flat_map(|x| x.to_le_bytes()).collect();
    hasher.update(delta_bytes);
    hasher.update(binding_data);

    let mut raw = [0u8; RLWE_N / 8];
    {
        let h = hasher.clone();
        let digest: [u8; 32] = h.finalize().into();
        let mut written = 0usize;
        let mut counter: u64 = 0;
        while written < raw.len() {
            let mut h_ext = Sha256::new();
            h_ext.update(counter.to_be_bytes());
            h_ext.update(digest);
            let block: [u8; 32] = h_ext.finalize().into();
            let take = (raw.len() - written).min(32);
            raw[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter += 1;
        }
    }

    let mut bits = Vec::with_capacity(RLWE_N);
    'outer: for byte in &raw {
        for bit_pos in 0..8u32 {
            if bits.len() < RLWE_N {
                bits.push(i64::from((byte >> bit_pos) & 1u8));
            } else {
                break 'outer;
            }
        }
    }
    bits
}

/// For use in tests and aggregators: encode a BfvSigmaProof into a byte vector.
pub fn encode_bfv_sigma_proof(proof: &BfvSigmaProof) -> Vec<u8> {
    let mut out = Vec::new();

    #[allow(clippy::as_conversions)]
    fn write_u64_vec(out: &mut Vec<u8>, v: &[u64]) {
        out.extend_from_slice(&u32::to_be_bytes(v.len() as u32));
        for x in v {
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
    #[allow(clippy::as_conversions)]
    fn write_i64_vec(out: &mut Vec<u8>, v: &[i64]) {
        out.extend_from_slice(&u32::to_be_bytes(v.len() as u32));
        for x in v {
            out.extend_from_slice(&x.to_le_bytes());
        }
    }

    write_u64_vec(&mut out, &proof.t0_rns);
    write_u64_vec(&mut out, &proof.t1_rns);
    write_i64_vec(&mut out, &proof.u_resp);
    write_i64_vec(&mut out, &proof.e0_resp);
    write_i64_vec(&mut out, &proof.e1_resp);
    write_i64_vec(&mut out, &proof.m_resp);
    write_i64_vec(&mut out, &proof.ch);

    out
}

/// Decode a serialised BfvSigmaProof from bytes.
pub fn decode_bfv_sigma_proof(bytes: &[u8]) -> Result<BfvSigmaProof, NizkError> {
    let mut offset = 0;

    fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Result<u32, NizkError> {
        let end = offset
            .checked_add(4)
            .ok_or(NizkError::InvalidInput("eof"))?;
        let arr: [u8; 4] = bytes
            .get(*offset..end)
            .ok_or(NizkError::InvalidInput("eof"))?
            .try_into()
            .map_err(|_| NizkError::InvalidInput("eof"))?;
        *offset = end;
        Ok(u32::from_be_bytes(arr))
    }

    fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, NizkError> {
        let end = offset
            .checked_add(8)
            .ok_or(NizkError::InvalidInput("eof"))?;
        let arr: [u8; 8] = bytes
            .get(*offset..end)
            .ok_or(NizkError::InvalidInput("eof"))?
            .try_into()
            .map_err(|_| NizkError::InvalidInput("eof"))?;
        *offset = end;
        Ok(u64::from_le_bytes(arr))
    }

    fn read_i64_le(bytes: &[u8], offset: &mut usize) -> Result<i64, NizkError> {
        let end = offset
            .checked_add(8)
            .ok_or(NizkError::InvalidInput("eof"))?;
        let arr: [u8; 8] = bytes
            .get(*offset..end)
            .ok_or(NizkError::InvalidInput("eof"))?
            .try_into()
            .map_err(|_| NizkError::InvalidInput("eof"))?;
        *offset = end;
        Ok(i64::from_le_bytes(arr))
    }

    #[allow(clippy::as_conversions)]
    fn read_u64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u64>, NizkError> {
        let len = read_u32_le(bytes, offset)? as usize;
        if len > 1_000_000 {
            return Err(NizkError::InvalidInput("vec too large"));
        }
        (0..len).map(|_| read_u64_le(bytes, offset)).collect()
    }

    #[allow(clippy::as_conversions)]
    fn read_i64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<i64>, NizkError> {
        let len = read_u32_le(bytes, offset)? as usize;
        if len > 1_000_000 {
            return Err(NizkError::InvalidInput("vec too large"));
        }
        (0..len).map(|_| read_i64_le(bytes, offset)).collect()
    }

    let t0_rns = read_u64_vec(bytes, &mut offset)?;
    let t1_rns = read_u64_vec(bytes, &mut offset)?;
    let u_resp = read_i64_vec(bytes, &mut offset)?;
    let e0_resp = read_i64_vec(bytes, &mut offset)?;
    let e1_resp = read_i64_vec(bytes, &mut offset)?;
    let m_resp = read_i64_vec(bytes, &mut offset)?;
    let ch = read_i64_vec(bytes, &mut offset)?;

    if offset != bytes.len() {
        return Err(NizkError::InvalidInput("trailing bytes in proof"));
    }

    Ok(BfvSigmaProof {
        t0_rns,
        t1_rns,
        u_resp,
        e0_resp,
        e1_resp,
        m_resp,
        ch,
    })
}
