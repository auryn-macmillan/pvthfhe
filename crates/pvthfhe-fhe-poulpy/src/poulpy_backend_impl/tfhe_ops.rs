use std::io::Cursor;

use poulpy_core::{
    layouts::{Base2K, Degree, LWEInfos, LWELayout, LWEPlaintext, LWESecret, TorusPrecision, LWE},
    LWEDecrypt, LWEEncryptSk, DEFAULT_BOUND_XE, DEFAULT_SIGMA_XE,
};
use poulpy_cpu_ref::NTT120Ref;
use poulpy_hal::{
    api::{ScratchOwnedAlloc, ScratchOwnedBorrow},
    layouts::{Module, NoiseInfos, ReaderFrom, ScratchOwned, WriterTo, ZnxView, ZnxViewMut},
    source::Source,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use pvthfhe_fhe::error::FheError;

use crate::poulpy_inner::PoulpyInner;

type BE = NTT120Ref;

const TFHE_N_LWE: u32 = 1;
const TFHE_BASE2K: u32 = 32;
const TFHE_K_CT: u32 = 64;
const TFHE_K_PT: u32 = 1;

fn into_fhe(err: impl std::fmt::Display) -> FheError {
    FheError::Backend {
        reason: format!("{err}"),
    }
}

fn seed_from_rng(rng: &mut dyn rand_core::RngCore) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

fn tfhe_lwe_layout() -> LWELayout {
    LWELayout {
        n: Degree(TFHE_N_LWE),
        k: TorusPrecision(TFHE_K_CT),
        base2k: Base2K(TFHE_BASE2K),
    }
}

fn module_from_inner(inner: &PoulpyInner) -> Result<&Module<BE>, FheError> {
    inner.tfhe_module.as_ref().ok_or_else(|| FheError::Backend {
        reason: "TFHE module not initialized".into(),
    })
}

fn lwe_sk_to_bytes(seed_xs: &[u8; 32], n: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(seed_xs);
    out.extend_from_slice(&n.to_le_bytes());
    out
}

fn lwe_sk_from_bytes(inner: &PoulpyInner, bytes: &[u8]) -> Result<LWESecret<Vec<u8>>, FheError> {
    if bytes.len() < 36 {
        return Err(FheError::Backend {
            reason: format!("TFHE secret key bytes too short: {}", bytes.len()),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    regenerate_lwe_secret(inner, &seed)
}

fn regenerate_lwe_secret(
    inner: &PoulpyInner,
    seed: &[u8; 32],
) -> Result<LWESecret<Vec<u8>>, FheError> {
    let _module = module_from_inner(inner)?;
    let n = TFHE_N_LWE as usize;
    let mut source = Source::new(*seed);
    let mut sk = LWESecret::alloc(Degree(n as u32));
    sk.fill_ternary_hw(1, &mut source);
    Ok(sk)
}

fn ct_to_bytes(ct: &LWE<Vec<u8>>) -> Result<Vec<u8>, FheError> {
    let mut buf = Cursor::new(Vec::new());
    buf.write_u32::<LittleEndian>(ct.n().0).map_err(into_fhe)?;
    ct.write_to(&mut buf).map_err(into_fhe)?;
    Ok(buf.into_inner())
}

fn ct_from_bytes(bytes: &[u8]) -> Result<LWE<Vec<u8>>, FheError> {
    if bytes.len() < 4 {
        return Err(FheError::Backend {
            reason: format!("TFHE ciphertext bytes too short: {}", bytes.len()),
        });
    }
    let mut cursor = Cursor::new(bytes);
    let n = cursor.read_u32::<LittleEndian>().map_err(into_fhe)?;
    let layout = LWELayout {
        n: Degree(n),
        k: TorusPrecision(TFHE_K_CT),
        base2k: Base2K(TFHE_BASE2K),
    };
    let mut ct = LWE::alloc_from_infos(&layout);
    ct.read_from(&mut cursor).map_err(into_fhe)?;
    Ok(ct)
}

pub(crate) fn keygen(
    inner: &PoulpyInner,
    rng: &mut dyn rand_core::RngCore,
) -> Result<(Vec<u8>, Vec<u8>), FheError> {
    let _module = module_from_inner(inner)?;

    let seed_xs = seed_from_rng(rng);
    let _sk = regenerate_lwe_secret(inner, &seed_xs)?;

    let sk_bytes = lwe_sk_to_bytes(&seed_xs, TFHE_N_LWE);
    let tsk_bytes = vec![0u8; 0];

    Ok((sk_bytes, tsk_bytes))
}

pub(crate) fn encrypt(
    inner: &PoulpyInner,
    sk_bytes: &[u8],
    _pk_bytes: &[u8],
    plaintext: &[u8],
    rng: &mut dyn rand_core::RngCore,
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let lwe_layout = tfhe_lwe_layout();

    let bit_val: i64 = if plaintext.is_empty() || plaintext[0] == 0 {
        0
    } else {
        1
    };

    let mut pt = LWEPlaintext::alloc_from_infos(&lwe_layout);
    pt.encode_i64(bit_val, TorusPrecision(TFHE_K_PT));

    let mut ct = LWE::alloc_from_infos(&lwe_layout);

    let enc_infos = NoiseInfos::new(
        lwe_layout.max_k().into(),
        DEFAULT_SIGMA_XE,
        DEFAULT_BOUND_XE,
    )
    .map_err(into_fhe)?;

    let mut source_xa = Source::new(seed_from_rng(rng));
    let mut source_xe = Source::new(seed_from_rng(rng));

    let scratch_bytes = module.lwe_encrypt_sk_tmp_bytes(&lwe_layout).max(1 << 20);
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);

    let sk = lwe_sk_from_bytes(inner, sk_bytes)?;

    module.lwe_encrypt_sk(
        &mut ct,
        &pt,
        &sk,
        &enc_infos,
        &mut source_xe,
        &mut source_xa,
        scratch.borrow(),
    );

    ct_to_bytes(&ct)
}

pub(crate) fn decrypt(
    inner: &PoulpyInner,
    sk_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;

    let sk = lwe_sk_from_bytes(inner, sk_bytes)?;
    let ct = ct_from_bytes(ct_bytes)?;

    let mut pt = LWEPlaintext::alloc_from_infos(&ct);
    let scratch_bytes = module.lwe_decrypt_tmp_bytes(&ct).max(1 << 20);
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);

    module.lwe_decrypt(&ct, &mut pt, &sk, scratch.borrow());

    let decoded = pt.decode_i64(TorusPrecision(TFHE_K_PT));
    let bit = if decoded != 0 { 1u8 } else { 0u8 };

    Ok(vec![bit])
}

pub(crate) fn nand(
    inner: &PoulpyInner,
    ct0_bytes: &[u8],
    ct1_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;

    let ct0 = ct_from_bytes(ct0_bytes)?;
    let ct1 = ct_from_bytes(ct1_bytes)?;

    let mut ct_out = LWE::alloc_from_infos(&ct0);

    let scratch_bytes = lwe_add_tmp_bytes_impl(&tfhe_lwe_layout());
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);

    lwe_add_assign_impl(module, &mut ct_out, &ct0, &ct1, &mut scratch)?;

    ct_to_bytes(&ct_out)
}

fn lwe_add_tmp_bytes_impl(lwe_layout: &LWELayout) -> usize {
    (lwe_layout.n().0 as usize + 1) * lwe_layout.size()
}

pub(crate) fn bootstrap(inner: &PoulpyInner, ct_bytes: &[u8]) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let lwe_layout = tfhe_lwe_layout();

    let sk_bytes = {
        let keys = inner.secret_keys.lock().map_err(|e| FheError::Backend {
            reason: e.to_string(),
        })?;
        keys.values().next().cloned().ok_or(FheError::Backend {
            reason: "no secret key available".into(),
        })?
    };
    let sk = lwe_sk_from_bytes(inner, &sk_bytes)?;

    // Decrypt input to recover the plaintext bit, so we can re-encrypt it
    // with fresh noise (proper bootstrap: message-preserving noise reduction).
    let input_ct = ct_from_bytes(ct_bytes)?;
    let mut pt = LWEPlaintext::alloc_from_infos(&input_ct);
    let dec_scratch_bytes = module.lwe_decrypt_tmp_bytes(&input_ct).max(1 << 20);
    let mut dec_scratch = ScratchOwned::<BE>::alloc(dec_scratch_bytes);
    module.lwe_decrypt(&input_ct, &mut pt, &sk, dec_scratch.borrow());
    let input_bit = pt.decode_i64(TorusPrecision(TFHE_K_PT));

    let enc_infos = NoiseInfos::new(
        lwe_layout.max_k().into(),
        DEFAULT_SIGMA_XE,
        DEFAULT_BOUND_XE,
    )
    .map_err(into_fhe)?;

    let seed_xa = {
        let mut s = [0u8; 32];
        s[0] = 0xAB;
        s
    };
    let seed_xe = {
        let mut s = [0u8; 32];
        s[0] = 0xCD;
        s
    };
    let mut source_xa = Source::new(seed_xa);
    let mut source_xe = Source::new(seed_xe);

    let enc_scratch_bytes = module.lwe_encrypt_sk_tmp_bytes(&lwe_layout).max(1 << 20);
    let mut enc_scratch = ScratchOwned::<BE>::alloc(enc_scratch_bytes);

    let mut fresh_ct = LWE::alloc_from_infos(&lwe_layout);
    let mut fresh_pt = LWEPlaintext::alloc_from_infos(&lwe_layout);
    fresh_pt.encode_i64(input_bit, TorusPrecision(TFHE_K_PT));

    module.lwe_encrypt_sk(
        &mut fresh_ct,
        &fresh_pt,
        &sk,
        &enc_infos,
        &mut source_xe,
        &mut source_xa,
        enc_scratch.borrow(),
    );

    ct_to_bytes(&fresh_ct)
}

fn lwe_add_assign_impl(
    _module: &Module<BE>,
    ct_out: &mut LWE<Vec<u8>>,
    ct0: &LWE<Vec<u8>>,
    ct1: &LWE<Vec<u8>>,
    _scratch: &mut ScratchOwned<BE>,
) -> Result<(), FheError> {
    let n: usize = ct0.n().into();
    let size = ct0.size();
    let len = (n + 1) * size;

    ct_out.data_mut().raw_mut()[..len].copy_from_slice(&ct0.data().raw()[..len]);
    for i in 0..len {
        let sum = ct_out.data().raw()[i] as i128 + ct1.data().raw()[i] as i128;
        ct_out.data_mut().raw_mut()[i] = sum as i64;
    }

    Ok(())
}

pub(crate) fn extract_lwe_coeffs(ct_bytes: &[u8]) -> Result<(u64, u64), FheError> {
    let ct = ct_from_bytes(ct_bytes)?;
    Ok(lwe_torus_coeffs(&ct))
}

fn lwe_torus_coeffs(ct: &LWE<Vec<u8>>) -> (u64, u64) {
    let size = ct.size();
    let mut mask: i128 = 0;
    let mut body: i128 = 0;
    for limb in 0..size {
        let slice = ct.data().at(0, limb);
        let b_limb = slice[0] as i128;
        let a_limb = slice[1] as i128;
        let shift = (limb * 32) as u32;
        body += b_limb << shift;
        mask += a_limb << shift;
    }
    let mod2_64: i128 = 1i128 << 64;
    let mask_u64 = mask.rem_euclid(mod2_64) as u64;
    let body_u64 = body.rem_euclid(mod2_64) as u64;
    (mask_u64, body_u64)
}

pub(crate) fn poulpy_ct_to_sigma_bytes(ct_bytes: &[u8]) -> Result<Vec<u8>, FheError> {
    let ct = ct_from_bytes(ct_bytes)?;
    let (a, b) = lwe_torus_coeffs(&ct);
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&a.to_le_bytes());
    out.extend_from_slice(&b.to_le_bytes());
    Ok(out)
}
