use rand_core::RngCore as RngCoreV6;

use poulpy_ckks::{
    encoding::Encoder,
    layouts::{CKKSCiphertext, CKKSPlaintextConversion, CKKSPlaintextVecRnx, CKKSPlaintextVecZnx},
    leveled::api::{CKKSAddOps, CKKSDecrypt, CKKSEncrypt, CKKSMulOps},
    CKKSInfos, CKKSMeta,
};
use poulpy_core::{
    layouts::{
        prepared::{GLWESecretPreparedFactory, GLWETensorKeyPreparedFactory},
        GGLWEInfos, GLWEInfos, GLWELayout, GLWESecret, GLWETensorKey, GLWETensorKeyLayout,
        LWEInfos,
    },
    EncryptionLayout, GLWETensorKeyEncryptSk,
};
use poulpy_cpu_ref::NTT120Ref;
use poulpy_hal::{
    api::{ScratchOwnedAlloc, ScratchOwnedBorrow},
    layouts::{Module, ScratchOwned},
    source::Source,
};

use pvthfhe_fhe::error::FheError;

use crate::poulpy_inner::PoulpyInner;

type BE = NTT120Ref;

fn into_fhe(err: impl std::fmt::Display) -> FheError {
    FheError::Backend {
        reason: format!("{err}"),
    }
}

fn seed_from_rng(rng: &mut dyn RngCoreV6) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

fn module_from_inner(inner: &PoulpyInner) -> Result<&Module<BE>, FheError> {
    inner.ckks_module.as_ref().ok_or_else(|| FheError::Backend {
        reason: "CKKS module not initialized".into(),
    })
}

fn glwe_layout_from_inner(inner: &PoulpyInner) -> Result<GLWELayout, FheError> {
    let l = inner
        .ckks_glwe_layout
        .as_ref()
        .ok_or_else(|| FheError::Backend {
            reason: "CKKS GLWE layout not set".into(),
        })?;
    Ok(GLWELayout {
        n: l.n,
        base2k: l.base2k,
        k: l.k,
        rank: l.rank,
    })
}

fn tsk_layout_from_inner(inner: &PoulpyInner) -> Result<GLWETensorKeyLayout, FheError> {
    let l = inner
        .ckks_tsk_layout
        .as_ref()
        .ok_or_else(|| FheError::Backend {
            reason: "CKKS TSK layout not set".into(),
        })?;
    Ok(GLWETensorKeyLayout {
        n: l.n,
        base2k: l.base2k,
        k: l.k,
        rank: l.rank,
        dsize: l.dsize,
        dnum: l.dnum,
    })
}

unsafe fn raw_bytes_ptr<T>(obj: &T) -> &Vec<u8> {
    &*(obj as *const T as *const Vec<u8>)
}

unsafe fn raw_bytes_ptr_mut<T>(obj: &mut T) -> &mut Vec<u8> {
    &mut *(obj as *mut T as *mut Vec<u8>)
}

fn secret_to_bytes(sk: &GLWESecret<Vec<u8>>) -> Vec<u8> {
    unsafe { raw_bytes_ptr(sk).clone() }
}

fn secret_from_bytes(glwe: &GLWELayout, bytes: &[u8]) -> Result<GLWESecret<Vec<u8>>, FheError> {
    let n: usize = glwe.n().into();
    let rank: usize = glwe.rank().into();
    let expected = n * rank * 8;
    if bytes.len() != expected {
        return Err(FheError::Backend {
            reason: format!(
                "secret key bytes length mismatch: expected {expected}, got {}",
                bytes.len()
            ),
        });
    }
    let mut sk = GLWESecret::alloc_from_infos(glwe);
    unsafe {
        raw_bytes_ptr_mut(&mut sk).copy_from_slice(bytes);
    }
    Ok(sk)
}

fn tsk_to_bytes(tsk: &GLWETensorKey<Vec<u8>>) -> Vec<u8> {
    unsafe { raw_bytes_ptr(tsk).clone() }
}

fn tsk_from_bytes(
    tsk_layout: &GLWETensorKeyLayout,
    bytes: &[u8],
) -> Result<GLWETensorKey<Vec<u8>>, FheError> {
    let n: usize = tsk_layout.n().into();
    let base2k: usize = tsk_layout.base2k().into();
    let rank: usize = tsk_layout.rank().into();
    let dnum: usize = tsk_layout.dnum().into();
    let expected_bytes =
        poulpy_hal::layouts::MatZnx::<Vec<u8>>::bytes_of(n, base2k, rank + 1, 2, dnum);
    if bytes.len() != expected_bytes {
        return Err(FheError::Backend {
            reason: format!(
                "tensor key bytes length mismatch: expected {expected_bytes}, got {}",
                bytes.len()
            ),
        });
    }
    let mut tsk = GLWETensorKey::alloc_from_infos(tsk_layout);
    unsafe {
        raw_bytes_ptr_mut(&mut tsk).copy_from_slice(bytes);
    }
    Ok(tsk)
}

fn ct_to_bytes(ct: &CKKSCiphertext<Vec<u8>>) -> Vec<u8> {
    let meta = [ct.log_delta() as u32, ct.log_budget() as u32];
    let raw = unsafe { raw_bytes_ptr(ct) };
    let mut out = Vec::with_capacity(8 + raw.len());
    out.extend_from_slice(&meta[0].to_le_bytes());
    out.extend_from_slice(&meta[1].to_le_bytes());
    out.extend_from_slice(raw);
    out
}

fn ct_from_bytes(
    glwe_layout: &GLWELayout,
    bytes: &[u8],
) -> Result<CKKSCiphertext<Vec<u8>>, FheError> {
    if bytes.len() < 8 {
        return Err(FheError::Backend {
            reason: format!("ciphertext bytes too short: {}", bytes.len()),
        });
    }
    let log_delta = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let log_budget = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let data = &bytes[8..];

    let n: usize = glwe_layout.n().into();
    let rank: usize = glwe_layout.rank().into();
    let k: usize = glwe_layout.max_k().into();
    let expected = n * (rank + 1) * k * 8;
    if data.len() != expected {
        return Err(FheError::Backend {
            reason: format!(
                "ciphertext data bytes length mismatch: expected {expected}, got {}",
                data.len()
            ),
        });
    }

    let mut ct = CKKSCiphertext::alloc(n.into(), k.into(), glwe_layout.base2k());
    ct.set_meta_checked(CKKSMeta {
        log_delta,
        log_budget,
    })
    .map_err(|e| FheError::Backend {
        reason: format!("{e}"),
    })?;
    unsafe {
        raw_bytes_ptr_mut(&mut ct).copy_from_slice(data);
    }
    Ok(ct)
}

pub(crate) fn keygen(
    inner: &PoulpyInner,
    rng: &mut dyn RngCoreV6,
) -> Result<(Vec<u8>, Vec<u8>), FheError> {
    let module = module_from_inner(inner)?;
    let glwe = glwe_layout_from_inner(inner)?;
    let tsk_layout = tsk_layout_from_inner(inner)?;

    let mut source_xs = Source::new(seed_from_rng(rng));
    let mut source_xa = Source::new(seed_from_rng(rng));
    let mut source_xe = Source::new(seed_from_rng(rng));

    let mut sk_raw = GLWESecret::alloc_from_infos(&glwe);
    let hw = 192usize;
    sk_raw.fill_ternary_hw(hw, &mut source_xs);

    let tsk_enc_layout =
        EncryptionLayout::new_from_default_sigma(tsk_layout.clone()).map_err(into_fhe)?;
    let mut tsk = GLWETensorKey::alloc_from_infos(&tsk_enc_layout);
    let scratch_bytes = module.glwe_tensor_key_encrypt_sk_tmp_bytes(&tsk_enc_layout);
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);
    module.glwe_tensor_key_encrypt_sk(
        &mut tsk,
        &sk_raw,
        &tsk_enc_layout,
        &mut source_xa,
        &mut source_xe,
        scratch.borrow(),
    );

    Ok((secret_to_bytes(&sk_raw), tsk_to_bytes(&tsk)))
}

pub(crate) fn encrypt(
    inner: &PoulpyInner,
    sk_bytes: &[u8],
    _tsk_bytes: &[u8],
    plaintext: &[u8],
    rng: &mut dyn RngCoreV6,
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let glwe = glwe_layout_from_inner(inner)?;

    let sk_raw = secret_from_bytes(&glwe, sk_bytes)?;
    let mut sk = module.glwe_secret_prepared_alloc_from_infos(&glwe);
    module.glwe_secret_prepare(&mut sk, &sk_raw);

    let value = if plaintext.len() >= 8 {
        f64::from_le_bytes(plaintext[..8].try_into().unwrap())
    } else {
        let mut buf = [0u8; 8];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        f64::from_le_bytes(buf)
    };

    let n: usize = glwe.n().into();
    let base2k: usize = glwe.base2k().into();
    let meta = CKKSMeta {
        log_delta: 30,
        log_budget: usize::from(glwe.max_k()) * base2k - 30,
    };
    let mut pt_rnx = CKKSPlaintextVecRnx::<f64>::alloc(n).map_err(into_fhe)?;
    let encoder = Encoder::<f64>::new(n / 2).map_err(into_fhe)?;
    let re = vec![value; n / 2];
    let im = vec![0.0f64; n / 2];
    encoder
        .encode_reim(&mut pt_rnx, &re, &im)
        .map_err(into_fhe)?;

    let mut pt_znx = CKKSPlaintextVecZnx::alloc(glwe.n(), glwe.base2k(), meta);
    pt_rnx.to_znx(&mut pt_znx).map_err(into_fhe)?;

    let k = glwe.max_k();
    let mut ct = CKKSCiphertext::alloc(glwe.n(), k, glwe.base2k());
    let enc_layout = EncryptionLayout::new_from_default_sigma(glwe).map_err(into_fhe)?;
    let mut source_xa = Source::new(seed_from_rng(rng));
    let mut source_xe = Source::new(seed_from_rng(rng));
    module
        .ckks_encrypt_sk(
            &mut ct,
            &pt_znx,
            &sk,
            &enc_layout,
            &mut source_xa,
            &mut source_xe,
            ScratchOwned::<BE>::alloc(1024).borrow(),
        )
        .map_err(into_fhe)?;

    Ok(ct_to_bytes(&ct))
}

pub(crate) fn decrypt(
    inner: &PoulpyInner,
    sk_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let glwe = glwe_layout_from_inner(inner)?;
    let n: usize = glwe.n().into();

    let sk_raw = secret_from_bytes(&glwe, sk_bytes)?;
    let mut sk = module.glwe_secret_prepared_alloc_from_infos(&glwe);
    module.glwe_secret_prepare(&mut sk, &sk_raw);

    let ct = ct_from_bytes(&glwe, ct_bytes)?;

    let mut pt_znx = CKKSPlaintextVecZnx::alloc_from_infos(&ct);
    let scratch_bytes = module.ckks_decrypt_tmp_bytes(&glwe);
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);
    module
        .ckks_decrypt(&mut pt_znx, &ct, &sk, scratch.borrow())
        .map_err(into_fhe)?;

    let mut pt_rnx = CKKSPlaintextVecRnx::<f64>::alloc(n).map_err(into_fhe)?;
    pt_rnx.decode_from_znx(&pt_znx).map_err(into_fhe)?;

    let half_n = n / 2;
    let mut re = vec![0.0f64; half_n];
    let mut im = vec![0.0f64; half_n];
    let encoder = Encoder::<f64>::new(half_n).map_err(into_fhe)?;
    encoder
        .decode_reim(&pt_rnx, &mut re, &mut im)
        .map_err(into_fhe)?;

    Ok(re[0].to_le_bytes().to_vec())
}

pub(crate) fn add(
    inner: &PoulpyInner,
    ct0_bytes: &[u8],
    ct1_bytes: &[u8],
    _tsk_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let glwe = glwe_layout_from_inner(inner)?;

    let ct0 = ct_from_bytes(&glwe, ct0_bytes)?;
    let ct1 = ct_from_bytes(&glwe, ct1_bytes)?;

    let k = ct0.effective_k().max(ct1.effective_k());
    let mut dst = CKKSCiphertext::alloc(glwe.n(), k.into(), glwe.base2k());
    let scratch_bytes = module.ckks_add_tmp_bytes();
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);
    module
        .ckks_add_into(&mut dst, &ct0, &ct1, scratch.borrow())
        .map_err(into_fhe)?;

    Ok(ct_to_bytes(&dst))
}

pub(crate) fn mul(
    inner: &PoulpyInner,
    ct0_bytes: &[u8],
    ct1_bytes: &[u8],
    tsk_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    let module = module_from_inner(inner)?;
    let glwe = glwe_layout_from_inner(inner)?;
    let tsk_layout = tsk_layout_from_inner(inner)?;

    let ct0 = ct_from_bytes(&glwe, ct0_bytes)?;
    let ct1 = ct_from_bytes(&glwe, ct1_bytes)?;

    let tsk_raw = tsk_from_bytes(&tsk_layout, tsk_bytes)?;
    let mut tsk_prepared = module.alloc_tensor_key_prepared_from_infos(&tsk_layout);
    let prep_scratch_bytes = module.prepare_tensor_key_tmp_bytes(&tsk_layout);
    let mut prep_scratch = ScratchOwned::<BE>::alloc(prep_scratch_bytes);
    module.prepare_tensor_key(&mut tsk_prepared, &tsk_raw, prep_scratch.borrow());

    let k: u32 = ct0.effective_k().max(ct1.effective_k()) as u32;
    let mut dst = CKKSCiphertext::alloc(glwe.n(), k.into(), glwe.base2k());
    let scratch_bytes = module.ckks_mul_tmp_bytes(&glwe, &tsk_layout);
    let mut scratch = ScratchOwned::<BE>::alloc(scratch_bytes);
    module
        .ckks_mul_into(&mut dst, &ct0, &ct1, &tsk_prepared, scratch.borrow())
        .map_err(into_fhe)?;

    Ok(ct_to_bytes(&dst))
}
