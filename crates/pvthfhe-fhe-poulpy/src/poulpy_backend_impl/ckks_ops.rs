use rand_core::RngCore as RngCoreV6;

use pvthfhe_fhe::error::FheError;

use crate::poulpy_inner::PoulpyInner;

pub(crate) fn keygen(
    _inner: &PoulpyInner,
    _rng: &mut dyn RngCoreV6,
) -> Result<(Vec<u8>, Vec<u8>), FheError> {
    todo!("CKKS keygen using poulpy-ckks")
}

pub(crate) fn encrypt(
    _inner: &PoulpyInner,
    _sk_bytes: &[u8],
    _tsk_bytes: &[u8],
    _plaintext: &[u8],
    _rng: &mut dyn RngCoreV6,
) -> Result<Vec<u8>, FheError> {
    todo!("CKKS encrypt using poulpy-ckks")
}

pub(crate) fn decrypt(
    _inner: &PoulpyInner,
    _sk_bytes: &[u8],
    _ct_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    todo!("CKKS decrypt using poulpy-ckks")
}

pub(crate) fn add(
    _inner: &PoulpyInner,
    _ct0_bytes: &[u8],
    _ct1_bytes: &[u8],
    _tsk_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    todo!("CKKS add using poulpy-ckks")
}

pub(crate) fn mul(
    _inner: &PoulpyInner,
    _ct0_bytes: &[u8],
    _ct1_bytes: &[u8],
    _tsk_bytes: &[u8],
) -> Result<Vec<u8>, FheError> {
    todo!("CKKS mul using poulpy-ckks")
}
