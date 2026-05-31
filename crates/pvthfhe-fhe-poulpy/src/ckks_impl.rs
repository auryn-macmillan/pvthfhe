#![allow(dead_code)]

use poulpy_ckks::CKKSMeta;
use poulpy_core::layouts::{
    Base2K, Degree, Dnum, Dsize, GLWELayout, GLWETensorKeyLayout, Rank, TorusPrecision,
};

use crate::FheError;

pub(crate) fn rng_v10_seed(rng: &mut dyn rand_core::RngCore) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

pub(crate) fn ckks_glwe_layout(n: u32) -> Result<GLWELayout, FheError> {
    if !n.is_power_of_two() || n < 512 {
        return Err(FheError::InvalidParams {
            reason: format!("CKKS requires N power of two >= 512, got {n}"),
        });
    }
    Ok(GLWELayout {
        n: Degree(n),
        base2k: Base2K(52),
        k: TorusPrecision(728),
        rank: Rank(1),
    })
}

pub(crate) fn ckks_meta() -> CKKSMeta {
    CKKSMeta {
        log_delta: 40,
        log_budget: 728 - 40,
    }
}

pub(crate) fn ckks_tsk_layout(n: u32) -> GLWETensorKeyLayout {
    let dsize = 1usize;
    let base2k = 52;
    let k = 728usize;
    GLWETensorKeyLayout {
        n: Degree(n),
        base2k: Base2K(base2k as u32),
        k: TorusPrecision((k + dsize * base2k) as u32),
        rank: Rank(1),
        dsize: Dsize(dsize as u32),
        dnum: Dnum(k.div_ceil(dsize * base2k) as u32),
    }
}
