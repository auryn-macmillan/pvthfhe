pub mod fhe_rs;
pub mod poulpy;

pub const POLY_DEGREE: usize = 4096;
pub const RNS_LIMBS: usize = 4;
pub const MODULI_60_BIT: [u64; RNS_LIMBS] = [
    4611686018326724609,
    4611686018309947393,
    4611686018282684417,
    4611686018257518593,
];

pub trait RqOps {
    fn ntt_fwd(&self, x: &mut [u64]);
    fn ntt_inv(&self, x: &mut [u64]);
    fn poly_mul(&self, a: &[u64], b: &[u64], out: &mut [u64]);
    fn sample_uniform(&self, out: &mut [u64], seed: u64);
}

#[derive(Debug, Clone, Copy)]
pub struct BackendGap {
    pub backend: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub enum BackendAvailability {
    Available,
    FeatureGap(BackendGap),
}

#[derive(Debug, Clone, Copy)]
pub struct BackendProbe {
    pub name: &'static str,
    pub availability: BackendAvailability,
}

pub fn expected_rns_len() -> usize {
    POLY_DEGREE * RNS_LIMBS
}
