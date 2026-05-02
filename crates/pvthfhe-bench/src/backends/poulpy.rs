use super::{BackendAvailability, BackendGap, BackendProbe, RqOps};

pub const POULPY_PINNED_SHA: &str = "4a1f0c642cef7e5830287c3d6af7e013d8a7bda4";

#[derive(Debug, Default, Clone, Copy)]
pub struct PoulpyBackend;

impl PoulpyBackend {
    pub fn probe() -> BackendProbe {
        BackendProbe {
            name: "poulpy",
            availability: BackendAvailability::FeatureGap(BackendGap {
                backend: "poulpy",
                reason: "Poulpy exposes torus/bivariate HAL backends on nightly Rust, not the fixed 4x60-bit RNS Rq API required by this benchmark harness on stable.",
            }),
        }
    }

    fn unsupported() -> ! {
        panic!(
            "Poulpy backend is a documented feature gap for T4: nightly-only HAL plus torus/bivariate representation does not provide the required stable RNS Rq adapter in this workspace."
        )
    }
}

impl RqOps for PoulpyBackend {
    fn ntt_fwd(&self, _x: &mut [u64]) {
        Self::unsupported();
    }

    fn ntt_inv(&self, _x: &mut [u64]) {
        Self::unsupported();
    }

    fn poly_mul(&self, _a: &[u64], _b: &[u64], _out: &mut [u64]) {
        Self::unsupported();
    }

    fn sample_uniform(&self, _out: &mut [u64], _seed: u64) {
        Self::unsupported();
    }
}
