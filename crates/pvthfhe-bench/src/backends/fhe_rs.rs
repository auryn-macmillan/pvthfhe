use super::{BackendAvailability, BackendProbe, RqOps};

#[cfg(not(feature = "backend-fhe-rs"))]
use super::BackendGap;

pub const FHE_RS_PINNED_SHA: &str = "5f24d0b62a7329b789db07a065b68accd614a47b";

#[derive(Debug, Default, Clone, Copy)]
pub struct FheRsBackend;

impl FheRsBackend {
    pub fn probe() -> BackendProbe {
        #[cfg(feature = "backend-fhe-rs")]
        {
            BackendProbe {
                name: "fhe_rs",
                availability: BackendAvailability::Available,
            }
        }

        #[cfg(not(feature = "backend-fhe-rs"))]
        {
            BackendProbe {
                name: "fhe_rs",
                availability: BackendAvailability::FeatureGap(BackendGap {
                    backend: "fhe_rs",
                    reason: "Compile the bench crate with --features backend-fhe-rs to enable the concrete fhe.rs adapter.",
                }),
            }
        }
    }
}

#[cfg(feature = "backend-fhe-rs")]
mod enabled {
    use super::FheRsBackend;
    use crate::backends::{expected_rns_len, MODULI_60_BIT, POLY_DEGREE, RNS_LIMBS};
    use fhe_math::{
        rq::{traits::TryConvertFrom, Context, Poly, Representation},
        zq::Modulus,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::sync::{Arc, OnceLock};

    fn single_limb_context() -> &'static Arc<Context> {
        static CONTEXT: OnceLock<Arc<Context>> = OnceLock::new();
        CONTEXT.get_or_init(|| {
            let context = match Context::new(&[MODULI_60_BIT[0]], POLY_DEGREE) {
                Ok(context) => context,
                Err(err) => unreachable!("valid single-limb fhe.rs context: {err:?}"),
            };
            Arc::new(context)
        })
    }

    fn four_limb_context() -> &'static Arc<Context> {
        static CONTEXT: OnceLock<Arc<Context>> = OnceLock::new();
        CONTEXT.get_or_init(|| {
            let context = match Context::new(&MODULI_60_BIT, POLY_DEGREE) {
                Ok(context) => context,
                Err(err) => unreachable!("valid four-limb fhe.rs context: {err:?}"),
            };
            Arc::new(context)
        })
    }

    fn four_limb_moduli() -> &'static [Modulus] {
        &four_limb_context().q
    }

    impl FheRsBackend {
        fn require_single_limb(x: &[u64]) {
            assert_eq!(
                x.len(),
                POLY_DEGREE,
                "expected one-limb polynomial with degree {POLY_DEGREE}"
            );
        }

        fn require_full_rns(x: &[u64]) {
            assert_eq!(
                x.len(),
                expected_rns_len(),
                "expected four-limb RNS polynomial with {} coefficients",
                expected_rns_len()
            );
        }

        fn poly_from_power_basis(coeffs: &[u64]) -> Poly {
            match Poly::try_convert_from(
                coeffs.to_vec(),
                four_limb_context(),
                false,
                Representation::PowerBasis,
            ) {
                Ok(poly) => poly,
                Err(err) => unreachable!("valid RNS polynomial: {err:?}"),
            }
        }
    }

    impl super::RqOps for FheRsBackend {
        fn ntt_fwd(&self, x: &mut [u64]) {
            Self::require_single_limb(x);
            single_limb_context().ops[0].forward(x);
        }

        fn ntt_inv(&self, x: &mut [u64]) {
            Self::require_single_limb(x);
            single_limb_context().ops[0].backward(x);
        }

        fn poly_mul(&self, a: &[u64], b: &[u64], out: &mut [u64]) {
            Self::require_full_rns(a);
            Self::require_full_rns(b);
            Self::require_full_rns(out);

            let mut lhs = Self::poly_from_power_basis(a);
            let mut rhs = Self::poly_from_power_basis(b);
            lhs.change_representation(Representation::Ntt);
            rhs.change_representation(Representation::Ntt);

            let mut product = &lhs * &rhs;
            product.change_representation(Representation::PowerBasis);
            out.copy_from_slice(&Vec::<u64>::from(&product));
        }

        fn sample_uniform(&self, out: &mut [u64], seed: u64) {
            assert!(
                out.len() == POLY_DEGREE || out.len() == expected_rns_len(),
                "unsupported output length {}",
                out.len()
            );

            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            if out.len() == POLY_DEGREE {
                out.copy_from_slice(&four_limb_moduli()[0].random_vec(POLY_DEGREE, &mut rng));
                return;
            }

            for (limb, modulus) in four_limb_moduli().iter().enumerate().take(RNS_LIMBS) {
                let start = limb * POLY_DEGREE;
                let end = start + POLY_DEGREE;
                out[start..end].copy_from_slice(&modulus.random_vec(POLY_DEGREE, &mut rng));
            }
        }
    }
}

#[cfg(not(feature = "backend-fhe-rs"))]
impl RqOps for FheRsBackend {
    fn ntt_fwd(&self, _x: &mut [u64]) {
        unreachable!("fhe.rs adapter requires --features backend-fhe-rs");
    }

    fn ntt_inv(&self, _x: &mut [u64]) {
        unreachable!("fhe.rs adapter requires --features backend-fhe-rs");
    }

    fn poly_mul(&self, _a: &[u64], _b: &[u64], _out: &mut [u64]) {
        unreachable!("fhe.rs adapter requires --features backend-fhe-rs");
    }

    fn sample_uniform(&self, _out: &mut [u64], _seed: u64) {
        unreachable!("fhe.rs adapter requires --features backend-fhe-rs");
    }
}
