//! Integration test for explicit RLWE moduli and variance parsing.

use pvthfhe_fhe::Params;

mod error {
    pub use pvthfhe_fhe::error::*;
}

mod types {
    pub use pvthfhe_fhe::types::*;
}

pub use pvthfhe_fhe::FheBackend;

#[path = "../src/mock_impl.rs"]
mod mock_impl;

const PARAMS_TOML_WITH_MODULI: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

#[test]
fn parse_params_round_trips_explicit_moduli_and_variance() {
    let params = mock_impl::parse_params(PARAMS_TOML_WITH_MODULI).expect("params parse");

    assert_eq!(params.n, 8192);
    assert_eq!(params.log2_q, 174);
    assert_eq!(params.t_plain, 65536);
    assert_eq!(
        params.moduli,
        vec![288230376173076481, 288230376167047169, 288230376161280001]
    );
    assert_eq!(params.variance, 10);

    let round_trip = Params {
        n: params.n,
        log2_q: params.log2_q,
        t_plain: params.t_plain,
        moduli: params.moduli.clone(),
        variance: params.variance,
    };

    assert_eq!(round_trip.n, params.n);
    assert_eq!(round_trip.log2_q, params.log2_q);
    assert_eq!(round_trip.t_plain, params.t_plain);
    assert_eq!(round_trip.moduli, params.moduli);
    assert_eq!(round_trip.variance, params.variance);
}
