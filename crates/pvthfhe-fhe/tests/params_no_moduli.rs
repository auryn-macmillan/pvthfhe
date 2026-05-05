//! Integration test for rejecting RLWE params without explicit moduli.

mod error {
    pub use pvthfhe_fhe::error::*;
}

mod types {
    pub use pvthfhe_fhe::types::*;
}

pub use pvthfhe_fhe::FheBackend;

#[path = "../src/mock_impl.rs"]
mod mock_impl;

const PARAMS_TOML_WITHOUT_MODULI: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
variance = 10
"#;

#[test]
fn params_no_moduli_rejects_missing_moduli() {
    let result = mock_impl::parse_params(PARAMS_TOML_WITHOUT_MODULI);

    assert_eq!(
        result,
        Err(error::FheError::InvalidParams {
            reason: "moduli required in [rlwe] section".into(),
        })
    );
}
