//! Integration test for real BFV parameter construction in `FhersBackend`.

use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_load_params_builds_real_bfv_parameters() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");

    assert_eq!(backend.bfv_params().degree(), 8192);
    assert_eq!(backend.bfv_params().moduli().len(), 3);
}
