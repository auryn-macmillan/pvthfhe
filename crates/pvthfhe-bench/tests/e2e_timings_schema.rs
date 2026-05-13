use pvthfhe_bench::e2e_timings::E2eTimings;

#[test]
fn schema_version_constant_is_1_0_0() {
    assert_eq!(E2eTimings::SCHEMA_VERSION, "1.0.0");
}

#[test]
fn round_trip_serialization() {
    let timings = E2eTimings::new(3, 1, 1, "test-compressor");
    let json = match serde_json::to_string(&timings) {
        Ok(json) => json,
        Err(err) => unreachable!("serialize E2eTimings: {err}"),
    };
    let decoded: E2eTimings = match serde_json::from_str(&json) {
        Ok(decoded) => decoded,
        Err(err) => unreachable!("deserialize E2eTimings: {err}"),
    };

    assert_eq!(decoded.schema_version, timings.schema_version);
    assert_eq!(decoded.n, timings.n);
    assert_eq!(decoded.t, timings.t);
    assert_eq!(decoded.seed, timings.seed);
    assert_eq!(decoded.compressor_backend_id, timings.compressor_backend_id);
    assert_eq!(decoded.produced_at_unix_secs, timings.produced_at_unix_secs);
    assert_eq!(decoded.git_sha, timings.git_sha);
}

#[test]
fn version_mismatch_returns_error() {
    let error = match E2eTimings::check_version("0.9.0") {
        Ok(()) => unreachable!("expected version mismatch error"),
        Err(err) => err,
    };

    assert!(error.contains("version"));
}

#[test]
fn new_has_all_required_phase_keys() {
    let timings = E2eTimings::new(3, 1, 1, "test");
    let json = match serde_json::to_value(&timings) {
        Ok(json) => json,
        Err(err) => unreachable!("serialize E2eTimings to value: {err}"),
    };
    let phases = &json["phases"];

    for key in [
        "keygen",
        "nizk_prove",
        "nizk_verify",
        "pvss_share_encrypt",
        "pvss_decrypt_prove",
        "cyclo_fold",
        "compressor_prove",
        "compressor_verify",
        "partial_decrypt",
        "aggregate_decrypt",
        "noir_sonobe_wrap",
        "noir_aggregator_final",
        "onchain_verify",
    ] {
        assert!(phases.get(key).is_some(), "missing phase key: {key}");
    }
}
