//! RED integration test for the larger full-pipeline path.

#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
mod tests {
    use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
    use std::env;

    #[derive(Default)]
    struct QuietObserver;

    impl PipelineObserver for QuietObserver {}

    #[test]
    fn demo_large_n_runs_full_pipeline() {
        env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
        let mut observer = QuietObserver;
        let report = run_full_pipeline(
            &PipelineConfig {
                n: 128,
                t: 64,
                seed: 1,
            },
            &mut observer,
        )
        .expect("full pipeline should succeed");

        assert!(report.plaintext_roundtrip_ok);
    }
}
