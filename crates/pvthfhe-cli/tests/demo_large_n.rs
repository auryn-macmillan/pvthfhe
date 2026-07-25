//! Integration test for the larger full-pipeline path.

#[cfg(feature = "with-fhe")]
mod tests {
    use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
    use std::env;

    #[derive(Default)]
    struct QuietObserver;

    impl PipelineObserver for QuietObserver {}

    /// Full pipeline at scale. Default: n=16, t=7 — exercises every stage
    /// beyond the demo default, fits a 32 GB host.
    ///
    /// Opt-in edge run: `PVTHFHE_LARGE_N=1` selects n=129, t=64, which peaks
    /// above 30 GB RAM — only for machines with ≥ 48 GB. (The pipeline's
    /// per-party memory footprint grows steeply with n — pre-existing
    /// behavior, tracked as a known limitation.)
    #[test]
    fn demo_large_n_runs_full_pipeline() {
        env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
        let (n, t) = if env::var("PVTHFHE_LARGE_N").as_deref() == Ok("1") {
            (129, 64)
        } else {
            (16, 7)
        };
        let mut observer = QuietObserver;
        let report = run_full_pipeline(&PipelineConfig { n, t, seed: 0 }, &mut observer)
            .expect("full pipeline should succeed");

        assert!(report.plaintext_roundtrip_ok);
    }
}
