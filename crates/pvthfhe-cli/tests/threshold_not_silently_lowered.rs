//! R8.2a RED: CLI must NEVER silently lower the threshold.
//!
//! On current `main`, `full_pipeline.rs:78` caps `backend_threshold` at
//! `cfg.t.min((cfg.n+1)/2)`, silently reducing it from 5 to 4 for `n=8`.
//! This test asserts that the pipeline returns an error instead of silently
//! lowering the threshold — the plan requires a hard `InvalidThreshold` error,
//! never a silent reduction.

use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};

/// Naive observer that counts partial-decrypt calls and records
/// the `setup_threshold` detail string.
#[derive(Default)]
struct DetectObserver {
    partial_decrypt_count: usize,
    setup_threshold_detail: Option<String>,
}

impl PipelineObserver for DetectObserver {
    fn phase_start(&mut self, name: &str, detail: Option<&str>) {
        if name == "setup_threshold" {
            self.setup_threshold_detail = detail.map(|s| s.to_owned());
        }
    }

    fn phase_end(&mut self, name: &str, _ms: f64) {
        if name == "partial_decrypt" {
            self.partial_decrypt_count += 1;
        }
    }
}

#[test]
fn threshold_not_silently_lowered_n8_t5() {
    // Plan: t=5, n=8 has t > (n+1)/2 = 4. The pipeline must NOT
    // silently lower t to 4; it must return a hard error.
    //
    // On current main, `run_full_pipeline` silently replaces t=5 with
    // backend_threshold=4 and continues. This RED test asserts the
    // pipeline returns an Err, which will FAIL on current main and
    // PASS only after the GREEN hard-error guard is in place.
    let mut observer = DetectObserver::default();
    let result = run_full_pipeline(
        &PipelineConfig { n: 8, t: 5, seed: 0 },
        &mut observer,
    );

    match result {
        Err(e) => {
            // GREEN: pipeline correctly rejected the invalid threshold.
            // Check that the error message mentions "threshold" so we
            // know it's an intentional reject, not an unrelated failure.
            let msg = format!("{e}");
            assert!(
                msg.to_lowercase().contains("threshold"),
                "error should mention threshold, got: {msg}"
            );
            // Also verify that partial_decrypt was never reached.
            assert_eq!(
                observer.partial_decrypt_count, 0,
                "pipeline should reject before any partial_decrypt"
            );
        }
        Ok(_report) => {
            // RED: pipeline succeeded — this means the threshold was
            // silently lowered on current main. Assert we detect this.
            if let Some(detail) = &observer.setup_threshold_detail {
                let lowered = detail.contains("backend_threshold=4");
                if lowered {
                    panic!(
                        "RED failure: threshold silently lowered to 4 \
                         (setup_threshold detail: {detail}). \
                         Pipeline must return InvalidThreshold error, \
                         not silently lower t=5 -> backend_threshold=4."
                    );
                }
            }
            panic!(
                "RED failure: full_pipeline succeeded with t=5, n=8 \
                 (t > (n+1)/2 = 4). Pipeline must return error, not \
                 silently cap the threshold."
            );
        }
    }
}
