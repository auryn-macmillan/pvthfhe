//! Memory-budget regression test for the e2e compressor probe path.
//!
//! ROOT CAUSE (H_TRACING, confirmed 2026-05-07):
//!   The unscoped `EnvFilter::new("info")` default in `pvthfhe-e2e` enables
//!   arkworks-rs / folding-schemes internal `tracing::span!` invocations whose
//!   fields include `&mut [FpVar]` slices. tracing-subscriber's
//!   `record_debug` then debug-formats those slices, recursing into
//!   `ConstraintSystemRef` and walking the entire (growing) R1CS constraint
//!   system per Poseidon round, blowing memory from ~244 MB to >12.6 GB and
//!   OOM-killing the process.
//!
//! This test catches any regression of that bug by:
//!   1. Spawning `pvthfhe-e2e --probe-compressor-only --n 3 --t 1 --seed 1`
//!      with `RUST_LOG=info` (the original failing condition).
//!   2. Wrapping it in a bash `ulimit -v 16777216` (16 GiB virtual address
//!      space) so a regression is killed by the kernel rather than swapping
//!      the host into oblivion.
//!   3. Capturing peak RSS via `/usr/bin/time -v` and asserting it is
//!      below a 500 MB budget (~2x the healthy baseline of ~244 MB).
//!
//! Requires the `nova-compressor` feature (the only mode in which the
//! probe-compressor-only path constructs a real Nova compressor). The test
//! is gated to Linux because `/usr/bin/time -v` and `ulimit -v` semantics are
//! Linux-specific.

#![cfg(all(target_os = "linux", feature = "sonobe-compressor"))]

use std::process::Command;

const MEMORY_BUDGET_KB: u64 = 500_000;
const VMEM_CAP_KB: u64 = 16 * 1024 * 1024;

#[test]
fn e2e_probe_compressor_only_under_500mb() {
    let bin = std::env::var("CARGO_BIN_EXE_pvthfhe-e2e")
        .expect("CARGO_BIN_EXE_pvthfhe-e2e should be set by cargo");

    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let time_out =
        std::env::temp_dir().join(format!("pvthfhe_e2e_memory_budget_{pid}_{nanos}.time.txt"));
    let _ = std::fs::remove_file(&time_out);

    let bash_script = format!(
        "ulimit -v {VMEM_CAP_KB}; exec /usr/bin/time -v -o {time_out} {bin} \
         --probe-compressor-only --n 3 --t 1 --seed 1",
        time_out = time_out.display(),
        bin = bin,
    );

    let status = Command::new("bash")
        .arg("-c")
        .arg(&bash_script)
        .env("RUST_LOG", "info")
        .status()
        .expect("failed to spawn bash wrapper for pvthfhe-e2e");

    let time_report = std::fs::read_to_string(&time_out).unwrap_or_default();
    eprintln!("--- /usr/bin/time -v output ---\n{time_report}\n--- end ---");

    let peak_rss_kb = parse_max_rss_kb(&time_report);
    let _ = std::fs::remove_file(&time_out);

    assert!(
        status.success(),
        "subprocess did not exit successfully (status={:?}); time -v report:\n{time_report}",
        status,
    );

    let peak = peak_rss_kb.unwrap_or_else(|| {
        panic!("could not parse 'Maximum resident set size' from time -v output:\n{time_report}")
    });

    assert!(
        peak < MEMORY_BUDGET_KB,
        "peak RSS {peak} KB exceeds budget {MEMORY_BUDGET_KB} KB (regression of H_TRACING tracing-filter bug?); time -v report:\n{time_report}",
    );
}

fn parse_max_rss_kb(report: &str) -> Option<u64> {
    for line in report.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Maximum resident set size (kbytes):") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}
