use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_bench_scaling_dry_run() -> (Option<std::process::ExitStatus>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bench_scaling"))
        .current_dir(repo_root())
        .arg("--n")
        .arg("4")
        .arg("--dry-run")
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bench_scaling");

    let mut stderr = child.stderr.take().expect("capture stderr");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll bench_scaling status") {
            break Some(status);
        }

        if started.elapsed() >= Duration::from_secs(2) {
            child.kill().expect("kill hung bench_scaling --dry-run");
            break None;
        }

        thread::sleep(Duration::from_millis(10));
    };

    let mut stderr_text = String::new();
    stderr
        .read_to_string(&mut stderr_text)
        .expect("read bench_scaling stderr");

    (status, stderr_text)
}

#[test]
fn bench_scaling_uses_real_backend() {
    let (status, stderr) = run_bench_scaling_dry_run();

    assert!(
        status.is_some_and(|status| status.success()),
        "bench_scaling --dry-run should exit successfully: {stderr}"
    );
    assert!(
        stderr.contains("backend_id") && stderr.contains("fhers-bfv"),
        "expected stderr backend_id line to contain fhers-bfv, got: {stderr}"
    );
    assert!(
        !stderr.contains("mock-xor"),
        "bench_scaling stderr must not mention mock-xor: {stderr}"
    );
}
