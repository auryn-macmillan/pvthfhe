//! Stage-0 banner checks.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const OLD_SURROGATE_BANNER: &str =
    "SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final";

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    crate_dir()
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn read_build_rs() -> String {
    fs::read_to_string(crate_dir().join("build.rs")).expect("read build.rs")
}

fn read_justfile() -> String {
    fs::read_to_string(repo_root().join("Justfile")).expect("read Justfile")
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "pvthfhe-banner-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(dir.join("src")).expect("create temp crate dir");
    dir
}

fn write_probe_crate(dir: &Path, dependency_spec: &str) {
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"banner-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npvthfhe-fhe = {{ {dependency_spec} }}\n"
        ),
    )
    .expect("write probe Cargo.toml");
    fs::write(dir.join("src/lib.rs"), "pub fn probe() {}\n").expect("write probe lib.rs");
}

fn cargo_build_stderr(label: &str, dependency_spec: &str) -> String {
    let probe_dir = unique_temp_dir(label);
    write_probe_crate(&probe_dir, dependency_spec);

    let target_dir = probe_dir.join("target");
    let output = Command::new("cargo")
        .args(["build", "--color", "never"])
        .current_dir(&probe_dir)
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .expect("run cargo build for banner probe");

    assert!(
        output.status.success(),
        "probe build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stderr).expect("stderr utf8")
}

#[test]
fn banner_default_backend_emits_folding_warning_and_not_old_banner() {
    let stderr = cargo_build_stderr(
        "default",
        &format!("path = {:?}", crate_dir().display().to_string()),
    );

    assert!(
        stderr.contains("FOLDING ACCUMULATOR IS A SURROGATE"),
        "expected default-backend folding warning in stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("MOCK BACKEND ACTIVE — XOR/SHA256 ONLY"),
        "default build should not emit mock warning:\n{stderr}"
    );
    assert!(
        !stderr.contains(OLD_SURROGATE_BANNER),
        "default build should not emit old surrogate banner:\n{stderr}"
    );
}

#[test]
fn banner_mock_feature_emits_mock_warning_and_not_default_warning() {
    let stderr = cargo_build_stderr(
        "mock",
        &format!(
            "path = {:?}, default-features = false, features = [\"mock\"]",
            crate_dir().display().to_string()
        ),
    );

    assert!(
        stderr.contains("MOCK BACKEND ACTIVE — XOR/SHA256 ONLY"),
        "expected mock-backend warning in stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("FOLDING ACCUMULATOR IS A SURROGATE"),
        "mock build should not emit default folding warning:\n{stderr}"
    );
}

#[test]
fn banner_source_replaces_old_surrogate_wording() {
    let build_rs = read_build_rs();

    assert!(
        build_rs.contains("FOLDING ACCUMULATOR IS A SURROGATE"),
        "expected default-backend folding warning in build.rs"
    );
    assert!(
        build_rs.contains("MOCK BACKEND ACTIVE — XOR/SHA256 ONLY"),
        "expected mock-backend warning in build.rs"
    );
    assert!(
        !build_rs.contains(OLD_SURROGATE_BANNER),
        "old surrogate banner should be absent from build.rs"
    );
}

#[test]
fn banner_stage0_gate_checks_new_default_warning() {
    let justfile = read_justfile();

    assert!(
        justfile.contains("FOLDING ACCUMULATOR IS A SURROGATE"),
        "expected stage0-gate cargo tripwire to check new default warning"
    );
}
