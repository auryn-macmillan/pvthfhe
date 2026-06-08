use std::fs;
use std::path::{Path, PathBuf};

const BUILD_RS_PATH: &str = "crates/pvthfhe-fhe/build.rs";
const AGGREGATOR_SRC_DIR: &str = "crates/pvthfhe-aggregator/src";
const CRATES_DIR: &str = "crates";
const CIRCUIT_TESTS_SRC_DIR: &str = "crates/pvthfhe-circuit-tests/src";
const BENCH_SCRIPTS_DIR: &str = "bench/scripts";
const JUSTFILE_PATH: &str = "Justfile";

const PRODUCTION_PROFILE_OWNERS: &[(&str, &str, &[&str])] = &[
    (
        "pvthfhe-fhe",
        "crates/pvthfhe-fhe/Cargo.toml",
        &["real-nizk"],
    ),
    (
        "pvthfhe-aggregator",
        "crates/pvthfhe-aggregator/Cargo.toml",
        &[
            "real-folding",
            "real-verifier",
            "real-pvss",
            "real-nizk",
            "pvthfhe-fhe/production-profile",
        ],
    ),
    (
        "pvthfhe-compressor",
        "crates/pvthfhe-compressor/Cargo.toml",
        &["pvthfhe-aggregator/production-profile"],
    ),
    (
        "pvthfhe-cli",
        "crates/pvthfhe-cli/Cargo.toml",
        &[
            "with-fhe",
            "nova-compressor",
            "pipeline-extra-checks",
            "pvthfhe-fhe/production-profile",
            "pvthfhe-aggregator/production-profile",
            "pvthfhe-compressor/production-profile",
            "pvthfhe-keygen/production-profile",
            "pvthfhe-pvss/production-profile",
            "pvthfhe-bench/production-profile",
        ],
    ),
    (
        "pvthfhe-keygen",
        "crates/pvthfhe-keygen/Cargo.toml",
        &["pvthfhe-fhe/production-profile"],
    ),
    (
        "pvthfhe-pvss",
        "crates/pvthfhe-pvss/Cargo.toml",
        &["pvthfhe-fhe/production-profile"],
    ),
    (
        "pvthfhe-enclave-adapter",
        "crates/pvthfhe-enclave-adapter/Cargo.toml",
        &["pvthfhe-fhe/production-profile"],
    ),
    (
        "pvthfhe-offchain-verifier",
        "crates/pvthfhe-offchain-verifier/Cargo.toml",
        &["pvthfhe-compressor/production-profile"],
    ),
    (
        "pvthfhe-bench",
        "crates/pvthfhe-bench/Cargo.toml",
        &["pvthfhe-fhe/production-profile"],
    ),
];

const FORBIDDEN_PRODUCTION_FEATURES: &[&str] = &[
    "mock",
    "surrogate-compressor",
    "surrogate-decrypt-share",
    "trace-decrypt",
    "demo-seeded-rng",
    "legacy-nova",
    "production-stub-allowed",
    "stub",
    "production-stub-allowed",
    "hermine",
];

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_repo_file(path: &str) -> String {
    let full_path = repo_path(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {}", full_path.display(), error))
}

fn manifest_features_section(manifest: &str) -> &str {
    manifest
        .split_once("[features]")
        .map(|(_, rest)| rest.split_once('\n').map_or(rest, |_| rest))
        .and_then(|rest| {
            rest.split_once("\n[")
                .map(|(features, _)| features)
                .or(Some(rest))
        })
        .unwrap_or("")
}

fn feature_line<'a>(features_section: &'a str, feature: &str) -> Option<&'a str> {
    let prefix = format!("{feature} =");
    let mut lines = features_section.lines();
    while let Some(line) = lines.next() {
        if !line.trim_start().starts_with(&prefix) {
            continue;
        }

        if !line.contains('[') || line.contains(']') {
            return Some(line);
        }

        let mut collected = String::from(line);
        for continuation in lines.by_ref() {
            collected.push('\n');
            collected.push_str(continuation);
            if continuation.contains(']') {
                break;
            }
        }
        return Some(Box::leak(collected.into_boxed_str()));
    }
    None
}

fn visit_files(dir: &Path, extension: Option<&str>, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read dir {}: {}", dir.display(), error));

    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("failed to read entry in {}: {}", dir.display(), error));
        let path = entry.path();
        if path.is_dir() {
            visit_files(&path, extension, files);
        } else if extension.map_or(true, |expected| {
            path.extension().and_then(|ext| ext.to_str()) == Some(expected)
        }) {
            files.push(path);
        }
    }
}

fn repo_files_with_extension(path: &str, extension: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit_files(&repo_path(path), Some(extension), &mut files);
    files
}

#[test]
fn build_banner_mentions_mock_backend_warning() {
    let build_rs = read_repo_file(BUILD_RS_PATH);

    assert!(
        build_rs.contains("MOCK BACKEND ACTIVE — XOR/SHA256 ONLY"),
        "build.rs must retain the Stage-0 mock backend banner"
    );
}

#[test]
fn aggregator_source_retains_mock_env_guard() {
    let source_files = repo_files_with_extension(AGGREGATOR_SRC_DIR, "rs");
    let matching_files: Vec<String> = source_files
        .into_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {}", path.display(), error));
            if content.contains("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK") {
                Some(
                    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect();

    assert!(
        !matching_files.is_empty(),
        "aggregator src must contain the PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK guard in a non-test Rust file"
    );
}

#[test]
fn forbidden_nargo_commands_remain_absent_from_scripts_and_justfile() {
    for path in repo_files_with_extension(BENCH_SCRIPTS_DIR, "sh") {
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {}", path.display(), error));
        assert!(
            !content.contains("nargo prove") && !content.contains("nargo verify"),
            "{} must not contain forbidden nargo commands",
            path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&path)
                .display()
        );
    }

    let justfile = read_repo_file(JUSTFILE_PATH);
    assert!(
        !justfile.contains("nargo prove") && !justfile.contains("nargo verify"),
        "Justfile must not contain forbidden nargo commands"
    );
}

#[test]
fn circuit_test_harness_sources_avoid_forbidden_nargo_commands() {
    for path in repo_files_with_extension(CIRCUIT_TESTS_SRC_DIR, "rs") {
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {}", path.display(), error));
        assert!(
            !content.contains("nargo prove") && !content.contains("nargo verify"),
            "{} must not contain forbidden nargo commands",
            path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&path)
                .display()
        );
    }
}

#[test]
fn production_profile_is_per_crate_and_excludes_legacy_mock_features() {
    for (crate_name, manifest_path, required_members) in PRODUCTION_PROFILE_OWNERS {
        let manifest = read_repo_file(manifest_path);
        let features = manifest_features_section(&manifest);
        let production_profile =
            feature_line(features, "production-profile").unwrap_or_else(|| {
                panic!("{crate_name} must define an owning production-profile feature")
            });

        for required in *required_members {
            assert!(
                production_profile.contains(required),
                "{crate_name} production-profile must include {required}: {production_profile}"
            );
        }

        for forbidden in FORBIDDEN_PRODUCTION_FEATURES {
            assert!(
                !production_profile.contains(forbidden),
                "{crate_name} production-profile must not include forbidden feature {forbidden}: {production_profile}"
            );
        }
    }
}

#[test]
fn production_profile_manifests_do_not_hard_request_forbidden_features() {
    for manifest_path in repo_files_with_extension(CRATES_DIR, "toml") {
        if manifest_path.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml") {
            continue;
        }

        let manifest = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
        let non_dev_manifest = manifest
            .split_once("[dev-dependencies]")
            .map_or(manifest.as_str(), |(before_dev, _)| before_dev);

        for forbidden in FORBIDDEN_PRODUCTION_FEATURES {
            let forbidden_request = format!("features = [\"{forbidden}\"");
            let forbidden_request_with_prefix =
                format!("features = [\"real-nizk\", \"{forbidden}\"");
            assert!(
                !non_dev_manifest
                    .lines()
                    .filter(|line| line.contains("pvthfhe-"))
                    .any(|line| line.contains(&forbidden_request)
                        || line.contains(&forbidden_request_with_prefix)),
                "{} must not hard-request forbidden feature {forbidden} outside dev-dependencies",
                manifest_path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&manifest_path)
                    .display()
            );
        }
    }
}
