use std::fs;
use std::path::{Path, PathBuf};

const BUILD_RS_PATH: &str = "crates/pvthfhe-fhe/build.rs";
const AGGREGATOR_SRC_DIR: &str = "crates/pvthfhe-aggregator/src";
const CRATES_DIR: &str = "crates";
const CIRCUIT_TESTS_SRC_DIR: &str = "crates/pvthfhe-circuit-tests/src";
const VECTORS_ALLOW_PATH: &str = "crates/pvthfhe-core/tests/vectors.rs";
const BENCH_SCRIPTS_DIR: &str = "bench/scripts";
const JUSTFILE_PATH: &str = "Justfile";

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_repo_file(path: &str) -> String {
    let full_path = repo_path(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {}", full_path.display(), error))
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
fn no_new_allow_attributes_exist_outside_vectors_test_file() {
    let rs_files = repo_files_with_extension(CRATES_DIR, "rs");
    let mut allow_files: Vec<String> = rs_files
        .into_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {}", path.display(), error));
            if content.contains("#[allow(") {
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

    allow_files.sort();

    assert_eq!(
        allow_files,
        vec![VECTORS_ALLOW_PATH.to_string()],
        "only crates/pvthfhe-core/tests/vectors.rs may contain #[allow(...)]"
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
