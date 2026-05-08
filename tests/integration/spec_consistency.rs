use std::fs;
use std::path::Path;

const SPEC_PATH: &str = ".sisyphus/design/spec-real-p2p3.md";
const PARAMETERS_PATH: &str = "parameters.toml";

fn repo_file(path: &str) -> String {
    let full_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {}", full_path.display(), error))
}

fn has_tag_after(haystack: &str, needle: &str) -> bool {
    haystack
        .find(needle)
        .and_then(|index| haystack.get(index + needle.len()..))
        .map(|tail| {
            let boundary = tail.find('\n').unwrap_or(tail.len());
            let window = &tail[..boundary.min(80)];
            ["(illustrative", "(legacy", "(deprecated"]
                .iter()
                .any(|tag| window.contains(tag))
        })
        .unwrap_or(false)
}

fn canonical_claim_lines(spec: &str) -> Vec<&str> {
    spec.lines()
        .filter(|line| {
            (line.contains(" is canonical")
                || line.contains(" production ring degree")
                || line.contains("canonical ring degree"))
                && (line.contains("N=") || line.contains("RLWE_N="))
        })
        .collect()
}

#[test]
fn canonical_ring_degree_is_frozen_and_legacy_mentions_are_tagged() {
    let spec = repo_file(SPEC_PATH);
    let parameters = repo_file(PARAMETERS_PATH);

    assert!(
        parameters.contains("[rlwe]")
            && parameters.contains("N = 8192")
            && parameters.contains("log2_q = 174")
            && parameters.contains("B_e = 16"),
        "parameters.toml must define the canonical [rlwe] parameter set"
    );

    assert!(
        spec.contains("Canonical Parameters"),
        "spec must add a canonical parameters section near the top"
    );
    assert!(spec.contains("N=8192"), "spec must mention N=8192");
    assert!(
        spec.contains("Ring degree N=8192 is canonical"),
        "spec must state that N=8192 is canonical"
    );

    let canonical_claims = canonical_claim_lines(&spec);
    assert_eq!(
        canonical_claims.len(),
        1,
        "spec must name exactly one production/canonical ring degree: {:?}",
        canonical_claims
    );
    assert!(
        canonical_claims[0].contains("N=8192"),
        "the sole production/canonical ring degree claim must be N=8192: {:?}",
        canonical_claims
    );

    let bare_legacy = spec.lines().enumerate().find(|(_, line)| {
        line.contains("RLWE_N=1024")
            && !line.contains("(illustrative")
            && !line.contains("(legacy")
            && !line.contains("(deprecated")
    });
    assert!(
        bare_legacy.is_none(),
        "spec must not contain a bare RLWE_N=1024 mention: {:?}",
        bare_legacy
    );

    assert!(
        has_tag_after(&spec, "RLWE_N=1024"),
        "RLWE_N=1024 must be explicitly tagged as illustrative, legacy, or deprecated"
    );
    assert!(
        spec.contains("RLWE_N=1024 (illustrative; see Canonical Parameters")
            && spec.contains("parameters.toml [rlwe]`), 3 limbs")
            || spec.contains("RLWE_N=1024 (illustrative; see Canonical Parameters and\n`parameters.toml [rlwe]`), 3 limbs"),
        "legacy sizing example must reference the canonical parameter source"
    );
}
