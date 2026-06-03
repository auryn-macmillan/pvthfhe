use std::fs;
use std::path::PathBuf;

#[test]
fn production_profile_exists_and_excludes_mock() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read_to_string(crate_dir.join("Cargo.toml")).expect("read Cargo.toml");
    
    let features_section = cargo_toml
        .split_once("[features]")
        .and_then(|(_, rest)| rest.split_once("\n[").or_else(|| Some((rest, ""))))
        .map(|(features, _)| features)
        .unwrap_or("");
        
    let prod_profile = features_section.lines().find(|line| {
        line.trim_start().starts_with("production-profile =")
    });
    
    assert!(prod_profile.is_some(), "production-profile feature must exist");
    let prod_profile = prod_profile.unwrap();
    
    assert!(
        !prod_profile.contains("\"mock\""),
        "production-profile must not include mock"
    );
    assert!(
        !prod_profile.contains("\"surrogate-decrypt-share\""),
        "production-profile must not include surrogate-decrypt-share"
    );
    assert!(
        !prod_profile.contains("\"trace-decrypt\""),
        "production-profile must not include trace-decrypt"
    );
}
