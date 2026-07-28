/// Verify that DO-NOT-DEPLOY banners are present in all required doc files.
/// Migrated from `stage0-gate` check 2.
#[test]
fn do_not_deploy_banners_present() {
    let files = ["README.md", "ARCHITECTURE.md", "SECURITY.md"];
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for fname in &files {
        let path = repo.join(fname);
        let first_15 = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .take(15)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            first_15.contains("DO NOT DEPLOY"),
            "{} missing DO NOT DEPLOY banner in first 15 lines",
            fname
        );
    }
}
