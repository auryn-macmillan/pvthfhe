//! Surrogate retirement audit — ensures zero `// SURROGATE` markers remain in
//! any .rs, .sol, or .nr file (excluding the surrogate-declaration files).
//!
//! Migrated from `.sisyphus/scripts/surrogate-retirement-check.py`.

use std::fs;
use std::path::Path;

#[test]
fn no_surrogate_markers_in_source() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut hits = Vec::new();
    let whitelist: &[&str] = &[
        "contracts/script/SurrogateCheck.s.sol",
        "contracts/src/SurrogateNotice.sol",
        "crates/pvthfhe-tests/tests/surrogate_retirement.rs",
    ];

    walk(&repo, &repo, whitelist, &mut hits);

    assert!(
        hits.is_empty(),
        "found {} SURROGATE marker(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

fn walk(base: &Path, dir: &Path, whitelist: &[&str], hits: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        if path.is_dir() {
            walk(base, &path, whitelist, hits);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ["rs", "sol", "nr"].contains(&ext) {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                if whitelist.contains(&rel.to_string_lossy().as_ref()) {
                    continue;
                }
                if let Ok(contents) = fs::read_to_string(&path) {
                    for (i, line) in contents.lines().enumerate() {
                        if line.contains("// SURROGATE") || line.contains("//SURROGATE") {
                            hits.push(format!("  {}:{}: {}", rel.display(), i + 1, line.trim()));
                        }
                    }
                }
            }
        }
    }
}
