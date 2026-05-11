use std::fs;
use std::path::{Path, PathBuf};

use syn::{Item, ItemStruct};
use walkdir::WalkDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("tests") | Some("target") | Some("vendor-stub")
        )
    })
}

fn is_fold_path_struct(name: &str) -> bool {
    name == "HashChainFoldingScheme"
        || name.ends_with("FoldingScheme")
        || name.ends_with("FoldingAdapter")
}

#[test]
fn single_fold_path_exists() {
    let root = workspace_root();
    let src_root = root.join("crates/pvthfhe-aggregator/src");
    let folding_mod = src_root.join("folding/mod.rs");

    let mut pub_fold_types = Vec::new();

    for entry in WalkDir::new(&src_root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_dir() || should_skip(path) || path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        let src = fs::read_to_string(path).expect("read aggregator source file");
        let file = syn::parse_file(&src).expect("parse aggregator source file");

        if path != folding_mod {
            continue;
        }

        for item in file.items {
            if let Item::Struct(ItemStruct { ident, vis, .. }) = item {
                if matches!(vis, syn::Visibility::Public(_)) && is_fold_path_struct(&ident.to_string()) {
                    pub_fold_types.push(ident.to_string());
                }
            }
        }
    }

    pub_fold_types.sort();
    pub_fold_types.dedup();

    assert_eq!(
        pub_fold_types.len(),
        1,
        "expected exactly one canonical fold path in folding/mod.rs, found {}: {:?}",
        pub_fold_types.len(),
        pub_fold_types
    );
}
