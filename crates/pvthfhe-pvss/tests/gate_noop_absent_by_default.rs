use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn production_stub_allowed_is_not_default() {
    let lib_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let src = fs::read_to_string(&lib_rs).expect("read pvss lib.rs");
    let file = syn::parse_file(&src).expect("parse pvss lib.rs");

    let noop_is_gated = file.items.into_iter().any(|item| match item {
        syn::Item::Struct(item_struct) if item_struct.ident == "NoopPvssAdapter" => {
            item_struct.attrs.iter().any(|attr| {
                attr.path().is_ident("cfg")
                    && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains("production-stub-allowed"))
            })
        }
        syn::Item::Impl(item_impl) => match *item_impl.self_ty {
            syn::Type::Path(ref path)
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|seg| seg.ident == "NoopPvssAdapter") =>
            {
                item_impl.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg")
                        && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains("production-stub-allowed"))
                })
            }
            _ => false,
        },
        _ => false,
    });

    assert!(noop_is_gated, "NoopPvssAdapter must remain feature-gated");

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("cargo")
        .current_dir(&crate_dir)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            "Cargo.toml",
        ])
        .output()
        .expect("run cargo metadata");
    assert!(output.status.success(), "cargo metadata failed");

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata json");
    let package = metadata
        .get("packages")
        .and_then(|packages| packages.as_array())
        .and_then(|packages| {
            packages
                .iter()
                .find(|pkg| pkg.get("name").and_then(|name| name.as_str()) == Some("pvthfhe-pvss"))
        })
        .expect("find pvthfhe-pvss package");
    let features = package
        .get("features")
        .and_then(|features| features.as_object())
        .expect("features table");
    assert!(
        features.contains_key("production-stub-allowed"),
        "feature missing from metadata"
    );

    let cargo_toml = fs::read_to_string(crate_dir.join("Cargo.toml")).expect("read Cargo.toml");
    let features_section = cargo_toml
        .split_once("[features]")
        .and_then(|(_, rest)| rest.split_once("[dependencies]"))
        .map(|(features, _)| features)
        .unwrap_or("");
    let default_has_stub = features_section.lines().any(|line| {
        line.trim_start().starts_with("default =") && line.contains("production-stub-allowed")
    });

    assert!(
        !default_has_stub,
        "production-stub-allowed must not be in default features"
    );
}
