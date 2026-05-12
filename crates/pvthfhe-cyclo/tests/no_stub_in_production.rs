use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use syn::{Attribute, Item, ItemImpl, ItemStruct, Type};
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

fn doc_text(attrs: &[Attribute]) -> String {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                    syn::Lit::Str(s) => Some(s.value()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn struct_name_from_type(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|seg| seg.ident.to_string()),
        _ => None,
    }
}

fn is_cyclo_adapter_impl(item_impl: &ItemImpl) -> bool {
    item_impl.trait_.as_ref().is_some_and(|(_, path, _)| {
        path.segments
            .last()
            .is_some_and(|seg| seg.ident == "CycloAdapter")
    })
}

#[test]
fn no_stub_cyclo_adapter_or_production_docs() {
    let root = workspace_root();
    let src_root = root.join("crates/pvthfhe-cyclo/src");

    let mut struct_docs: BTreeMap<String, String> = BTreeMap::new();
    let mut impl_targets: Vec<(PathBuf, String)> = Vec::new();

    for entry in WalkDir::new(&src_root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_dir()
            || should_skip(path)
            || path.extension().and_then(|s| s.to_str()) != Some("rs")
        {
            continue;
        }

        let src = fs::read_to_string(path).expect("read cyclo source file");
        let file = syn::parse_file(&src).expect("parse cyclo source file");

        for item in file.items {
            match item {
                Item::Struct(ItemStruct { ident, attrs, .. }) => {
                    struct_docs.insert(ident.to_string(), doc_text(&attrs));
                }
                Item::Impl(item_impl) if is_cyclo_adapter_impl(&item_impl) => {
                    if let Some(name) = struct_name_from_type(&item_impl.self_ty) {
                        impl_targets.push((path.to_path_buf(), name));
                    }
                }
                _ => {}
            }
        }
    }

    let stub_impls = impl_targets
        .iter()
        .filter(|(_, name)| name == "StubCycloAdapter")
        .collect::<Vec<_>>();
    assert!(
        stub_impls.is_empty(),
        "StubCycloAdapter is still the CycloAdapter impl target: {stub_impls:?}"
    );

    let production_docs = struct_docs
        .iter()
        .filter(|(_, docs)| docs.to_ascii_lowercase().contains("production"))
        .map(|(name, docs)| format!("{name}: {docs}"))
        .collect::<Vec<_>>();
    assert!(
        production_docs.is_empty(),
        "CycloAdapter structs still mention Production in docs: {production_docs:?}"
    );
}
