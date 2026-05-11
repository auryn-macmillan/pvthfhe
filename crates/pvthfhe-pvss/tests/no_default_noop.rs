use std::fs;
use std::path::PathBuf;

#[test]
fn pvss_default_surface_is_not_noop_adapter() {
    let lib_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let src = fs::read_to_string(&lib_rs).expect("read pvss lib.rs");
    let file = syn::parse_file(&src).expect("parse pvss lib.rs");

    let has_unguarded_noop = file.items.into_iter().any(|item| match item {
        syn::Item::Struct(item_struct) if item_struct.ident == "NoopPvssAdapter" => {
            !item_struct.attrs.iter().any(|attr| {
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
                !item_impl.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg")
                        && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains("production-stub-allowed"))
                })
            }
            _ => false,
        },
        _ => false,
    });

    assert!(
        !has_unguarded_noop,
        "R0.2 RED: unguarded NoopPvssAdapter exposure remains on main"
    );
}
