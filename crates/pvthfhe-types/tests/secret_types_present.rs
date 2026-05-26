use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::Visit;
use syn::{Field, Fields, ItemStruct, Type, TypePath, Visibility};
use walkdir::WalkDir;

#[derive(Debug)]
struct Violation {
    crate_name: String,
    file: PathBuf,
    struct_name: String,
    field_name: String,
    type_repr: String,
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("tests") | Some("target") | Some("vendor-stub")
        )
    }) || path
        .components()
        .any(|c| c.as_os_str().to_str() == Some("pvthfhe-types"))
}

fn struct_is_secret_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Simple substring matching is enough here; we intentionally avoid regex overhead.
    lower.contains("secret") || lower.contains("share") || lower.contains("sk")
}

fn is_vec_u8(ty: &Type) -> bool {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return false;
    };
    let Some(seg) = path.segments.last() else {
        return false;
    };
    if seg.ident != "Vec" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    let mut iter = args.args.iter();
    matches!(
        (iter.next(), iter.next()),
        (
            Some(syn::GenericArgument::Type(Type::Path(TypePath { qself: None, path: u8_path }))),
            None,
        ) if u8_path.segments.last().is_some_and(|s| s.ident == "u8")
    )
}

fn is_poly(ty: &Type) -> bool {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return false;
    };
    path.segments.last().is_some_and(|seg| seg.ident == "Poly")
}

fn field_name(field: &Field, idx: usize) -> String {
    field
        .ident
        .as_ref()
        .map(|ident| ident.to_string())
        .unwrap_or_else(|| format!("#{idx}"))
}

fn type_repr(ty: &Type) -> String {
    ty.to_token_stream().to_string()
}

fn is_compliant_wrapper(ty: &Type) -> bool {
    let repr = type_repr(ty).replace(' ', "");
    [
        "Secret<",
        "ShareSecret",
        "Sk<",
        "NoisePoly",
        "EncRandomness",
        "CcsWitnessSecret",
        "ProtocolBytes",
    ]
    .iter()
    .any(|token| repr.contains(token))
}

fn crate_name_for(path: &Path, root: &Path) -> String {
    path.strip_prefix(root.join("crates"))
        .ok()
        .and_then(|rel| rel.components().next())
        .and_then(|c| c.as_os_str().to_str())
        .unwrap_or("unknown")
        .to_string()
}

struct StructVisitor<'a> {
    file: &'a Path,
    crate_name: String,
    violations: &'a mut Vec<Violation>,
}

impl<'ast, 'a> Visit<'ast> for StructVisitor<'a> {
    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        if !struct_is_secret_like(&item.ident.to_string()) {
            return;
        }

        match &item.fields {
            Fields::Named(fields) => {
                for (idx, field) in fields.named.iter().enumerate() {
                    if matches!(field.vis, Visibility::Public(_))
                        && !is_compliant_wrapper(&field.ty)
                        && (is_vec_u8(&field.ty) || is_poly(&field.ty))
                    {
                        self.violations.push(Violation {
                            crate_name: self.crate_name.clone(),
                            file: self.file.to_path_buf(),
                            struct_name: item.ident.to_string(),
                            field_name: field_name(field, idx),
                            type_repr: type_repr(&field.ty),
                        });
                    }
                }
            }
            Fields::Unnamed(fields) => {
                for (idx, field) in fields.unnamed.iter().enumerate() {
                    if matches!(field.vis, Visibility::Public(_))
                        && !is_compliant_wrapper(&field.ty)
                        && (is_vec_u8(&field.ty) || is_poly(&field.ty))
                    {
                        self.violations.push(Violation {
                            crate_name: self.crate_name.clone(),
                            file: self.file.to_path_buf(),
                            struct_name: item.ident.to_string(),
                            field_name: field_name(field, idx),
                            type_repr: type_repr(&field.ty),
                        });
                    }
                }
            }
            Fields::Unit => {}
        }
    }
}

#[test]
fn secret_types_use_newtypes() {
    let root = workspace_root();
    let mut violations = Vec::new();

    for entry in WalkDir::new(root.join("crates"))
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if entry.file_type().is_dir() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") || should_skip(path) {
            continue;
        }

        let src = match fs::read_to_string(path) {
            Ok(src) => src,
            Err(err) => {
                eprintln!("warning: failed to read {}: {err}", path.display());
                continue;
            }
        };

        let file = match syn::parse_file(&src) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("warning: failed to parse {}: {err}", path.display());
                continue;
            }
        };

        let crate_name = crate_name_for(path, &root);
        let mut visitor = StructVisitor {
            file: path,
            crate_name,
            violations: &mut violations,
        };
        visitor.visit_file(&file);
    }

    if !violations.is_empty() {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for v in &violations {
            *counts.entry(v.crate_name.clone()).or_default() += 1;
        }

        let list = violations
            .iter()
            .map(|v| {
                format!(
                    "{}:{}.{}: {}",
                    v.file.display(),
                    v.struct_name,
                    v.field_name,
                    v.type_repr
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let breakdown = counts
            .into_iter()
            .map(|(crate_name, count)| format!("  - {crate_name}: {count}"))
            .collect::<Vec<_>>()
            .join("\n");

        panic!(
            "R0.3 RED: found {} secret-material field violation(s):\n{}\n\nBy crate:\n{}",
            violations.len(),
            list,
            breakdown
        );
    }
}
