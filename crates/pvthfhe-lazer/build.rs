//! Build script for pvthfhe-lazer.
//!
//! On `cfg(feature = "enable-lazer")`, invokes the LaZer Makefile to produce
//! `liblazer.a` and links it along with its third-party dependencies (GMP,
//! MPFR, C++ standard library, libm).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build the native library when the feature is enabled.
    if cfg!(feature = "enable-lazer") {
        build_lazer();
    } else {
        // Stub: no native library needed, emit empty linkage.
        println!("cargo:warning=pvthfhe-lazer built without enable-lazer feature; FFI calls will be unavailable");
    }
}

fn build_lazer() {
    let lazer_dir = PathBuf::from(
        env::var("LAZER_DIR").unwrap_or_else(|_| format!("{}/lazer", env::var("HOME").unwrap())),
    );

    if !lazer_dir.join("Makefile").exists() {
        panic!(
            "LaZer source not found at {}. Set LAZER_DIR env var or clone https://github.com/auryn-macmillan/lazer",
            lazer_dir.display()
        );
    }

    let local_prefix = PathBuf::from(
        env::var("LOCAL_PREFIX")
            .unwrap_or_else(|_| format!("{}/.local", env::var("HOME").unwrap())),
    );

    // Determine include dirs and lib dirs for GMP / MPFR.
    // If LOCAL_PREFIX points to a custom local installation, use it.
    let inc_dir = local_prefix.join("include");
    let lib_dir = local_prefix.join("lib");

    let cppflags = format!("-DNDEBUG -I{}", inc_dir.display());

    // Build liblazer.a via make
    let status = Command::new("make")
        .arg("lib-static")
        .env("CPPFLAGS", &cppflags)
        .env("libgmp", format!("-L{} -lgmp", lib_dir.display()))
        .env("libmpfr", format!("-L{} -lmpfr", lib_dir.display()))
        .current_dir(&lazer_dir)
        .status()
        .expect("Failed to execute make for LaZer");

    if !status.success() {
        panic!("LaZer build failed");
    }

    // Emit linker directives so Rust can find the static library and its deps.
    println!("cargo:rustc-link-search=native={}", lazer_dir.display());
    println!("cargo:rustc-link-lib=static=lazer");

    // Intel HEXL (built as part of LaZer's third-party deps).
    let hexl_lib_dir = lazer_dir.join("third_party/hexl-development/build/hexl/lib");
    if !hexl_lib_dir.exists() {
        let hexl_lib_dir_alt = lazer_dir.join("third_party/hexl-development/build/hexl/lib64");
        if hexl_lib_dir_alt.exists() {
            println!(
                "cargo:rustc-link-search=native={}",
                hexl_lib_dir_alt.display()
            );
            println!("cargo:rustc-link-lib=static=hexl");
        }
    } else {
        println!("cargo:rustc-link-search=native={}", hexl_lib_dir.display());
        println!("cargo:rustc-link-lib=static=hexl");
    }

    // System / local libraries needed by LaZer.
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=mpfr");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=m");

    // Re-run build if any source files in lazer/src/ change.
    println!("cargo:rerun-if-changed={}/src/", lazer_dir.display());
    println!("cargo:rerun-if-changed={}/config.h", lazer_dir.display());
    println!("cargo:rerun-if-changed={}/Makefile", lazer_dir.display());
}
