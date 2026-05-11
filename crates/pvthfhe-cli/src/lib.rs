//! # ⚠️ INTENTIONALLY MINIMAL
//!
//! CLI façade. Real logic lives in feature-gated modules (`pvss_support`, `demo_nizk`, `compressor_glue`, `full_pipeline`) and the binary entry-points in `src/bin/`. The `lib.rs` itself is intentionally a thin module-export shim.
/// Shared lattice-PVSS helpers for CLI binaries and tests.
#[cfg(feature = "with-fhe")]
pub mod pvss_support;

#[cfg(feature = "with-fhe")]
pub mod demo_nizk;

#[cfg(feature = "with-fhe")]
pub mod compressor_glue;

#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
pub mod full_pipeline;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
