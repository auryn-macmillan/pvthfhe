//! pvthfhe-cli — command-line interface for PVTHFHE.
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
