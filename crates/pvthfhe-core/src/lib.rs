//! # ⚠️ INTENTIONALLY MINIMAL
//!
//! This crate intentionally hosts no library code. Its sole purpose is to host shared test vectors under `tests/vectors/*.json` and property tests consumed cross-crate (e.g. `pvthfhe-aggregator/tests/decrypt_roundtrip.rs`). The empty re-export keeps the crate compilable without diluting the skeleton-crate lint.
//!
#![allow(missing_docs)]

pub use pvthfhe_compressor;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
