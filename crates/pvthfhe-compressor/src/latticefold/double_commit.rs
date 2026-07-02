//! LatticeFold+ §4.1 Double commitment scheme.
//!
//! Implements commitments-of-commitments for shorter proofs.
//! The inner commitment binds to the witness data; the outer commitment
//! binds to the inner commitment, enabling efficient sumcheck-based
//! verification of the commitment chain.
//!
//! All logic is implemented in [`super::fold`] — this module re-exports
//! the public API for plan-conformant module structure.

pub use super::fold::DoubleCommitment;
pub use super::fold::{double_commit, smart_commit, verify_double_commitment};

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn double_commit_roundtrip_via_module() {
        let data = b"test data for commitment";
        let dc = double_commit(data, b"test");
        assert!(verify_double_commitment(&dc, data, b"test"));
    }

    #[test]
    fn double_commit_tamper_rejected() {
        let data = b"original data";
        let dc = double_commit(data, b"test");
        let tampered = b"tampered data";
        assert!(!verify_double_commitment(&dc, tampered, b"test"));
    }

    #[test]
    fn smart_commit_small_n() {
        let data = b"smart commit data";
        let small = smart_commit(data, b"test", 3);
        let large = smart_commit(data, b"test", 11);
        assert_eq!(small.inner_commitment, small.outer_commitment);
        assert_ne!(large.inner_commitment, large.outer_commitment);
    }
}
