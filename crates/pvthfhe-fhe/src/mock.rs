//! Deterministic mock [`FheBackend`] for testing.
//!
//! **Not cryptographically secure.** Enabled with `--features mock`.
//!
//! Round-trip invariant: `aggregate_decrypt(encrypt(pk, m), shares, t) == m`
//! where `pk = aggregate_keygen(shares)` and each `ds_i = partial_decrypt(ct, i)`.

use crate::mock_impl::MockBackendInner;

/// Deterministic mock backend.
///
/// Uses XOR-based toy operations. The round-trip property holds:
/// `aggregate_decrypt(encrypt(pk, m)) == m`.
///
/// **Not cryptographically secure.**
pub type MockBackend = MockBackendInner;
