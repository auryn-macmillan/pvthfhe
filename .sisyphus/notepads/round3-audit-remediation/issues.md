# Issues — Round 3 Audit Remediation (A.1, A.2)

## Pre-existing issues encountered

### 1. `DecryptShare` missing `nizk_proof_bytes` in mock_impl.rs
- **Status**: Fixed (one-liner)
- **Location**: `crates/pvthfhe-fhe/src/mock_impl.rs:206`
- **Cause**: The `DecryptShare` struct gained an `nizk_proof_bytes: Option<Vec<u8>>` field
  but the mock construction wasn't updated.

### 2. `aggregate_must_use_submitted_shares_not_internal_state` test failure
- **Status**: Pre-existing, NOT fixed (unrelated to A.1/A.2)
- **Location**: `crates/pvthfhe-fhe/tests/aggregate_uses_submitted_shares.rs`
- **Note**: F67 finding — aggregate_decrypt recomputes from internal state.
  Outside scope of A.1/A.2.

### 3. `demo_prints_banner_and_backend_ids` test with n=3, t=2
- **Status**: Pre-existing, NOT fixed
- **Location**: `crates/pvthfhe-cli/tests/demo_banner.rs`
- **Cause**: Test uses parameters (n=3, t=2) that violate fhe.rs constraint t <= (n-1)/2.
  Outside scope of A.1/A.2.

### 4. `sha2` import needed in fhers.rs
- **Status**: Fixed
- **Cause**: `generate_deterministic_esm_noise_for_party` uses `Sha256` which wasn't imported.
  Added `use sha2::{Digest, Sha256};` to fhers.rs imports.
