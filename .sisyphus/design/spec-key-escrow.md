# Key Escrow / Distributed Authorization Specification

**Status**: draft  
**Paper**: Abraham, Bacho, Stern — ePrint 2026/1159, §6  
**Implementation**: `crates/pvthfhe-pvss/src/key_escrow.rs`

## Overview

Key Escrow generates ephemeral key pairs where the secret key is hidden until f+1 parties cooperate to reconstruct it. Used for decryption authorization: the aggregator must prove escrowed authorization before partial decryptions are accepted.

## Protocol

1. **KeyEscrow**: Generate `(eph_pk, π)` from `SHA256(session_id || tag || epoch)`. Secret key is deterministically derived.
2. **Share**: Split secret key into n Shamir shares over BN254 Fr.
3. **KeyRetrieve**: Collect ≥ f+1 shares, reconstruct via Lagrange at x=0.
4. **Verify**: `KeyVerify(eph_pk, π, tag)` checks commitment.

## Types

- `EphPublicKey { key_bytes: [u8; 32], epoch: u64 }`
- `KeyEscrowProof { epoch: u64, commitment: [u8; 32] }`
- `EphSecretShare { party_id: u32, share: Fr }`
- `EphSecretKey { key_bytes: [u8; 32] }`

## Integration

- Used in decryption authorization flow
- Ephemeral key pairs bound to DKG session
- Epoch-based replay protection

## See Also

- `crates/pvthfhe-pvss/src/key_escrow.rs` — implementation
- `spec-decrypt.md` — threshold decryption protocol
