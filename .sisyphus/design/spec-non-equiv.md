# Non-Equivocation Protocol Specification

**Status**: draft  
**Paper**: Abraham, Bacho, Stern — ePrint 2026/1159, §4.1  
**Implementation**: `crates/pvthfhe-non-equiv/`

## Overview

The NonEquiv protocol binds each dealer to a single DKG Round 1 message. If a dealer produces two distinct Round 1 messages, the combination of their NonEquiv proofs constitutes cryptographic evidence of equivocation.

## Protocol

1. After Round 1 broadcast, each observer signs `SHA256("pvthfhe-non-equiv/v1:msg-hash:" || dealer_id || round1_msg_hash)` using their Schnorr key (from `PartyIdentity`).
2. Signatures are collected until `n-f` distinct signers have signed.
3. The collection of n-f signatures is the NonEquiv proof.

## Security

Quorum intersection: any two sets of n-f signatures overlap by at least n-2f ≥ 1 honest party. That honest party would not sign two different messages → equivocation is detectable.

## Integration

- Wire format: `NonEquivProof` serialized as binary (dealer_id || message_hash || quorum_size || num_sigs || sig1 || sig2...).
- Round: Injected as "Round 1.5" between Round 1 broadcast and Round 2 complaints.
- Stored in `DkgTranscript.non_equiv_proofs`.

## See Also

- `spec-keygen.md` — DKG protocol, blame matrix
- `crates/pvthfhe-non-equiv/src/lib.rs` — implementation
