# Distributed Key Generation Protocol (Architecture B)

## Overview
This document specifies the distributed key generation (DKG) protocol for PVTHFHE Architecture B (Lattice PVSS + LatticeFold+ + MicroNova).

## Security Parameters
All parameter sets MUST target ≥120-bit security.
- **N**: 8192
- **L**: 3 RNS limbs
- **QIS**: ≈[2^58, 2^58, 2^58]
- **log₂(Q)**: ≈174 bits

## Participants and Model
- **Parties**: N parties P₁…Pₙ
- **Threshold**: t = ⌊N/2⌋+1
- **Adversary Model**: Static malicious adversary, abort-with-public-blame
- **Communication Model**: Timeout-based rounds (synchronous broadcast is not assumed)

## Round 1 — Share Distribution (PVSS)
Each party Pᵢ acts as a dealer: samples secret sᵢ ← χ_key, computes encrypted shares {Enc(pkⱼ, sᵢ,ⱼ)}ⱼ using lattice IBE/PVSS (Hermine-style everywhere-short secret sharing from 2026/419).

- **Broadcasts**: 
  `KeygenMsg1 { dealer_id: u32, encrypted_shares: Vec<EncShare>, nizk_well_formed: NizkWellFormed, version: u8 }`
- **Wire format**: CBOR-encoded, length-prefixed with 4-byte big-endian length header. No unbounded fields without length prefix.

## Round 2 — Share Verification + Complaint
Each party Pⱼ decrypts its share sᵢ,ⱼ from each dealer Pᵢ, verifies the NIZK.

- **If valid, broadcasts**: 
  `KeygenMsg2 { party_id: u32, dealer_id: u32, ack: true, version: u8 }`
- **If invalid, broadcasts**: 
  `KeygenMsg2 { party_id: u32, dealer_id: u32, ack: false, complaint_proof: ComplaintProof, version: u8 }`
- **Wire format**: CBOR-encoded, length-prefixed with 4-byte big-endian length header. No unbounded fields without length prefix.

## Round 3 — Key Aggregation
Aggregator collects ≥t valid acks per dealer, computes aggregate public key: pk = Σᵢ pkᵢ (sum of individual public keys).

- **Broadcasts**: 
  `KeygenMsg3 { aggregate_pk: RlwePk, participant_set: Vec<u32>, version: u8 }`
- **Wire format**: CBOR-encoded, length-prefixed with 4-byte big-endian length header. No unbounded fields without length prefix.

## NIZK Statements
1. **NizkWellFormed**: "∃ sᵢ ∈ Rq^k short such that ∀j: Enc(pkⱼ, sᵢ,ⱼ) = encrypted_shares[j]"
   - Proven via lattice NIZK (LatticeFold+ accumulator).
   - *Note: Soundness is currently flagged as open problem P1.*
2. **ComplaintProof**: "∃ skⱼ such that Dec(skⱼ, encrypted_shares[j]) ≠ valid_share"
   - Proven via decryption failure witness.

## Blame Matrix

| Failure Mode | Detection | Blame Target | Recovery |
|---|---|---|---|
| Malformed NIZK in Round 1 | Any party verifies NIZK → fails | Dealer Pᵢ | Exclude Pᵢ, re-run if <t dealers remain |
| Missing Round 1 message | Timeout after Δ₁ | Silent party Pᵢ | Exclude Pᵢ |
| Equivocation (two different Round 1 msgs) | Any party sees two msgs with same dealer_id | Dealer Pᵢ | Exclude Pᵢ, publish both msgs as evidence |
| Malformed complaint in Round 2 | Aggregator verifies complaint_proof → fails | Complaining party Pⱼ | Ignore complaint, proceed |
| Missing Round 2 ack | Timeout after Δ₂ | Silent party Pⱼ | Exclude Pⱼ from participant set |
| Aggregate pk inconsistent | Any party recomputes pk from participant set → mismatch | Aggregator | Re-run aggregation with different aggregator |
