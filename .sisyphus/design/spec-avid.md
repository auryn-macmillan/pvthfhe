# Provable AVID Specification

**Status**: draft  
**Paper**: Abraham, Bacho, Stern — ePrint 2026/1159, §4.3  
**Implementation**: `crates/pvthfhe-pvss/src/avid.rs`

## Overview

Provable AVID replaces broadcast of all n encrypted shares with information dispersal: the dealer publishes a Merkle root, and each party privately retrieves only their assigned share with a Merkle inclusion proof.

## Protocol

1. **Disperse**: Dealer builds an 8-ary Keccak256-backed Merkle tree over all encrypted shares. Publishes Merkle root.
2. **Private Retrieve**: Each party requests their share. Dealer returns share + Merkle inclusion proof.
3. **Verify**: Recipient verifies Merkle proof against the published root.

## Types

- `DispersedShares { merkle_root, party_count, proofs: HashMap<u32, MerkleInclusionProof> }`
- `MerkleInclusionProof { leaf_index, siblings: Vec<Vec<Fr>> }`

## Integration

- Used in DKG Round 1 share distribution
- Compatible with committee-based sharing (T2)
- Existing NIZK share-encryption proofs operate on retrieved shares

## See Also

- `crates/pvthfhe-pvss/src/avid.rs` — implementation
- `spec-committee-pvss.md` — committee-based sharing
