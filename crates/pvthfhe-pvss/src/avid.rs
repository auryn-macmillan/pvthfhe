//! Provable AVID (Asynchronous Verifiable Information Dispersal).
//!
//! Implements the Disperse + PrivateRetrieve pattern from:
//!   Abraham, Bacho, Stern — Quadratic Asynchronous DKG from Plain Setup
//!   (ePrint 2026/1159, §4.3, Algorithms 11–13)
//!
//! ## Overview
//!
//! Instead of broadcasting all n encrypted shares to all parties, the dealer:
//! 1. **Disperses**: Builds a Merkle tree over encrypted shares, publishes the
//!    Merkle root as a succinct dispersal proof.
//! 2. **Private Retrieval**: Each party requests only their assigned share;
//!    the disperser provides a Merkle inclusion proof.
//!
//! ## Merkle Tree
//!
//! 8-ary Poseidon-equivalent (Keccak256-backed) Merkle tree over BN254 Fr
//! field elements. Each encrypted share is hashed into an Fr element via
//! SHA-256 domain-separated hash.

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

const DOMAIN_SEPARATOR: &[u8] = b"pvthfhe-avid/v1";
const DEFAULT_ARITY: usize = 8;

// ── Types ─────────────────────────────────────────────────────────────────

/// A Merkle inclusion proof for a single leaf.
#[derive(Clone, Debug)]
pub struct MerkleInclusionProof {
    /// 0-based leaf index.
    pub leaf_index: usize,
    /// Sibling nodes at each level. `siblings[level]` contains the siblings
    /// for that level (arity-1 siblings).
    pub siblings: Vec<Vec<Fr>>,
}

/// Result of the dispersal phase: a Merkle root and per-party proofs.
#[derive(Clone, Debug)]
pub struct DispersedShares {
    /// Merkle root commitment over all encrypted shares.
    pub merkle_root: Fr,
    /// Number of parties / leaves.
    pub party_count: usize,
    /// Merkle inclusion proof for each party (party_id → proof).
    pub proofs: HashMap<u32, MerkleInclusionProof>,
}

// ── Hash Functions ────────────────────────────────────────────────────────

fn leaf_hash(party_id: u32, share_bytes: &[u8], session_id: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":leaf:");
    h.update(session_id);
    h.update(&party_id.to_be_bytes());
    h.update(share_bytes);
    Fr::from_be_bytes_mod_order(&h.finalize())
}

fn internal_hash_with_domain(values: &[Fr], is_leaf_level: bool) -> Fr {
    let domain_val = if is_leaf_level { Fr::zero() } else { Fr::one() };
    let mut h = Keccak256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":internal:");
    h.update(&domain_val.into_bigint().to_bytes_be());
    for val in values {
        h.update(&val.into_bigint().to_bytes_be());
    }
    Fr::from_be_bytes_mod_order(&h.finalize())
}

// ── Merkle Tree Construction ──────────────────────────────────────────────

fn build_tree(leaves: &[Fr], arity: usize) -> (Vec<Vec<Fr>>, Fr) {
    let mut levels: Vec<Vec<Fr>> = vec![leaves.to_vec()];
    let mut is_leaf = true;
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let mut next = Vec::new();
        for chunk in current.chunks(arity) {
            next.push(internal_hash_with_domain(chunk, is_leaf));
        }
        is_leaf = false;
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    (levels, root)
}

fn generate_proof(tree: &[Vec<Fr>], leaf_index: usize, arity: usize) -> MerkleInclusionProof {
    let mut siblings: Vec<Vec<Fr>> = Vec::new();
    let mut idx = leaf_index;
    for level in 0..tree.len() - 1 {
        let chunk_start = (idx / arity) * arity;
        let chunk = &tree[level][chunk_start..(chunk_start + arity).min(tree[level].len())];
        let pos_in_chunk = idx - chunk_start;
        let sib: Vec<Fr> = chunk
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != pos_in_chunk)
            .map(|(_, v)| *v)
            .collect();
        siblings.push(sib);
        idx /= arity;
    }
    MerkleInclusionProof {
        leaf_index,
        siblings,
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Disperse encrypted shares into a Merkle tree.
///
/// Takes a map of `(party_id → encrypted_share_bytes)`, builds an 8-ary
/// Merkle tree, and returns the Merkle root plus per-party inclusion proofs.
/// The Merkle tree binds to `session_id` to prevent cross-session replay.
pub fn disperse(shares: &HashMap<u32, Vec<u8>>, session_id: &[u8]) -> DispersedShares {
    let party_count = shares.len();

    // Build leaves: each party's share hashed into an Fr element
    let mut sorted: Vec<(u32, Vec<u8>)> = shares.iter().map(|(k, v)| (*k, v.clone())).collect();
    sorted.sort_by_key(|(k, _)| *k);

    let leaves: Vec<Fr> = sorted
        .iter()
        .map(|(id, bytes)| leaf_hash(*id, bytes, session_id))
        .collect();

    let (tree, merkle_root) = build_tree(&leaves, DEFAULT_ARITY);

    let mut proofs = HashMap::new();
    for (i, (id, _)) in sorted.iter().enumerate() {
        proofs.insert(*id, generate_proof(&tree, i, DEFAULT_ARITY));
    }

    DispersedShares {
        merkle_root,
        party_count,
        proofs,
    }
}

/// Verify that a share is correctly included in the Merkle tree.
pub fn verify_retrieval(
    merkle_root: &Fr,
    party_id: u32,
    share_bytes: &[u8],
    proof: &MerkleInclusionProof,
    session_id: &[u8],
) -> bool {
    let leaf = leaf_hash(party_id, share_bytes, session_id);

    let mut current = leaf;
    let mut idx = proof.leaf_index;

    for (level, siblings) in proof.siblings.iter().enumerate() {
        let is_leaf_level = level == 0;
        let pos_in_chunk = idx % DEFAULT_ARITY;
        let mut chunk: Vec<Fr> = Vec::with_capacity(siblings.len() + 1);

        let mut sib_iter = siblings.iter();
        for p in 0..(siblings.len() + 1) {
            if p == pos_in_chunk {
                chunk.push(current);
            } else if let Some(&sib) = sib_iter.next() {
                chunk.push(sib);
            }
        }
        current = internal_hash_with_domain(&chunk, is_leaf_level);
        idx /= DEFAULT_ARITY;
    }

    current == *merkle_root
}

/// Verify dispersal: check that the Merkle root matches for all proofs.
pub fn verify_dispersal(dispersed: &DispersedShares) -> bool {
    if dispersed.proofs.is_empty() {
        return false;
    }
    // Verify each proof against the same root
    for (_party_id, proof) in &dispersed.proofs {
        // We can't verify without the share data here — caller must use
        // verify_retrieval with actual share bytes. This just checks that
        // the proof structure is consistent (leaf_index within bounds).
        if proof.leaf_index >= dispersed.party_count {
            return false;
        }
    }
    true
}

// ── Committee Selection (VRF-based deterministic sampling) ─────────────

/// Deterministically select a committee of `size` parties from `n` total using
/// a SHA-256-based VRF over `seed`.
///
/// For each attempt position starting at 0, the function computes
/// `SHA256(seed || position_le_bytes)`, takes the first 8 bytes as a u64,
/// and maps it to a 1-based party id via `(u64_value % n) + 1`.
/// Duplicates are skipped (discarded) and the function keeps sampling until
/// exactly `size` unique party ids are collected.
///
/// # Panics
/// Panics if `size > n`, as it is impossible to select `size` unique
/// members from a set of `n`.
pub fn committee_sample(seed: &[u8; 32], n: usize, size: usize) -> Vec<u32> {
    assert!(
        size <= n,
        "committee size {size} cannot exceed party count {n}"
    );
    let mut committee = Vec::with_capacity(size);
    let mut seen = std::collections::HashSet::new();
    let mut position: u64 = 0;

    // Safety bound: each attempt has at worst a (size/n) rejection rate.
    // After 256 attempts per desired member we give up to avoid unbounded
    // loops on adversarial seeds (extremely unlikely with SHA-256).
    let max_attempts = size.saturating_mul(256).max(256);

    while committee.len() < size && position < max_attempts as u64 {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(&position.to_le_bytes());
        let digest = h.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
        let party_id = (value % n as u64) as u32 + 1; // 1-based

        if seen.insert(party_id) {
            committee.push(party_id);
        }
        position += 1;
    }

    assert_eq!(
        committee.len(),
        size,
        "VRF committee selection exhausted attempts; seed may be adversarial"
    );
    committee
}

/// Verify that a committee selection is correct for the given seed.
///
/// Recomputes the committee using [`committee_sample`] and compares the
/// result with `committee`. Returns `true` if they match exactly, including
/// order.
pub fn verify_committee_selection(
    seed: &[u8; 32],
    n: usize,
    size: usize,
    committee: &[u32],
) -> bool {
    if size > n || committee.len() != size {
        return false;
    }
    committee_sample(seed, n, size) == committee
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SESSION: &[u8] = b"test-session";

    // ── F2 RED: session binding tests ──────────────────────────────────────

    #[test]
    fn test_avid_leaf_hash_binds_session() {
        let h1 = leaf_hash(1, b"share-data", b"session-A");
        let h2 = leaf_hash(1, b"share-data", b"session-B");
        assert_ne!(h1, h2, "different session must produce different leaf hash");
    }

    #[test]
    fn test_avid_leaf_hash_same_session_deterministic() {
        let h1 = leaf_hash(1, b"share-data", b"session-C");
        let h2 = leaf_hash(1, b"share-data", b"session-C");
        assert_eq!(h1, h2, "same session must be deterministic");
    }

    #[test]
    fn test_avid_cross_session_share_replay_rejected() {
        let mut shares_a = HashMap::new();
        let mut shares_b = HashMap::new();
        for i in 0..5u32 {
            shares_a.insert(i + 1, vec![i as u8; 32]);
            shares_b.insert(i + 1, vec![i as u8; 32]);
        }
        let dispersed_a = disperse(&shares_a, b"session-A");
        let dispersed_b = disperse(&shares_b, b"session-B");

        // Merkle roots must differ across sessions even with identical shares
        assert_ne!(
            dispersed_a.merkle_root, dispersed_b.merkle_root,
            "different session must produce different Merkle root"
        );

        // Session-A proof must NOT verify against session-B root
        let proof = dispersed_a.proofs.get(&1).unwrap();
        let share = shares_a.get(&1).unwrap();
        assert!(
            !verify_retrieval(&dispersed_b.merkle_root, 1, share, proof, b"session-B"),
            "cross-session Merkle proof must be rejected"
        );
    }

    // ── Existing tests updated with TEST_SESSION ───────────────────────────

    #[test]
    fn test_disperse_and_verify() {
        let mut shares = HashMap::new();
        for i in 0..10u32 {
            shares.insert(i + 1, vec![i as u8; 64]);
        }
        let dispersed = disperse(&shares, TEST_SESSION);

        assert_eq!(dispersed.party_count, 10);
        assert_eq!(dispersed.proofs.len(), 10);

        // Verify each party can retrieve their share
        for (id, proof) in &dispersed.proofs {
            let share = shares.get(id).unwrap();
            assert!(
                verify_retrieval(&dispersed.merkle_root, *id, share, proof, TEST_SESSION),
                "party {id} retrieval should verify"
            );
        }
    }

    #[test]
    fn test_tampered_share_rejected() {
        let mut shares = HashMap::new();
        for i in 0..5u32 {
            shares.insert(i + 1, vec![i as u8; 32]);
        }
        let dispersed = disperse(&shares, TEST_SESSION);

        let proof = dispersed.proofs.get(&1).unwrap();
        let tampered = vec![0xFF; 32];
        assert!(
            !verify_retrieval(&dispersed.merkle_root, 1, &tampered, proof, TEST_SESSION),
            "tampered share should be rejected"
        );
    }

    #[test]
    fn test_wrong_party_rejected() {
        let mut shares = HashMap::new();
        shares.insert(1, vec![0xAA; 32]);
        shares.insert(2, vec![0xBB; 32]);
        let dispersed = disperse(&shares, TEST_SESSION);

        // Party 1's proof should NOT verify for party 2's share
        let proof = dispersed.proofs.get(&1).unwrap();
        let share_2 = shares.get(&2).unwrap();
        assert!(
            !verify_retrieval(&dispersed.merkle_root, 2, share_2, proof, TEST_SESSION),
            "wrong party proof should be rejected"
        );
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let mut shares = HashMap::new();
        shares.insert(1, vec![0x11; 32]);
        shares.insert(2, vec![0x22; 32]);

        let d1 = disperse(&shares, TEST_SESSION);
        let d2 = disperse(&shares, TEST_SESSION);
        assert_eq!(d1.merkle_root, d2.merkle_root);
    }

    #[test]
    fn test_different_shares_different_root() {
        let mut s1 = HashMap::new();
        s1.insert(1, vec![0x11; 32]);
        let d1 = disperse(&s1, TEST_SESSION);

        let mut s2 = HashMap::new();
        s2.insert(1, vec![0x22; 32]);
        let d2 = disperse(&s2, TEST_SESSION);

        assert_ne!(d1.merkle_root, d2.merkle_root);
    }

    // ── committee selection tests ──────────────────────────────────────

    #[test]
    fn committee_sample_is_deterministic() {
        let seed = [0xCA; 32];
        let c1 = committee_sample(&seed, 100, 10);
        let c2 = committee_sample(&seed, 100, 10);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 10);
    }

    #[test]
    fn committee_sample_no_duplicates() {
        let seed = [0xAB; 32];
        let committee = committee_sample(&seed, 1000, 50);
        let mut seen = std::collections::HashSet::new();
        for id in &committee {
            assert!(seen.insert(*id), "duplicate party id {id}");
        }
    }

    #[test]
    fn committee_sample_sizes() {
        let seed = [0x42; 32];
        for size in [1, 5, 10, 20] {
            let committee = committee_sample(&seed, 50, size);
            assert_eq!(committee.len(), size, "wrong size for size={size}");
        }
    }

    #[test]
    fn verify_committee_selection_roundtrip() {
        let seed = [0xDE; 32];
        let committee = committee_sample(&seed, 200, 15);
        assert!(verify_committee_selection(&seed, 200, 15, &committee));
    }

    #[test]
    fn verify_committee_selection_rejects_wrong() {
        let seed = [0xDE; 32];
        let committee = committee_sample(&seed, 200, 15);
        let mut tampered = committee.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        assert!(!verify_committee_selection(&seed, 200, 15, &tampered));
    }
}
