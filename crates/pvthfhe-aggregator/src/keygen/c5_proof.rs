//! C5 Aggregate Public-Key Formation Proof.
//!
//! Proves that `pk_agg == Σ pk_i` with per-participant Proof-of-Possession
//! (PoP) for rogue-key attack protection.
//!
//! # Proof structure
//!
//! Each participant generates a PoP proving knowledge of their secret key `sk_i`
//! corresponding to their public key `pk_i`. The aggregator bundles all PoPs
//! together with the sum relation claim, producing a `C5Proof`. The
//! `c5_proof_root` is a SHA-256 hash of the proof bundle for verification
//! statement inclusion.
//!
//! # Security
//!
//! The PoP prevents rogue-key attacks: an adversary cannot claim a public key
//! `pk_M = X - Σ_{i≠M} pk_i` without knowing the corresponding secret key `sk_M`.
//! Combined with H2 commit-reveal binding, this provides two layers of rogue-key
//! protection.

use super::types::PartyId;
use pvthfhe_fhe::{FheBackend, KeygenShare, PublicKey};
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════════════
// PoP: Proof-of-Possession per participant
// ═══════════════════════════════════════════════════════════════════════════

/// Per-participant Proof-of-Possession proving knowledge of the secret key
/// corresponding to the claimed public key.
#[derive(Clone, Debug)]
pub struct PoP {
    /// Party that generated this proof.
    pub party_id: PartyId,
    /// Fresh random nonce for commit-reveal binding.
    pub nonce: [u8; 32],
    /// SHA256 commitment binding (party_id, session_id, pk_bytes, nonce).
    pub commitment: [u8; 32],
    /// Keygen share bytes — the "response" allowing the verifier to check
    /// `aggregate_keygen([share]) == pk_i`.
    pub keygen_share_bytes: Vec<u8>,
}

/// C5 formation proof: proves `pk_agg = Σ pk_i` with per-participant PoP.
#[derive(Clone, Debug)]
pub struct C5Proof {
    /// Proof format version.
    pub version: u8,
    /// SHA256 hash of sorted participant IDs.
    pub participant_set_hash: [u8; 32],
    /// Raw aggregate public key bytes.
    pub aggregate_pk_bytes: Vec<u8>,
    /// Per-participant Proof-of-Possession proofs.
    pub pops: Vec<PoP>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Core API
// ═══════════════════════════════════════════════════════════════════════════

/// Domain separator prefix for C5 PoP hashing.
const POP_DOMAIN: &[u8] = b"pvthfhe-c5-pop/v1";

/// Generate a Proof-of-Possession for a single participant.
///
/// Called per-party during keygen. The `keygen_share_bytes` are the raw bytes
/// from the participant's keygen share (opaque to the C5 module).
pub fn generate_pop(
    party_id: PartyId,
    session_id: &[u8; 32],
    pk_bytes: &[u8],
    keygen_share_bytes: Vec<u8>,
    nonce: [u8; 32],
) -> PoP {
    let commitment = compute_pop_commitment(party_id, session_id, pk_bytes, &nonce);
    PoP {
        party_id,
        nonce,
        commitment,
        keygen_share_bytes,
    }
}

/// Verify a single PoP against a claimed public key.
///
/// Checks:
/// 1. The commitment is correctly formed (binds party_id, session_id, pk, nonce).
/// 2. The keygen share produces the claimed public key via `aggregate_keygen`.
pub fn verify_pop(
    pop: &PoP,
    pk_bytes: &[u8],
    session_id: &[u8; 32],
    backend: &dyn FheBackend,
) -> Result<(), String> {
    // 1. Recompute and check commitment
    let expected_commitment =
        compute_pop_commitment(pop.party_id, session_id, pk_bytes, &pop.nonce);
    if pop.commitment != expected_commitment {
        return Err("C5 PoP commitment mismatch".to_string());
    }

    // 2. Check that the keygen share produces the claimed public key
    let share = KeygenShare {
        party_id: pop.party_id,
        bytes: pvthfhe_types::ProtocolBytes(pop.keygen_share_bytes.clone()),
    };
    let pk_from_share = backend
        .aggregate_keygen(&[share])
        .map_err(|e| format!("{e}"))?;
    if pk_from_share.bytes != pk_bytes {
        return Err("C5 PoP key mismatch: aggregate_keygen(share) != pk_i".to_string());
    }

    Ok(())
}

/// Construct a C5 proof from collected PoPs.
///
/// The participant_set_hash should be computed as SHA256 of sorted party IDs.
pub fn bundle_c5_proof(
    _pks: &[PublicKey],
    aggregate_pk: &PublicKey,
    pops: Vec<PoP>,
    participant_set_hash: [u8; 32],
) -> C5Proof {
    C5Proof {
        version: 1,
        participant_set_hash,
        aggregate_pk_bytes: aggregate_pk.bytes.clone(),
        pops,
    }
}

/// Verify the full C5 proof: sum relation AND all PoPs.
///
/// Returns `Ok(())` iff:
/// 1. Every PoP passes verification for its corresponding `pk_i`.
/// 2. `aggregate_keygen(all keygen shares) == aggregate_pk`.
pub fn verify_pk_formation(
    pks: &[PublicKey],
    aggregate_pk: &PublicKey,
    proof: &C5Proof,
    session_id: &[u8; 32],
    backend: &dyn FheBackend,
) -> Result<(), String> {
    // Check version
    if proof.version != 1 {
        return Err(format!("unsupported C5 proof version: {}", proof.version));
    }

    // Check participant count matches
    if proof.pops.len() != pks.len() {
        return Err(format!(
            "C5 proof pop count ({}) != pk count ({})",
            proof.pops.len(),
            pks.len()
        ));
    }

    // 1. Verify each PoP
    for (i, pop) in proof.pops.iter().enumerate() {
        verify_pop(pop, &pks[i].bytes, session_id, backend)
            .map_err(|e| format!("C5 PoP verification failed for party {}: {e}", pop.party_id))?;
    }

    // 2. Verify sum relation: aggregate_keygen(all shares) == aggregate_pk
    let all_shares: Vec<KeygenShare> = proof
        .pops
        .iter()
        .map(|pop| KeygenShare {
            party_id: pop.party_id,
            bytes: pvthfhe_types::ProtocolBytes(pop.keygen_share_bytes.clone()),
        })
        .collect();

    let recomputed_pk = backend
        .aggregate_keygen(&all_shares)
        .map_err(|e| format!("{e}"))?;
    if recomputed_pk.bytes != aggregate_pk.bytes {
        return Err("C5 sum relation failed: aggregate_keygen(shares) != aggregate_pk".to_string());
    }

    Ok(())
}

/// Compute the `c5_proof_root` as a SHA-256 hash of the canonical proof
/// serialization. The result is a compact 32-byte commitment suitable for
/// inclusion in the verification statement.
///
/// When integrated into the on-chain verifier (Task 4), this will be
/// replaced with a Poseidon BN254 hash for efficient in-circuit verification.
pub fn compute_c5_proof_root(proof: &C5Proof) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-c5-proof-root/v1");
    hasher.update(&[proof.version]);
    hasher.update(&proof.participant_set_hash);
    // Prefix-length encode aggregate_pk_bytes to prevent ambiguity
    hasher.update(&(proof.aggregate_pk_bytes.len() as u32).to_be_bytes());
    hasher.update(&proof.aggregate_pk_bytes);
    // Encode pop count
    hasher.update(&(proof.pops.len() as u32).to_be_bytes());
    for pop in &proof.pops {
        hasher.update(&pop.party_id.to_be_bytes());
        hasher.update(&pop.nonce);
        hasher.update(&pop.commitment);
        hasher.update(&(pop.keygen_share_bytes.len() as u32).to_be_bytes());
        hasher.update(&pop.keygen_share_bytes);
    }
    hasher.finalize().into()
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn compute_pop_commitment(
    party_id: PartyId,
    session_id: &[u8; 32],
    pk_bytes: &[u8],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POP_DOMAIN);
    h.update(&party_id.to_be_bytes());
    h.update(session_id);
    h.update(&(pk_bytes.len() as u32).to_be_bytes());
    h.update(pk_bytes);
    h.update(nonce);
    h.finalize().into()
}
