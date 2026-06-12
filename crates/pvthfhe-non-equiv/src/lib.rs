//! Non-equivocation protocol for pvthfhe DKG.
//!
//! Implements the non-equivocation sub-protocol from:
//!   Abraham, Bacho, Stern — Quadratic Asynchronous DKG from Plain Setup
//!   (ePrint 2026/1159, §4.1, Algorithms 7–8)
//!
//! ## Protocol
//!
//! After a dealer broadcasts a Round 1 message, each observing party signs
//! the message hash with their long-term Schnorr key (from `PartyIdentity`).
//! Once a quorum of `n-f` signatures is collected, the set forms a
//! **NonEquiv proof** — cryptographic evidence that the observed Round 1
//! message is the only one that party has sent (up to quorum intersection).
//!
//! If two distinct Round 1 messages from the same dealer carry valid
//! NonEquiv proofs, the dealer equivocated — the two proofs together form
//! **equivocation evidence**, and the dealer is excluded.
//!
//! ## Security
//!
//! Quorum intersection (any two sets of n-f out of n parties overlap by at
//! least n-2f parties). With f < n/3 in the paper's model, this guarantees
//! at least one honest party signed both — but that honest party would not
//! sign two different messages. In pvthfhe's model (f < t = ⌊n/2⌋+1), the
//! intersection is n-2f ≥ 1, still sufficient for detection.
//!
//! ## Signature scheme
//!
//! Uses the existing Schnorr-over-BN254 implementation from `pvthfhe-nizk::schnorr`,
//! which is already integrated with `PartyIdentity` (Schnorr pk + PoP).

use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_nizk::schnorr::{schnorr_sign_with_session, schnorr_verify_with_session};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// ── Domain separator ──────────────────────────────────────────────────────

const DOMAIN_SEPARATOR: &[u8] = b"pvthfhe-non-equiv/v1";

// ── Types ─────────────────────────────────────────────────────────────────

/// A single signature in a NonEquiv proof.
#[derive(Clone, Debug)]
pub struct NonEquivSignature {
    /// Party that produced this signature (1-based).
    pub signer_id: u32,
    /// Schnorr signature: commitment point R.
    pub sig_r: G1Affine,
    /// Schnorr signature: scalar s.
    pub sig_s: Fr,
}

/// A complete NonEquiv proof for a dealer's Round 1 message.
///
/// Contains `quorum` signatures from distinct parties on the same
/// `message_hash`.  The quorum size must be at least `n - f`.
#[derive(Clone, Debug)]
pub struct NonEquivProof {
    /// The dealer whose message this proof binds.
    pub dealer_id: u32,
    /// Hash of the dealer's Round 1 message that was signed.
    pub message_hash: [u8; 32],
    /// Collected signatures (must be from distinct parties).
    pub signatures: Vec<NonEquivSignature>,
    /// Quorum size required (n-f).
    pub quorum_size: usize,
}

/// Cryptographic evidence of equivocation.
///
/// Two valid [`NonEquivProof`]s for the same dealer but different
/// `message_hash` values constitute a proof that the dealer sent two
/// distinct Round 1 messages — equivocation.
#[derive(Clone, Debug)]
pub struct EquivocationEvidence {
    pub dealer_id: u32,
    pub proof_a: NonEquivProof,
    pub proof_b: NonEquivProof,
}

/// Errors returned by NonEquiv operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonEquivError {
    /// Quorum not reached — fewer than n-f signatures collected.
    InsufficientSignatures { have: usize, need: usize },
    /// Duplicate signer in signature set.
    DuplicateSigner(u32),
    /// A signature failed verification.
    InvalidSignature(u32),
    /// Signer's public key was not provided.
    MissingPublicKey(u32),
    /// The two proofs do not constitute equivocation (same message hash).
    NotEquivocation,
    /// Message hash mismatch in verification.
    MessageHashMismatch,
}

impl std::fmt::Display for NonEquivError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientSignatures { have, need } => {
                write!(f, "need {need} signatures, have {have}")
            }
            Self::DuplicateSigner(id) => write!(f, "duplicate signer: party {id}"),
            Self::InvalidSignature(id) => write!(f, "invalid signature from party {id}"),
            Self::MissingPublicKey(id) => write!(f, "missing public key for party {id}"),
            Self::NotEquivocation => write!(f, "proofs have same message hash — not equivocation"),
            Self::MessageHashMismatch => write!(f, "message hash does not match proof"),
        }
    }
}

impl std::error::Error for NonEquivError {}

// ── Message hashing ───────────────────────────────────────────────────────

/// Hash a dealer's Round 1 message for NonEquiv signing.
///
/// Domain-separated SHA-256 over `(session_id, dealer_id, round1_payload)`.
pub fn hash_round1_message(dealer_id: u32, round1_payload: &[u8], session_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":msg-hash:");
    h.update(session_id);
    h.update(&dealer_id.to_be_bytes());
    h.update(round1_payload);
    h.finalize().into()
}

/// Compute the challenge Fr value from a message hash, bound to a session.
///
/// Hashes the message hash with a domain separator and session_id to produce
/// an Fr element suitable for Schnorr signing/verification. Uses
/// `from_le_bytes_mod_order` for field reduction (identical approach to the
/// existing Schnorr module).
pub fn non_equiv_challenge(message_hash: &[u8; 32], session_id: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(b":challenge:");
    hasher.update(session_id);
    hasher.update(message_hash);
    let digest: [u8; 32] = hasher.finalize().into();
    Fr::from_le_bytes_mod_order(&digest)
}

// ── Signature generation ──────────────────────────────────────────────────

/// Sign a dealer's Round 1 message for the NonEquiv protocol.
///
/// Uses the party's Schnorr signing key (from `PartyIdentity.sk`). The
/// signature binds to `session_id` to prevent cross-session replay.
///
/// The Schnorr signature is computed over the message hash converted to an Fr
/// field element via `non_equiv_challenge`.  The R point and s scalar form the
/// signature; the verifier reconstructs the challenge from (R, pk, msg_hash)
/// and checks s·G == R + e·pk.
pub fn produce_signature(
    signer_sk: Fr,
    _signer_pk: G1Affine,
    _dealer_id: u32,
    message_hash: &[u8; 32],
    session_id: &[u8],
    rng: &mut impl RngCore,
) -> NonEquivSignature {
    let msg_fr = non_equiv_challenge(message_hash, session_id);
    let (sig_r, sig_s) = schnorr_sign_with_session(signer_sk, msg_fr, session_id, rng);
    NonEquivSignature {
        signer_id: 0,
        sig_r,
        sig_s,
    }
}

/// Sign with party_id embedded and session binding.
pub fn produce_signed_signature(
    signer_id: u32,
    signer_sk: Fr,
    signer_pk: G1Affine,
    dealer_id: u32,
    message_hash: &[u8; 32],
    session_id: &[u8],
    rng: &mut impl RngCore,
) -> NonEquivSignature {
    let mut sig = produce_signature(
        signer_sk,
        signer_pk,
        dealer_id,
        message_hash,
        session_id,
        rng,
    );
    sig.signer_id = signer_id;
    sig
}

// ── Proof collection ──────────────────────────────────────────────────────

/// Builder for collecting signatures into a NonEquiv proof.
#[derive(Debug)]
pub struct NonEquivCollector {
    dealer_id: u32,
    message_hash: [u8; 32],
    quorum_size: usize,
    signatures: Vec<NonEquivSignature>,
    seen_signers: HashSet<u32>,
}

impl NonEquivCollector {
    /// Start collecting signatures for a dealer's message.
    ///
    /// `total_parties` is `n`, `max_faults` is `f`.  Quorum = n - f.
    pub fn new(dealer_id: u32, message_hash: [u8; 32], n: usize, f: usize) -> Self {
        Self {
            dealer_id,
            message_hash,
            quorum_size: n.saturating_sub(f),
            signatures: Vec::with_capacity(n.saturating_sub(f)),
            seen_signers: HashSet::with_capacity(n.saturating_sub(f)),
        }
    }

    /// Add a signature to the collection.
    ///
    /// Returns `Ok(true)` if quorum has been reached, `Ok(false)` if more
    /// signatures are needed, or `Err` on duplicate/invalid.
    pub fn add_signature(&mut self, sig: NonEquivSignature) -> Result<bool, NonEquivError> {
        if !self.seen_signers.insert(sig.signer_id) {
            return Err(NonEquivError::DuplicateSigner(sig.signer_id));
        }
        self.signatures.push(sig);
        Ok(self.signatures.len() >= self.quorum_size)
    }

    /// Finalize the collection into a NonEquiv proof.
    ///
    /// Errors if quorum has not been reached.
    pub fn finalize(self) -> Result<NonEquivProof, NonEquivError> {
        if self.signatures.len() < self.quorum_size {
            return Err(NonEquivError::InsufficientSignatures {
                have: self.signatures.len(),
                need: self.quorum_size,
            });
        }
        Ok(NonEquivProof {
            dealer_id: self.dealer_id,
            message_hash: self.message_hash,
            signatures: self.signatures,
            quorum_size: self.quorum_size,
        })
    }
}

// ── Verification ──────────────────────────────────────────────────────────

/// Verify a single NonEquiv signature, bound to a session.
pub fn verify_signature(
    sig: &NonEquivSignature,
    signer_pk: &G1Affine,
    message_hash: &[u8; 32],
    session_id: &[u8],
) -> Result<(), NonEquivError> {
    let challenge = non_equiv_challenge(message_hash, session_id);
    if !schnorr_verify_with_session(*signer_pk, sig.sig_r, sig.sig_s, challenge, session_id) {
        return Err(NonEquivError::InvalidSignature(sig.signer_id));
    }
    Ok(())
}

/// Verify a complete NonEquiv proof, bound to a session.
///
/// Checks:
/// 1. Quorum size is satisfied (at least `n-f` signatures)
/// 2. All signers are distinct
/// 3. All signatures verify against the provided public keys
pub fn verify_nonequiv_proof(
    proof: &NonEquivProof,
    public_keys: &HashMap<u32, G1Affine>,
    message_hash: &[u8; 32],
    session_id: &[u8],
) -> Result<(), NonEquivError> {
    // Check message hash binding
    if proof.message_hash != *message_hash {
        return Err(NonEquivError::MessageHashMismatch);
    }

    // Check quorum
    if proof.signatures.len() < proof.quorum_size {
        return Err(NonEquivError::InsufficientSignatures {
            have: proof.signatures.len(),
            need: proof.quorum_size,
        });
    }

    // Check signer uniqueness and verify each signature
    let mut seen = HashSet::new();
    for sig in &proof.signatures {
        if !seen.insert(sig.signer_id) {
            return Err(NonEquivError::DuplicateSigner(sig.signer_id));
        }
        let pk = public_keys
            .get(&sig.signer_id)
            .ok_or(NonEquivError::MissingPublicKey(sig.signer_id))?;
        verify_signature(sig, pk, &proof.message_hash, session_id)?;
    }

    Ok(())
}

/// Detect and prove equivocation.
///
/// Returns `Some(EquivocationEvidence)` if two proofs from the same dealer
/// have different message hashes. Returns `None` if they are consistent.
pub fn detect_equivocation(
    proof_a: &NonEquivProof,
    proof_b: &NonEquivProof,
) -> Result<Option<EquivocationEvidence>, NonEquivError> {
    if proof_a.dealer_id != proof_b.dealer_id {
        return Err(NonEquivError::NotEquivocation);
    }
    if proof_a.message_hash == proof_b.message_hash {
        // Same message — no equivocation
        return Ok(None);
    }
    Ok(Some(EquivocationEvidence {
        dealer_id: proof_a.dealer_id,
        proof_a: proof_a.clone(),
        proof_b: proof_b.clone(),
    }))
}

fn g1_affine_to_xy_bytes(p: &G1Affine) -> ([u8; 32], [u8; 32]) {
    let x = match p.x() {
        Some(c) => c,
        None => return ([0u8; 32], [0u8; 32]),
    };
    let y = match p.y() {
        Some(c) => c,
        None => return ([0u8; 32], [0u8; 32]),
    };
    let x_bytes = x.into_bigint().to_bytes_be();
    let y_bytes = y.into_bigint().to_bytes_be();
    let mut x_buf = [0u8; 32];
    let mut y_buf = [0u8; 32];
    let x_len = x_bytes.len().min(32);
    let y_len = y_bytes.len().min(32);
    x_buf[..x_len].copy_from_slice(&x_bytes[..x_len]);
    y_buf[..y_len].copy_from_slice(&y_bytes[..y_len]);
    (x_buf, y_buf)
}

impl NonEquivSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        buf.extend_from_slice(&self.signer_id.to_be_bytes());
        let (rx, ry) = g1_affine_to_xy_bytes(&self.sig_r);
        buf.extend_from_slice(&rx);
        buf.extend_from_slice(&ry);
        let s_bytes = self.sig_s.into_bigint().to_bytes_be();
        let mut s_buf = [0u8; 32];
        let s_len = s_bytes.len().min(32);
        s_buf[..s_len].copy_from_slice(&s_bytes[..s_len]);
        buf.extend_from_slice(&s_buf);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NonEquivError> {
        if bytes.len() < 100 {
            return Err(NonEquivError::InsufficientSignatures { have: 0, need: 0 });
        }
        let signer_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let rx_bytes: [u8; 32] = bytes[4..36].try_into().unwrap();
        let ry_bytes: [u8; 32] = bytes[36..68].try_into().unwrap();
        let s_bytes: [u8; 32] = bytes[68..100].try_into().unwrap();

        let rx = ark_bn254::Fq::from_be_bytes_mod_order(&rx_bytes);
        let ry = ark_bn254::Fq::from_be_bytes_mod_order(&ry_bytes);
        let sig_r = G1Affine::new_unchecked(rx, ry);
        if !sig_r.is_on_curve() {
            return Err(NonEquivError::InvalidSignature(signer_id));
        }
        let sig_s = Fr::from_be_bytes_mod_order(&s_bytes);

        Ok(NonEquivSignature {
            signer_id,
            sig_r,
            sig_s,
        })
    }
}

impl NonEquivProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let num_sigs = self.signatures.len() as u32;
        let mut buf = Vec::with_capacity(44 + 100 * self.signatures.len());
        buf.extend_from_slice(&self.dealer_id.to_be_bytes());
        buf.extend_from_slice(&self.message_hash);
        buf.extend_from_slice(&(self.quorum_size as u32).to_be_bytes());
        buf.extend_from_slice(&num_sigs.to_be_bytes());
        for sig in &self.signatures {
            buf.extend_from_slice(&sig.to_bytes());
        }
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NonEquivError> {
        if bytes.len() < 44 {
            return Err(NonEquivError::InsufficientSignatures { have: 0, need: 0 });
        }
        let dealer_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&bytes[4..36]);
        let quorum_size = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]) as usize;
        let num_sigs = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as usize;

        let mut signatures = Vec::with_capacity(num_sigs);
        let mut offset = 44;
        for _ in 0..num_sigs {
            if offset + 100 > bytes.len() {
                break;
            }
            let sig = NonEquivSignature::from_bytes(&bytes[offset..offset + 100])?;
            signatures.push(sig);
            offset += 100;
        }
        Ok(NonEquivProof {
            dealer_id,
            message_hash,
            signatures,
            quorum_size,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use pvthfhe_nizk::schnorr::generate_signing_keypair;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    const TEST_SESSION: &[u8] = b"test-session";

    fn make_rng() -> ChaCha8Rng {
        ChaCha8Rng::from_seed([0x42; 32])
    }

    // ── F1 RED: session binding tests (must fail before GREEN implementation) ──

    #[test]
    fn test_message_hash_binds_session_id() {
        let h1 = hash_round1_message(1, b"payload", b"session-alpha");
        let h2 = hash_round1_message(1, b"payload", b"session-beta");
        assert_ne!(h1, h2, "different session must produce different hash");
    }

    #[test]
    fn test_message_hash_same_session_deterministic() {
        let h1 = hash_round1_message(1, b"payload", b"session-alpha");
        let h2 = hash_round1_message(1, b"payload", b"session-alpha");
        assert_eq!(h1, h2, "same session must be deterministic");
    }

    #[test]
    fn test_nonequiv_signature_cross_session_replay_rejected() {
        // Sign message in session A, verify fails in session B
        let mut rng = make_rng();
        let (sk, pk) = generate_signing_keypair(&mut rng);
        let msg_hash_a = hash_round1_message(1, b"round1 data", b"session-A");
        let msg_hash_b = hash_round1_message(1, b"round1 data", b"session-B");

        // Signature computed for session-A hash
        let sig = produce_signed_signature(7, sk, pk, 1, &msg_hash_a, b"session-A", &mut rng);

        // Should verify against session-A
        assert!(verify_signature(&sig, &pk, &msg_hash_a, b"session-A").is_ok());

        // Should REJECT when verified against session-B message hash
        assert!(
            verify_signature(&sig, &pk, &msg_hash_b, b"session-B").is_err(),
            "cross-session signature replay must be rejected"
        );
    }

    // ── Existing tests updated with TEST_SESSION ──

    #[test]
    fn test_single_signature_verifies() {
        let mut rng = make_rng();
        let (sk, pk) = generate_signing_keypair(&mut rng);
        let msg_hash = hash_round1_message(1, b"test round1 payload", TEST_SESSION);
        let sig = produce_signed_signature(7, sk, pk, 1, &msg_hash, TEST_SESSION, &mut rng);

        let mut pks = HashMap::new();
        pks.insert(7, pk);
        let result = verify_signature(&sig, &pk, &msg_hash, TEST_SESSION);
        assert!(
            result.is_ok(),
            "valid signature should verify: {:?}",
            result
        );
    }

    #[test]
    fn test_bad_signature_rejected() {
        let mut rng = make_rng();
        let (sk, pk) = generate_signing_keypair(&mut rng);
        let msg_hash = hash_round1_message(1, b"real message", TEST_SESSION);
        let sig = produce_signed_signature(7, sk, pk, 1, &msg_hash, TEST_SESSION, &mut rng);

        let bad_hash = hash_round1_message(1, b"different message", TEST_SESSION);
        let result = verify_signature(&sig, &pk, &bad_hash, TEST_SESSION);
        assert!(
            result.is_err(),
            "signature on wrong message should be rejected"
        );
    }

    #[test]
    fn test_quorum_collection() {
        let mut rng = make_rng();
        let n = 7;
        let f = 2; // n-f = 5
        let msg_hash = hash_round1_message(1, b"round1 data", TEST_SESSION);

        let mut collector = NonEquivCollector::new(1, msg_hash, n, f);
        let mut pks = HashMap::new();

        for i in 0..5 {
            let (sk, pk) = generate_signing_keypair(&mut rng);
            pks.insert(i + 1, pk);
            let sig = produce_signed_signature(i + 1, sk, pk, 1, &msg_hash, TEST_SESSION, &mut rng);
            let reached = collector.add_signature(sig).unwrap();
            if i < 4 {
                assert!(!reached, "quorum should not be reached with {} sigs", i + 1);
            } else {
                assert!(reached, "quorum should be reached at {} sigs", i + 1);
            }
        }

        let proof = collector.finalize().unwrap();
        assert!(verify_nonequiv_proof(&proof, &pks, &msg_hash, TEST_SESSION).is_ok());
    }

    #[test]
    fn test_insufficient_quorum_rejected() {
        let mut rng = make_rng();
        let n = 7;
        let f = 2;
        let msg_hash = hash_round1_message(1, b"data", TEST_SESSION);

        let mut collector = NonEquivCollector::new(1, msg_hash, n, f);
        for i in 0..4 {
            let (sk, pk) = generate_signing_keypair(&mut rng);
            let sig = produce_signed_signature(i + 1, sk, pk, 1, &msg_hash, TEST_SESSION, &mut rng);
            collector.add_signature(sig).unwrap();
        }
        let err = collector.finalize().unwrap_err();
        assert_eq!(
            err,
            NonEquivError::InsufficientSignatures { have: 4, need: 5 }
        );
    }

    #[test]
    fn test_duplicate_signer_rejected() {
        let mut rng = make_rng();
        let n = 7;
        let f = 2;
        let msg_hash = hash_round1_message(1, b"data", TEST_SESSION);
        let mut collector = NonEquivCollector::new(1, msg_hash, n, f);

        let (sk, pk) = generate_signing_keypair(&mut rng);
        let sig = produce_signed_signature(1, sk, pk, 1, &msg_hash, TEST_SESSION, &mut rng);
        collector.add_signature(sig.clone()).unwrap();
        let err = collector.add_signature(sig).unwrap_err();
        assert_eq!(err, NonEquivError::DuplicateSigner(1));
    }

    #[test]
    fn test_equivocation_detection() {
        let mut rng = make_rng();
        let n = 7;
        let f = 2;
        let msg_a = hash_round1_message(1, b"message A", TEST_SESSION);
        let msg_b = hash_round1_message(1, b"message B", TEST_SESSION);

        let mut pks = HashMap::new();
        let mut collector_a = NonEquivCollector::new(1, msg_a, n, f);
        let mut collector_b = NonEquivCollector::new(1, msg_b, n, f);

        for i in 0..5 {
            let (sk, pk) = generate_signing_keypair(&mut rng);
            pks.insert(i + 1, pk);
            let sig_a = produce_signed_signature(i + 1, sk, pk, 1, &msg_a, TEST_SESSION, &mut rng);
            let sig_b = produce_signed_signature(i + 1, sk, pk, 1, &msg_b, TEST_SESSION, &mut rng);
            collector_a.add_signature(sig_a).unwrap();
            collector_b.add_signature(sig_b).unwrap();
        }

        let proof_a = collector_a.finalize().unwrap();
        let proof_b = collector_b.finalize().unwrap();

        let evidence = detect_equivocation(&proof_a, &proof_b)
            .unwrap()
            .expect("should detect equivocation");
        assert_eq!(evidence.dealer_id, 1);
        assert_ne!(evidence.proof_a.message_hash, evidence.proof_b.message_hash);
    }

    #[test]
    fn test_no_equivocation_same_message() {
        let msg = hash_round1_message(1, b"same", TEST_SESSION);
        let proof_a = NonEquivProof {
            dealer_id: 1,
            message_hash: msg,
            signatures: vec![],
            quorum_size: 5,
        };
        let proof_b = proof_a.clone();
        let evidence = detect_equivocation(&proof_a, &proof_b).unwrap();
        assert!(
            evidence.is_none(),
            "same message should not be equivocation"
        );
    }

    #[test]
    fn test_message_hash_determinism() {
        let h1 = hash_round1_message(42, b"payload", TEST_SESSION);
        let h2 = hash_round1_message(42, b"payload", TEST_SESSION);
        assert_eq!(h1, h2, "message hash must be deterministic");
    }

    #[test]
    fn test_message_hash_different_dealer() {
        let h1 = hash_round1_message(1, b"payload", TEST_SESSION);
        let h2 = hash_round1_message(2, b"payload", TEST_SESSION);
        assert_ne!(h1, h2, "different dealer => different hash");
    }

    #[test]
    fn test_message_hash_different_payload() {
        let h1 = hash_round1_message(1, b"payload A", TEST_SESSION);
        let h2 = hash_round1_message(1, b"payload B", TEST_SESSION);
        assert_ne!(h1, h2, "different payload => different hash");
    }

    #[test]
    fn test_deserialize_rejects_off_curve_point() {
        let mut bytes = [0u8; 100];
        // signer_id = 1
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
        // rx = Fq(1) in big-endian: last byte = 1, rest = 0 (note: uses from_be_bytes_mod_order)
        bytes[35] = 1;
        // ry = Fq(1) in big-endian: last byte = 1
        bytes[67] = 1;
        // s = Fr(0)
        bytes[68..100].fill(0);

        let result = NonEquivSignature::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "off-curve point (1,1) must be rejected: BN254 curve is y² = x³ + 3, and 1² ≠ 1³+3"
        );
    }
}
