//! DKG ceremony simulator.
//!
//! Split by ceremony responsibility:
//! - [`round1`]: Round 1 message generation (dealing, fault injection, H2
//!   commit-reveal binding) and per-recipient share encryption.
//! - [`nonequiv`]: NonEquiv sub-round — every signer signs each dealer's
//!   first-seen Round 1 message; a quorum binds the dealer to that message.
//! - [`blame`]: aggregator verification checks for Rounds 1 and 2 (blame
//!   detection, ciphertext memory-clearing threshold).
//! - [`round2`]: Round 2 complaint generation.
//! - [`round3`]: Round 3 key aggregation, C5 formation proof, and transcript
//!   assembly.
//! - [`nizk`]: keygen/encrypted-share NIZK proving and witness derivation.

mod blame;
mod nizk;
mod nonequiv;
mod round1;
mod round2;
mod round3;

use super::types::{DkgTranscript, PartyId};
use ark_bn254::{Fr, G1Affine};
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_fhe::{FheBackend, PublicKey};
use pvthfhe_nizk::schnorr::generate_signing_keypair;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultType {
    MalformedProof,
    WithholdShare,
    Equivocate,
}

#[derive(Debug)]
pub enum KeygenResult {
    Complete(DkgTranscript),
    Blamed(Vec<PartyId>),
}

/// Error returned when [`KeygenSimulator::new`] receives invalid parameters.
#[derive(Debug)]
pub enum KeygenError {
    /// Threshold t must satisfy 1 ≤ t ≤ ⌊n/2⌋+1.
    InvalidThreshold { n: usize, t: usize },
}

impl fmt::Display for KeygenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { n, t } => {
                write!(
                    f,
                    "invalid threshold: n={n}, t={t} (must satisfy 1 ≤ t ≤ ⌊n/2⌋+1 for the honest-majority threshold policy)"
                )
            }
        }
    }
}

impl std::error::Error for KeygenError {}

pub struct KeygenSimulator {
    n_parties: usize,
    threshold: usize,
    backend: Arc<dyn FheBackend>,
    faults: HashMap<PartyId, FaultType>,
}

fn party_id_from_index(index: usize) -> PartyId {
    // KNOWN_LIMITATION(c5_usize_conv): usize→u32 fallback; party count is validated at construction.
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}

fn hash_bytes(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(Tag::ProtocolPrefix.as_bytes());
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

/// H2: Round1 commit-reveal binding for a party public key hash.
pub fn compute_round1_commitment(
    party_id: PartyId,
    session_id: &[u8; 32],
    pk_i_hash: &[u8; 32],
    commitment_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(Tag::DkgCommitRevealV2.as_bytes());
    h.update(&party_id.to_be_bytes());
    h.update(session_id);
    h.update(pk_i_hash);
    h.update(commitment_nonce);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round1_commitment_opens_only_with_bound_pk_hash_and_nonce() {
        let party_id = 7;
        let session_id = [0x11; 32];
        let pk_i_hash = [0x22; 32];
        let commitment_nonce = [0x33; 32];

        let commitment =
            compute_round1_commitment(party_id, &session_id, &pk_i_hash, &commitment_nonce);

        let mut different_pk_hash = pk_i_hash;
        different_pk_hash[0] ^= 0xff;
        let mut different_nonce = commitment_nonce;
        different_nonce[0] ^= 0xff;

        assert_eq!(
            commitment,
            compute_round1_commitment(party_id, &session_id, &pk_i_hash, &commitment_nonce)
        );
        assert_ne!(
            commitment,
            compute_round1_commitment(party_id, &session_id, &different_pk_hash, &commitment_nonce,)
        );
        assert_ne!(
            commitment,
            compute_round1_commitment(party_id, &session_id, &pk_i_hash, &different_nonce)
        );
    }

    /// P0-3: H2 commit-reveal verification — wrong commitment must be detectable.
    /// The aggregator MUST verify SHA256("pvthfhe-dkg-commit-reveal/v2" || party_id ||
    /// session_id || pk_i_hash || nonce) during Round 1 validation.
    #[test]
    fn test_wrong_round1_commitment_is_detectable() {
        let party_id = 7u32;
        let session_id = [0x11u8; 32];
        let pk_i_hash = [0x22u8; 32];
        let commitment_nonce = [0x33u8; 32];

        let commitment =
            compute_round1_commitment(party_id, &session_id, &pk_i_hash, &commitment_nonce);
        let wrong = [0xDEu8; 32];

        assert_ne!(
            commitment, wrong,
            "wrong commitment must differ from correct one"
        );

        // Changing pk_i_hash (rogue key attack) must change the commitment.
        let mut different_pk = pk_i_hash;
        different_pk[0] ^= 0xff;
        assert_ne!(
            commitment,
            compute_round1_commitment(party_id, &session_id, &different_pk, &commitment_nonce),
            "rogue pk must produce different commitment"
        );
    }
}

impl KeygenSimulator {
    pub fn new<B: FheBackend + 'static>(
        n_parties: usize,
        threshold: usize,
        backend: B,
    ) -> Result<Self, KeygenError> {
        if n_parties == 0 {
            return Err(KeygenError::InvalidThreshold {
                n: n_parties,
                t: threshold,
            });
        }
        if threshold == 0 || threshold > n_parties {
            return Err(KeygenError::InvalidThreshold {
                n: n_parties,
                t: threshold,
            });
        }
        // Honest-majority reconstruction threshold per threat-model-v1.md §2.2
        // (t = floor(n/2)+1). Prior (n-1)/2 bound (commit 80a0c82)
        // contradicted the documented model; this is spec conformance, not a relaxation.
        let max_t = n_parties / 2 + 1;
        if threshold > max_t {
            return Err(KeygenError::InvalidThreshold {
                n: n_parties,
                t: threshold,
            });
        }
        Self::assert_mock_acknowledged_if_needed(&backend);
        Ok(Self {
            n_parties,
            threshold,
            backend: Arc::new(backend),
            faults: HashMap::new(),
        })
    }

    pub fn new_with_backend<B: FheBackend + 'static>(
        n_parties: usize,
        threshold: usize,
        backend: B,
    ) -> Result<Self, KeygenError> {
        Self::new(n_parties, threshold, backend)
    }

    fn assert_mock_acknowledged_if_needed(backend: &dyn FheBackend) {
        if !backend.requires_mock_acknowledgement() {
            return;
        }

        if std::env::var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK").as_deref() != Ok("1") {
            panic!(
                "PVTHFHE: mock backend requires PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 \
                 to be set in the environment."
            );
        }
    }

    fn session_id(&self) -> [u8; 32] {
        let participant_set_hash = self.participant_set_hash();
        let mut data = Vec::with_capacity(72);
        data.extend_from_slice(Tag::KeygenSimulatorSession.as_bytes());
        data.extend_from_slice(&participant_set_hash);
        data.extend_from_slice(&self.threshold.to_be_bytes());
        hash_bytes(b"session-id/v1", &data)
    }

    fn participant_set_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.n_parties * std::mem::size_of::<PartyId>());
        for index in 0..self.n_parties {
            data.extend_from_slice(&party_id_from_index(index).to_be_bytes());
        }
        hash_bytes(b"participant-set/v1", &data)
    }

    /// Deterministic keygen for the simulator: derives a seeded RNG from
    /// `(session_id, party_id)` so all parties can compute each other's
    /// public keys consistently.  This is correct in the simulator because
    /// all parties are controlled by a single honest node; a real deployment
    /// would use independently-generated random keys per party.
    fn keygen_share_with_session(
        &self,
        session_id: &[u8; 32],
        party_id: PartyId,
    ) -> Result<pvthfhe_fhe::KeygenShare, pvthfhe_fhe::FheError> {
        let mut hasher = Sha256::new();
        hasher.update(Tag::SimKeygen.as_bytes());
        hasher.update(session_id);
        hasher.update(&party_id.to_be_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator
        if self.backend.supports_session_scoped_keygen() {
            self.backend
                .keygen_share_with_session(session_id, party_id, &mut rng)
        } else {
            self.backend.keygen_share(party_id, &mut rng)
        }
    }

    pub fn inject_fault(&mut self, party_id: PartyId, fault: FaultType) {
        self.faults.insert(party_id, fault);
    }

    pub fn run(&mut self) -> Result<KeygenResult, pvthfhe_fhe::FheError> {
        self.run_with_timeout(None)
    }

    /// Run DKG with per-round timeout enforcement.
    ///
    /// If `round_timeout` is `Some(d)`, each protocol round (Round 1, NonEquiv,
    /// Round 2, Round 3) must complete within `d`. If a round exceeds the
    /// timeout, the method returns with a descriptive error identifying the
    /// round and parties that have not yet responded.
    ///
    /// If `round_timeout` is `None`, the method behaves identically to `run()`.
    pub fn run_with_timeout(
        &mut self,
        round_timeout: Option<Duration>,
    ) -> Result<KeygenResult, pvthfhe_fhe::FheError> {
        let session_id = self.session_id();
        let round_start = Instant::now();

        // Pre-compute all party public keys (also initialises backend party states).
        let mut all_pks: HashMap<PartyId, PublicKey> = HashMap::new();
        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            let share = self.keygen_share_with_session(&session_id, party_id)?;
            let pk = self.backend.aggregate_keygen(&[share.clone()])?;
            all_pks.insert(party_id, pk);
        }

        // Generate Schnorr signing keypairs for NonEquiv protocol (simulator controls all parties).
        let mut schnorr_sks: HashMap<PartyId, Fr> = HashMap::new();
        let mut schnorr_pks: HashMap<PartyId, G1Affine> = HashMap::new();
        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            let mut seed = [0u8; 32];
            {
                let mut h = Sha256::new();
                h.update(Tag::SimSchnorr.as_bytes());
                h.update(&session_id);
                h.update(&party_id.to_be_bytes());
                seed.copy_from_slice(&h.finalize());
            }
            let mut rng = ChaCha8Rng::from_seed(seed);
            let (sk, pk) = generate_signing_keypair(&mut rng);
            schnorr_sks.insert(party_id, sk);
            schnorr_pks.insert(party_id, pk);
        }

        let mut blames = Vec::new();

        // ROUND 1
        let (r1_msgs, mut equivocated) = self.generate_round1_messages(&session_id, &all_pks)?;

        // NON-EQUIV SUB-ROUND: each signer signs every dealer's Round 1 message.
        // We keep the first message seen for each dealer as the transcript-bound
        // target and collect a quorum of signatures for that message.
        let (canonical_r1_msgs, non_equiv_proofs) = self.run_non_equiv_subround(
            r1_msgs,
            &schnorr_sks,
            &schnorr_pks,
            &session_id,
            &mut equivocated,
        )?;

        // AGGREGATOR CHECK ROUND 1 — uses canonical_r1_msgs (r1_msgs dropped above).
        let valid_r1 =
            self.aggregator_check_round1(canonical_r1_msgs, &equivocated, &session_id, &mut blames);

        // Round 1 timeout check
        if let Some(timeout) = round_timeout {
            if round_start.elapsed() > timeout {
                let pending: Vec<PartyId> = (0..self.n_parties)
                    .map(party_id_from_index)
                    .filter(|id| {
                        !valid_r1.iter().any(|m| m.party_id == *id) && !blames.contains(id)
                    })
                    .collect();
                return Err(pvthfhe_fhe::FheError::Backend {
                    reason: format!(
                        "round 1 timed out after {:?}: {} pending parties",
                        round_start.elapsed(),
                        pending.len()
                    ),
                });
            }
        }

        if !blames.is_empty() {
            blames.sort();
            return Ok(KeygenResult::Blamed(blames));
        }

        // ROUND 2
        let round_start = Instant::now();
        let r2_msgs = self.generate_round2_messages(&valid_r1, &blames);

        // AGGREGATOR CHECK ROUND 2
        Self::aggregator_check_round2(&r2_msgs, &mut blames);

        // Round 2 timeout check
        if let Some(timeout) = round_timeout {
            if round_start.elapsed() > timeout {
                let pending: Vec<PartyId> = (0..self.n_parties)
                    .map(party_id_from_index)
                    .filter(|id| !r2_msgs.iter().any(|m| m.party_id == *id) && !blames.contains(id))
                    .collect();
                return Err(pvthfhe_fhe::FheError::Backend {
                    reason: format!(
                        "round 2 timed out after {:?}: {} pending parties",
                        round_start.elapsed(),
                        pending.len()
                    ),
                });
            }
        }

        if !blames.is_empty() {
            blames.sort();
            return Ok(KeygenResult::Blamed(blames));
        }

        // ROUND 3
        self.finalize_round3(
            valid_r1,
            r2_msgs,
            &all_pks,
            &session_id,
            non_equiv_proofs,
            blames,
            round_timeout,
        )
    }
}
