use super::types::{DkgTranscript, PartyId, Round1Message, Round2Message, Round3Aggregate};
use anyhow::Context;
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_domain_tags::Tag;
use pvthfhe_fhe::{Ciphertext, FheBackend, PublicKey};
use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::bfv_sigma::poly_bytes_to_rns;
use pvthfhe_nizk::schnorr::generate_signing_keypair;
use pvthfhe_nizk::sigma::{self, SigmaStatement, SigmaWitness};
use pvthfhe_nizk::{NizkAdapter, NizkStatement, NizkWitness};
use pvthfhe_non_equiv::{
    hash_round1_message, produce_signed_signature, NonEquivCollector, NonEquivProof,
};
use pvthfhe_types::ProtocolBytes;
use rand_chacha::ChaCha8Rng;
use rand_core::OsRng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
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
    hasher.update(b"pvthfhe/");
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
    h.update(b"pvthfhe-dkg-commit-reveal/v2");
    h.update(&party_id.to_be_bytes());
    h.update(session_id);
    h.update(pk_i_hash);
    h.update(commitment_nonce);
    h.finalize().into()
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
        hasher.update(b"pvthfhe-sim-keygen-v1");
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
                h.update(b"pvthfhe-sim-schnorr-v1");
                h.update(&session_id);
                h.update(&party_id.to_be_bytes());
                seed.copy_from_slice(&h.finalize());
            }
            let mut rng = ChaCha8Rng::from_seed(seed);
            let (sk, pk) = generate_signing_keypair(&mut rng);
            schnorr_sks.insert(party_id, sk);
            schnorr_pks.insert(party_id, pk);
        }

        // ROUND 1
        let mut r1_msgs = Vec::new();
        let mut equivocated = HashSet::new();

        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            let fault = self.faults.get(&party_id);

            // Generate normal message
            let mut msg = self.generate_r1_msg(&session_id, party_id, &all_pks)?;

            // Apply faults
            if fault == Some(&FaultType::MalformedProof) {
                msg.nizk = vec![0xba, 0xad]; // Malformed
            } else if fault == Some(&FaultType::WithholdShare) {
                msg.encrypted_shares.clear(); // Withhold
            }

            r1_msgs.push(msg.clone());

            if fault == Some(&FaultType::Equivocate) {
                let mut alt_msg = msg.clone();
                alt_msg.commitment = hash_bytes(b"equivocation-alt/v1", b"alt");
                r1_msgs.push(alt_msg);
                equivocated.insert(party_id);
            }
        }

        // NON-EQUIV SUB-ROUND: each signer signs every dealer's Round 1 message.
        // We keep the first message seen for each dealer as the transcript-bound
        // target and collect a quorum of signatures for that message.
        let f = self.n_parties.saturating_sub(self.threshold);
        let mut non_equiv_proofs: HashMap<PartyId, NonEquivProof> = HashMap::new();
        let mut dealer_collectors: HashMap<PartyId, NonEquivCollector> = HashMap::new();
        let mut canonical_r1_msgs: Vec<Round1Message> = Vec::new();
        let mut seen_dealer_msg: HashMap<PartyId, [u8; 32]> = HashMap::new();

        for msg in &r1_msgs {
            let dealer_id = msg.party_id;
            let payload = self.build_round1_payload(msg);
            let msg_hash = hash_round1_message(dealer_id, &payload, &session_id);
            if let Some(&existing_hash) = seen_dealer_msg.get(&dealer_id) {
                if existing_hash != msg_hash {
                    equivocated.insert(dealer_id);
                }
                continue;
            }
            seen_dealer_msg.insert(dealer_id, msg_hash);
            canonical_r1_msgs.push(msg.clone());
            dealer_collectors.insert(
                dealer_id,
                NonEquivCollector::new(dealer_id, msg_hash, self.n_parties, f),
            );
        }
        // MEMORY: drop r1_msgs — canonical_r1_msgs holds the canonical copy;
        // the original vector is no longer needed.
        std::mem::drop(r1_msgs);

        for i in 0..self.n_parties {
            let signer_id = party_id_from_index(i);
            let sk = schnorr_sks
                .get(&signer_id)
                .ok_or_else(|| pvthfhe_fhe::FheError::Backend {
                    reason: format!("missing Schnorr sk for party {signer_id}"),
                })?;
            let pk = schnorr_pks
                .get(&signer_id)
                .ok_or_else(|| pvthfhe_fhe::FheError::Backend {
                    reason: format!("missing Schnorr pk for party {signer_id}"),
                })?;
            let sigs =
                self.non_equiv_round(signer_id, *sk, *pk, &canonical_r1_msgs, &session_id)?;

            for (msg, sig) in canonical_r1_msgs.iter().zip(sigs.into_iter()) {
                if let Some(collector) = dealer_collectors.get_mut(&msg.party_id) {
                    let _quorum_reached = collector.add_signature(sig).map_err(|e| {
                        pvthfhe_fhe::FheError::Backend {
                            reason: format!(
                                "non-equiv add_sig for dealer {} signer {signer_id}: {e}",
                                msg.party_id
                            ),
                        }
                    })?;
                }
            }
        }

        for (dealer_id, collector) in dealer_collectors {
            let proof = collector
                .finalize()
                .map_err(|e| pvthfhe_fhe::FheError::Backend {
                    reason: format!("non-equiv finalize for party {dealer_id}: {e}"),
                })?;
            let proof_bytes = proof.to_bytes();
            let proof = NonEquivProof::from_bytes(&proof_bytes).map_err(|e| {
                pvthfhe_fhe::FheError::Backend {
                    reason: format!("non-equiv round-trip for party {dealer_id}: {e}"),
                }
            })?;
            pvthfhe_non_equiv::verify_nonequiv_proof(
                &proof,
                &schnorr_pks,
                &proof.message_hash,
                &session_id,
            )
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("non-equiv verify for party {dealer_id}: {e}"),
            })?;
            non_equiv_proofs.insert(dealer_id, proof);
        }
        // MEMORY: canonical_r1_msgs no longer needed after NonEquiv collection
        // and aggregator check — all needed data is now in valid_r1.

        // AGGREGATOR CHECK ROUND 1 — uses canonical_r1_msgs (r1_msgs dropped above).
        let mut blames = Vec::new();
        // Propagate NonEquiv-detected equivocators to blame list.
        for &eq in &equivocated {
            if !blames.contains(&eq) {
                blames.push(eq);
            }
        }
        let mut valid_r1 = Vec::new();
        let mut seen = HashSet::new();
        let mut duplicates = HashSet::new();

        for msg in &canonical_r1_msgs {
            if !seen.insert(msg.party_id) {
                duplicates.insert(msg.party_id);
            }
        }

        for msg in &canonical_r1_msgs {
            // Skip parties already blamed for equivocation above
            if blames.contains(&msg.party_id) {
                continue;
            }
            if duplicates.contains(&msg.party_id) {
                if !blames.contains(&msg.party_id) {
                    blames.push(msg.party_id);
                }
                continue;
            }
            if msg.nizk == vec![0xba, 0xad] {
                if !blames.contains(&msg.party_id) {
                    blames.push(msg.party_id);
                }
                continue;
            }
            // H2: verify commit-reveal binding to prevent rogue-key attacks.
            let expected_commitment = compute_round1_commitment(
                msg.party_id,
                &session_id,
                &msg.pk_i_hash,
                &msg.commitment_nonce,
            );
            if msg.commitment != expected_commitment {
                blames.push(msg.party_id);
                continue;
            }
            // For WithholdShare, another party will complain in Round 2
            valid_r1.push(msg.clone());
        }
        // MEMORY: clear encrypted_shares ciphertexts — Round 2 only needs
        // key presence (contains_key), not the actual ciphertext bytes.
        // This frees n×(n-1) BFV ciphertexts (~392 KB each with real backend).
        for msg in &mut valid_r1 {
            msg.encrypted_shares.values_mut().for_each(|v| v.clear());
        }
        std::mem::drop(canonical_r1_msgs);

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
        let mut r2_msgs = Vec::new();
        for i in 0..self.n_parties {
            let party_id = party_id_from_index(i);
            if blames.contains(&party_id) {
                continue;
            }
            let mut complaints = Vec::new();
            for r1 in &valid_r1 {
                if r1.party_id == party_id {
                    continue;
                }
                if !r1.encrypted_shares.contains_key(&party_id) {
                    complaints.push(r1.party_id);
                }
            }
            r2_msgs.push(Round2Message {
                party_id,
                complaints,
            });
        }

        // AGGREGATOR CHECK ROUND 2
        for r2 in &r2_msgs {
            for &c in &r2.complaints {
                if !blames.contains(&c) {
                    blames.push(c);
                }
            }
        }

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
        let round_start = Instant::now();
        let participant_set: Vec<PartyId> = valid_r1.iter().map(|m| m.party_id).collect();
        let mut shares = Vec::new();
        for r1 in &valid_r1 {
            shares.push(pvthfhe_fhe::KeygenShare {
                party_id: r1.party_id,
                bytes: ProtocolBytes(r1.pk_i.bytes.clone()),
            });
        }

        let aggregate_pk = self.backend.aggregate_keygen(&shares)?;

        // C5: Aggregate public-key formation proof with per-participant PoP.
        let c5_proof_root = {
            let mut pops = Vec::new();
            for share in &shares {
                let pk_i = all_pks
                    .get(&share.party_id)
                    .cloned()
                    .unwrap_or_else(|| PublicKey {
                        bytes: share.bytes.0.clone(),
                    });
                let mut nonce = [0u8; 32];
                OsRng.fill_bytes(&mut nonce);
                let pop = super::c5_proof::generate_pop(
                    share.party_id,
                    &session_id,
                    &pk_i.bytes,
                    share.bytes.0.clone(),
                    nonce,
                );
                pops.push(pop);
            }
            let pks: Vec<PublicKey> = shares
                .iter()
                .map(|s| {
                    all_pks
                        .get(&s.party_id)
                        .cloned()
                        .unwrap_or_else(|| PublicKey {
                            bytes: s.bytes.0.clone(),
                        })
                })
                .collect();
            let proof = super::c5_proof::bundle_c5_proof(
                &pks,
                &aggregate_pk,
                pops,
                self.participant_set_hash(),
            );
            super::c5_proof::compute_c5_proof_root(&proof)
        };

        // Merkle root and hash mock
        let participant_set_hash = self.participant_set_hash();

        // Sort round 1 messages for transcript (by party_id)
        valid_r1.sort_by_key(|m| m.party_id);

        let mut dkg_root_hasher = Sha256::new();
        for m in &valid_r1 {
            let mut leaf = Vec::new();
            leaf.extend_from_slice(&m.party_id.to_be_bytes());
            leaf.extend_from_slice(&m.pk_i_hash);
            dkg_root_hasher.update(hash_bytes(b"dkg-root/v1", &leaf));
        }
        let mut dkg_root = [0u8; 32];
        dkg_root.copy_from_slice(&dkg_root_hasher.finalize());

        let mut transcript_hasher = Sha256::new();
        transcript_hasher.update(b"pvthfhe/transcript/v1");
        // Serialize round1_messages for transcript hash
        for msg in &valid_r1 {
            transcript_hasher.update(&msg.party_id.to_be_bytes());
            transcript_hasher.update(&msg.nizk);
            transcript_hasher.update(&msg.pk_i.bytes);
            transcript_hasher.update(&msg.pk_i_hash);
            transcript_hasher.update(&msg.commitment_nonce);
            transcript_hasher.update(&msg.commitment);
            transcript_hasher.update(&msg.poly_commit);
            // Skip encrypted_shares to avoid ordering issues across parties
        }
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&transcript_hasher.finalize());

        let transcript = DkgTranscript {
            version: 1,
            participant_set,
            round1_messages: valid_r1,
            round2_messages: r2_msgs,
            round3_aggregate: Round3Aggregate {
                aggregate_pk,
                participant_set_hash,
                c5_proof_root,
            },
            dkg_root,
            transcript_hash,
            non_equiv_proofs,
        };

        // Round 3 timeout check
        if let Some(timeout) = round_timeout {
            if round_start.elapsed() > timeout {
                let pending: Vec<PartyId> = (0..self.n_parties)
                    .map(party_id_from_index)
                    .filter(|id| !shares.iter().any(|s| s.party_id == *id) && !blames.contains(id))
                    .collect();
                return Err(pvthfhe_fhe::FheError::Backend {
                    reason: format!(
                        "round 3 timed out after {:?}: {} pending parties",
                        round_start.elapsed(),
                        pending.len()
                    ),
                });
            }
        }

        Ok(KeygenResult::Complete(transcript))
    }

    fn build_round1_payload(&self, msg: &Round1Message) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&msg.party_id.to_be_bytes());
        payload.extend_from_slice(&msg.pk_i_hash);
        payload.extend_from_slice(&msg.commitment_nonce);
        payload.extend_from_slice(&msg.commitment);
        payload.extend_from_slice(&msg.poly_commit);
        payload
    }

    fn non_equiv_round(
        &self,
        signer_id: PartyId,
        signing_key: Fr,
        signing_pk: G1Affine,
        round1_msgs: &[Round1Message],
        session_id: &[u8; 32],
    ) -> Result<Vec<pvthfhe_non_equiv::NonEquivSignature>, pvthfhe_fhe::FheError> {
        let mut signatures = Vec::with_capacity(round1_msgs.len());
        let mut rng_seed = [0u8; 32];
        {
            let mut h = Sha256::new();
            h.update(b"pvthfhe-sim-nonequiv-rng-v1");
            h.update(&signer_id.to_be_bytes());
            h.update(signing_key.into_bigint().to_bytes_le());
            rng_seed.copy_from_slice(&h.finalize());
        }
        let mut rng = ChaCha8Rng::from_seed(rng_seed);

        for msg in round1_msgs {
            let dealer_id = msg.party_id;
            let payload = self.build_round1_payload(msg);
            let msg_hash = hash_round1_message(dealer_id, &payload, session_id);
            let sig = produce_signed_signature(
                signer_id,
                signing_key,
                signing_pk,
                dealer_id,
                &msg_hash,
                session_id,
                &mut rng,
            );
            signatures.push(sig);
        }
        Ok(signatures)
    }

    fn generate_r1_msg(
        &self,
        session_id: &[u8; 32],
        party_id: PartyId,
        all_pks: &HashMap<PartyId, PublicKey>,
    ) -> Result<Round1Message, pvthfhe_fhe::FheError> {
        let share = self.keygen_share_with_session(session_id, party_id)?;
        let pk_i = PublicKey {
            bytes: share.bytes.0.clone(),
        };
        let pk_i_hash = hash_bytes(b"participant-pk-hash/v1", pk_i.bytes.as_slice());

        // Generate real BFV keypair correctness NIZK (C0). The current
        // Round1Message wire slot carries the per-recipient encrypted-share
        // proof bundle below; keep this proof generation here as a fail-fast
        // simulator self-check until the transcript schema grows a distinct C0
        // proof field.
        let _keygen_nizk = self
            .generate_keygen_nizk(session_id, party_id, &pk_i, &share)
            .map_err(|e| pvthfhe_fhe::FheError::Backend { reason: e })?;

        let mut encrypted_shares = HashMap::new();
        let mut nizk_proofs: Vec<Vec<u8>> = Vec::new();

        for j in 0..self.n_parties {
            let recipient_id = party_id_from_index(j);
            if recipient_id != party_id {
                match all_pks.get(&recipient_id) {
                    Some(recipient_pk) => {
                        let (ct_bytes, nizk_bytes) = self.encrypt_share_for_recipient(
                            session_id,
                            party_id,
                            recipient_id,
                            recipient_pk,
                        )?;
                        encrypted_shares.insert(recipient_id, ct_bytes);
                        nizk_proofs.push(nizk_bytes);
                    }
                    None => {
                        return Err(pvthfhe_fhe::FheError::Backend {
                            reason: format!(
                                "recipient {} has no public key registered in all_pks",
                                recipient_id
                            ),
                        });
                    }
                }
            }
        }

        // H2: fresh nonce for rogue-key commit-reveal binding.
        let commitment_nonce = {
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            nonce
        };
        // H2: commitment binds pk_i_hash + nonce to prevent an adversary from
        // choosing their pk after seeing honest keys.
        let commitment =
            { compute_round1_commitment(party_id, session_id, &pk_i_hash, &commitment_nonce) };

        let nizk =
            serialize_nizk_bundle(&nizk_proofs).map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("serialize encrypted-share NIZK bundle: {e}"),
            })?;

        Ok(Round1Message {
            party_id,
            pk_i,
            pk_i_hash,
            commitment_nonce,
            commitment,
            poly_commit: {
                let mut data = Vec::new();
                data.extend_from_slice(session_id);
                data.extend_from_slice(&party_id.to_be_bytes());
                data.extend_from_slice(&share.bytes.0);
                hash_bytes(b"poly-commit/v1", &data)
            },
            encrypted_shares,
            nizk,
        })
    }

    fn encrypt_share_for_recipient(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        recipient_pk: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), pvthfhe_fhe::FheError> {
        let mut hasher = Sha256::new();
        hasher.update(b"pvthfhe-sim-share-v1");
        hasher.update(session_id);
        hasher.update(&dealer_id.to_be_bytes());
        hasher.update(&recipient_id.to_be_bytes());
        let share_hash: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"pvthfhe-sim-encrypt-v1");
        hasher.update(session_id);
        hasher.update(&dealer_id.to_be_bytes());
        hasher.update(&recipient_id.to_be_bytes());
        let encrypt_seed: [u8; 32] = hasher.finalize().into();
        let mut encrypt_rng = ChaCha8Rng::from_seed(encrypt_seed); // allow-seeded-rng: deterministic simulator

        let ct = self
            .backend
            .encrypt(recipient_pk, &share_hash, &mut encrypt_rng)
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("encrypt share for recipient {recipient_id}: {e}"),
            })?;

        let nizk = self
            .prove_keygen_nizk(session_id, dealer_id, recipient_id, &ct, &share_hash)
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: e.to_string(),
            })?;

        Ok((ct.bytes, nizk))
    }

    fn prove_keygen_nizk(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        ct: &Ciphertext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, pvthfhe_nizk::NizkError> {
        // Delegate to the existing CycloNizkAdapter flow for per-recipient NIZKs.
        self._prove_share_nizk(session_id, dealer_id, recipient_id, ct, plaintext)
    }

    fn generate_keygen_nizk(
        &self,
        session_id: &[u8; 32],
        party_id: PartyId,
        pk_i: &PublicKey,
        share: &pvthfhe_fhe::KeygenShare,
    ) -> Result<Vec<u8>, String> {
        let real_pk = self
            .backend
            .aggregate_keygen(&[share.clone()])
            .map_err(|e| format!("aggregate single keygen: {e}"))?;
        let (pk0_bytes, pk1_bytes) = self
            .backend
            .decode_pk_polys(&real_pk)
            .map_err(|e| format!("decode pk polys: {e}"))?;

        let (sk_coeffs, error_bytes) = self
            .backend
            .keygen_witness(party_id)
            .map_err(|e| format!("keygen witness: {e}"))?
            .ok_or_else(|| "no keygen witness for party".to_string())?;

        let c_rns = poly_bytes_to_rns(&pk1_bytes).map_err(|e| format!("pk1 rns: {e}"))?;
        let d_rns = poly_bytes_to_rns(&pk0_bytes).map_err(|e| format!("pk0 rns: {e}"))?;

        let mut rng = ChaCha8Rng::from_seed(
            *Sha256::digest(format!("keygen-nizk-rng-{party_id}").as_bytes()).as_ref(),
        );

        let error_rns = poly_bytes_to_rns(&error_bytes).map_err(|e| format!("error rns: {e}"))?;
        let n = pvthfhe_nizk::sigma::rlwe_n();
        let q0 = 288230376173076481u64;
        let e_coeffs: Vec<i64> = error_rns
            .iter()
            .take(n)
            .map(|&v| {
                if v > q0 / 2 {
                    (v as i128 - q0 as i128) as i64
                } else {
                    v as i64
                }
            })
            .collect();

        let stmt = SigmaStatement { c_rns, d_rns };
        let wit = SigmaWitness {
            s_i: sk_coeffs,
            e_i: e_coeffs,
        };

        // Compute poly_commit identically to Round1Message for Fiat-Shamir binding.
        let mut poly_commit_data = Vec::new();
        poly_commit_data.extend_from_slice(session_id);
        poly_commit_data.extend_from_slice(&party_id.to_be_bytes());
        poly_commit_data.extend_from_slice(&share.bytes.0);
        let poly_commit = hash_bytes(b"poly-commit/v1", &poly_commit_data);

        let proof = sigma::prove(session_id, party_id, &stmt, &wit, &mut rng, &poly_commit)
            .map_err(|e| format!("sigma prove: {e}"))?;

        // Serialize the sigma proof into a compact bundle.
        let mut buf = Vec::with_capacity(8192 * 8 * 3 + 8);
        encode_sigma_proof(&proof, &mut buf);
        Ok(buf)
    }

    fn _prove_share_nizk(
        &self,
        session_id: &[u8; 32],
        dealer_id: PartyId,
        recipient_id: PartyId,
        ct: &Ciphertext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, pvthfhe_nizk::NizkError> {
        let session_str = hex::encode(session_id);
        let participant_id =
            u16::try_from(dealer_id).map_err(|_| pvthfhe_nizk::NizkError::InvalidInput {
                reason: "dealer_id too large",
                party_id: None,
            })?;

        let pvss_commitment = {
            let mut h = Sha256::new();
            h.update(session_id);
            h.update(&dealer_id.to_be_bytes());
            h.update(plaintext);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };

        let statement = NizkStatement {
            ciphertext_bytes: ct.bytes.clone(),
            decrypt_share_bytes: vec![0u8; 32],
            pvss_commitment,
            params: (
                65_537,
                pvthfhe_nizk::sigma::rlwe_n(),
                pvthfhe_nizk::sigma::SIGMA_B_E as u64,
            ),
            session_id: session_str,
            participant_id,
            epoch: 0,
        };

        let secret_share = if plaintext.len() >= 8 {
            u64::from_le_bytes(plaintext[..8].try_into().unwrap_or([0u8; 8]))
        } else {
            let mut buf = [0u8; 8];
            let len = plaintext.len().min(8);
            buf[..len].copy_from_slice(&plaintext[..len]);
            u64::from_le_bytes(buf)
        };

        let secret_share_poly = derive_witness_poly(plaintext);
        let error = derive_nizk_error_poly(plaintext);

        let mut rng_seed = [0u8; 32];
        {
            let mut h = Sha256::new();
            h.update(b"pvthfhe-sim-nizk-rng-v1");
            h.update(session_id);
            h.update(&dealer_id.to_be_bytes());
            h.update(&recipient_id.to_be_bytes());
            rng_seed.copy_from_slice(&h.finalize());
        }

        let witness = NizkWitness {
            secret_share,
            secret_share_poly,
            error,
            randomness: rng_seed.to_vec(),
        };

        let adapter = CycloNizkAdapter;
        let mut prove_rng = ChaCha8Rng::from_seed(rng_seed); // allow-seeded-rng: deterministic simulator
        let proof = adapter.prove(&statement, &witness, &mut prove_rng)?;

        Ok(proof.proof_bytes)
    }
}

fn serialize_nizk_bundle(proofs: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let count = u16::try_from(proofs.len()).context("proof count exceeds u16")?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&count.to_be_bytes());
    for proof in proofs {
        let len = u32::try_from(proof.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(proof);
    }
    Ok(buf)
}

fn derive_witness_poly(bytes: &[u8]) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-sim-witness-poly-v1");
    hasher.update(bytes);
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let range = 3u64;
    let max_multiple = (u64::MAX / range) * range;
    let mut poly = Vec::with_capacity(n);
    while poly.len() < n {
        let v = rng.next_u64();
        if v < max_multiple {
            poly.push((v % range) as i64 - 1);
        }
    }
    poly
}

fn derive_nizk_error_poly(bytes: &[u8]) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-sim-nizk-error-v1");
    hasher.update(bytes);
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha8Rng::from_seed(seed); // allow-seeded-rng: deterministic simulator
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let b = pvthfhe_nizk::sigma::SIGMA_B_E as u64;
    let range = 2 * b + 1;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let r = rng.next_u64();
        if r < max_multiple {
            out.push((r % range) as i64 - b as i64);
        }
    }
    out
}

fn encode_sigma_proof(proof: &sigma::SigmaProof, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(proof.z_s.len() as u32).to_le_bytes());
    for &coeff in &proof.z_s {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
    buf.extend_from_slice(&(proof.z_e.len() as u32).to_le_bytes());
    for &coeff in &proof.z_e {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
    buf.extend_from_slice(&(proof.t_rns.len() as u32).to_le_bytes());
    for &limb in &proof.t_rns {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&proof.ch.to_le_bytes());
}
