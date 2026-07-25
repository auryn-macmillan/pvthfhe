//! NonEquiv sub-round: every signer signs each dealer's first-seen Round 1
//! message; a quorum of Schnorr signatures binds the dealer to that message
//! and exposes equivocating dealers.

use super::super::types::{PartyId, Round1Message};
use super::{party_id_from_index, KeygenSimulator};
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_non_equiv::{
    hash_round1_message, produce_signed_signature, NonEquivCollector, NonEquivProof,
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

impl KeygenSimulator {
    /// Drive the NonEquiv sub-round: collect a quorum of signatures over each
    /// dealer's canonical Round 1 message, finalize and verify the proofs.
    /// Returns the canonical Round 1 messages and the per-dealer proofs.
    pub(super) fn run_non_equiv_subround(
        &self,
        r1_msgs: Vec<Round1Message>,
        schnorr_sks: &HashMap<PartyId, Fr>,
        schnorr_pks: &HashMap<PartyId, G1Affine>,
        session_id: &[u8; 32],
        equivocated: &mut HashSet<PartyId>,
    ) -> Result<(Vec<Round1Message>, HashMap<PartyId, NonEquivProof>), pvthfhe_fhe::FheError>
    {
        let f = self.n_parties.saturating_sub(self.threshold);
        let mut non_equiv_proofs: HashMap<PartyId, NonEquivProof> = HashMap::new();
        let mut dealer_collectors: HashMap<PartyId, NonEquivCollector> = HashMap::new();
        let mut canonical_r1_msgs: Vec<Round1Message> = Vec::new();
        let mut seen_dealer_msg: HashMap<PartyId, [u8; 32]> = HashMap::new();

        for msg in &r1_msgs {
            let dealer_id = msg.party_id;
            let payload = self.build_round1_payload(msg);
            let msg_hash = hash_round1_message(dealer_id, &payload, session_id);
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
                self.non_equiv_round(signer_id, *sk, *pk, &canonical_r1_msgs, session_id)?;

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
                schnorr_pks,
                &proof.message_hash,
                session_id,
            )
            .map_err(|e| pvthfhe_fhe::FheError::Backend {
                reason: format!("non-equiv verify for party {dealer_id}: {e}"),
            })?;
            non_equiv_proofs.insert(dealer_id, proof);
        }
        // MEMORY: canonical_r1_msgs no longer needed after NonEquiv collection
        // and aggregator check — all needed data is now in valid_r1.

        Ok((canonical_r1_msgs, non_equiv_proofs))
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
            h.update(Tag::SimNonEquivRng.as_bytes());
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
}
